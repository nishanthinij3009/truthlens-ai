const config = require('../config');

const MAX_INLINE_GEMINI_BYTES = 18 * 1024 * 1024;
const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com';

const MODALITY_INSTRUCTIONS = {
  image: [
    'Focus on visual forensics:',
    '- Check lighting/shadow consistency, reflections, skin texture smoothing, hair/eye symmetry, hands/fingers, and garbled text.',
    '- Inspect background perspective warping, unnatural bokeh, or compositing edges.',
    '- Cross-check with any embedded AI generator or editing metadata.',
  ].join('\n'),
  video: [
    'Focus on video & temporal deepfake forensics:',
    '- Check frame-to-frame facial boundary flickering, unnatural blinking, rigid head poses, and lip-sync alignment with speech.',
    '- Look for warping around jawline/hair/glasses, temporal smoothing, or AI video generation physics/motion glitches.',
    '- Evaluate audio-visual coherence if audio is present.',
  ].join('\n'),
  audio: [
    'Focus on audio & voice-cloning forensics:',
    '- Check speech prosody, breath pauses, pitch monotony, robotic cadence, and syllable transitions.',
    '- Inspect background noise floor consistency, abrupt splicing/cuts, or synthetic TTS/vocoder metallic artifacts.',
    '- Distinguish natural room acoustics from studio-clean synthetic voice generation.',
  ].join('\n'),
  text: [
    'Focus on text misinformation & AI-authorship forensics:',
    '- Evaluate verifiable factual claims vs sensationalism, urgency manipulation, conspiracy framing, or unsupported medical/financial assertions.',
    '- Check for repetitive LLM-style boilerplate phrasing, fabricated citations, or logical inconsistencies.',
    '- Highlight specific claims that require independent source verification.',
  ].join('\n'),
};

function buildPrompt(category, localReport) {
  const modalityGuide = MODALITY_INSTRUCTIONS[category] || MODALITY_INSTRUCTIONS.text;
  return [
    'You are TruthLens AI, a multimodal digital forensics and misinformation analyst.',
    `Analyze the provided ${category.toUpperCase()} input for AI generation, deepfake manipulation, tampering, or misleading claims.`,
    modalityGuide,
    `Known local forensic metadata: detectedType=${localReport.file.detectedType}, sha256=${localReport.file.sha256}, localSignals=${JSON.stringify(localReport.signals.map((s) => s.detail))}.`,
    'Respond ONLY with valid JSON matching this exact schema:',
    '{',
    '  "verdict": "Low Risk / Likely Authentic" | "Suspicious / Needs Verification" | "High Manipulation / AI Risk",',
    '  "authenticityScore": <integer 0-100>,',
    '  "manipulationRisk": <integer 0-100>,',
    '  "summary": "<2-3 sentence concise forensic explanation>",',
    '  "modalityAnalysis": {',
    '    "primaryCheck": "<main modality-specific finding>",',
    '    "aiGenerationLikelihood": "Low" | "Moderate" | "High",',
    '    "recommendedAction": "<practical next step for the user>"',
    '  },',
    '  "signals": [',
    '    { "severity": "low" | "medium" | "high" | "info", "detail": "<specific observation>" }',
    '  ]',
    '}',
  ].join('\n');
}

function extractJsonObject(rawText) {
  const trimmed = rawText.trim();
  const fencedMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fencedMatch ? fencedMatch[1].trim() : trimmed;
  return JSON.parse(candidate);
}

async function uploadToGeminiFiles({ buffer, mimeType, displayName, apiKey, fetchFn }) {
  const startRes = await fetchFn(
    `${GEMINI_BASE_URL}/upload/v1beta/files?key=${encodeURIComponent(apiKey)}`,
    {
      method: 'POST',
      headers: {
        'X-Goog-Upload-Protocol': 'resumable',
        'X-Goog-Upload-Command': 'start',
        'X-Goog-Upload-Header-Content-Length': String(buffer.length),
        'X-Goog-Upload-Header-Content-Type': mimeType,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ file: { display_name: displayName } }),
    }
  );

  if (!startRes.ok) {
    throw new Error(`Gemini file upload init failed (${startRes.status})`);
  }

  const uploadUrl = startRes.headers.get('x-goog-upload-url');
  if (!uploadUrl) {
    throw new Error('Gemini file upload URL missing in response headers.');
  }

  const uploadRes = await fetchFn(uploadUrl, {
    method: 'POST',
    headers: {
      'Content-Length': String(buffer.length),
      'X-Goog-Upload-Offset': '0',
      'X-Goog-Upload-Command': 'upload, finalize',
    },
    body: buffer,
  });

  if (!uploadRes.ok) {
    throw new Error(`Gemini file upload failed (${uploadRes.status})`);
  }

  const uploaded = await uploadRes.json();
  let fileObj = uploaded.file;
  if (!fileObj?.uri) {
    throw new Error('Gemini file upload did not return a file URI.');
  }

  for (let attempt = 0; attempt < 15 && fileObj.state === 'PROCESSING'; attempt += 1) {
    await new Promise((r) => setTimeout(r, 1500));
    const pollRes = await fetchFn(
      `${GEMINI_BASE_URL}/v1beta/${fileObj.name}?key=${encodeURIComponent(apiKey)}`
    );
    if (pollRes.ok) {
      fileObj = await pollRes.json();
    }
  }

  if (fileObj.state === 'FAILED') {
    throw new Error('Gemini failed to process uploaded media file.');
  }

  return fileObj;
}

async function deleteGeminiFile(fileName, apiKey, fetchFn) {
  if (!fileName) return;
  try {
    await fetchFn(`${GEMINI_BASE_URL}/v1beta/${fileName}?key=${encodeURIComponent(apiKey)}`, {
      method: 'DELETE',
    });
  } catch {
    // Best-effort cleanup of temporary uploaded file
  }
}

async function verifyGeminiApiKey(apiKey, fetchFn = fetch) {
  const cleanKey = (apiKey || '').trim();
  if (!cleanKey) {
    return { valid: false, error: 'API key cannot be empty.' };
  }

  const res = await fetchFn(
    `${GEMINI_BASE_URL}/v1beta/models?key=${encodeURIComponent(cleanKey)}&pageSize=1`
  );
  if (!res.ok) {
    const errText = await res.text();
    return {
      valid: false,
      error: `Gemini rejected API key (HTTP ${res.status}): ${errText.slice(0, 140)}`,
    };
  }
  return { valid: true };
}

async function analyzeWithGemini({ buffer, localReport, fetchFn = fetch, apiKey = config.geminiApiKey }) {
  if (!apiKey) {
    return null;
  }

  const category = localReport.file.category;
  const detectedType = localReport.file.detectedType;

  if (!['image', 'audio', 'video', 'text'].includes(category)) {
    return null;
  }

  const parts = [{ text: buildPrompt(category, localReport) }];
  let uploadedFileName = null;

  try {
    if (category === 'text') {
      const content = buffer.toString('utf8').slice(0, 50000);
      parts.push({ text: `TEXT CONTENT TO ANALYZE:\n"""\n${content}\n"""` });
    } else if (buffer.length <= MAX_INLINE_GEMINI_BYTES) {
      parts.push({
        inline_data: {
          mime_type: detectedType,
          data: buffer.toString('base64'),
        },
      });
    } else {
      const fileObj = await uploadToGeminiFiles({
        buffer,
        mimeType: detectedType,
        displayName: localReport.file.name,
        apiKey,
        fetchFn,
      });
      uploadedFileName = fileObj.name;
      parts.push({
        file_data: {
          mime_type: fileObj.mimeType || detectedType,
          file_uri: fileObj.uri,
        },
      });
    }

    const endpoint = `${GEMINI_BASE_URL}/v1beta/models/${encodeURIComponent(
      config.geminiModel
    )}:generateContent?key=${encodeURIComponent(apiKey)}`;

    const response = await fetchFn(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ role: 'user', parts }],
        generationConfig: {
          temperature: 0.2,
          responseMimeType: 'application/json',
        },
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      throw new Error(`Gemini API HTTP ${response.status}: ${errText.slice(0, 200)}`);
    }

    const payload = await response.json();
    const modelText = payload?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!modelText) {
      throw new Error('Gemini API returned an empty response.');
    }

    const parsed = extractJsonObject(modelText);

    return {
      ...localReport,
      mode: 'gemini-ai',
      model: config.geminiModel,
      verdict: parsed.verdict || localReport.verdict,
      authenticityScore:
        typeof parsed.authenticityScore === 'number'
          ? Math.max(0, Math.min(100, Math.round(parsed.authenticityScore)))
          : localReport.authenticityScore,
      manipulationRisk:
        typeof parsed.manipulationRisk === 'number'
          ? Math.max(0, Math.min(100, Math.round(parsed.manipulationRisk)))
          : localReport.manipulationRisk,
      summary: parsed.summary || localReport.summary,
      modalityAnalysis: parsed.modalityAnalysis || null,
      signals: [
        ...(Array.isArray(parsed.signals) ? parsed.signals : []),
        ...localReport.signals,
      ],
    };
  } finally {
    if (uploadedFileName) {
      await deleteGeminiFile(uploadedFileName, apiKey, fetchFn);
    }
  }
}

module.exports = {
  analyzeWithGemini,
  verifyGeminiApiKey,
  buildPrompt,
};
