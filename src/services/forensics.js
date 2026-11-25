const crypto = require('crypto');
const path = require('path');

const AI_IMAGE_MARKERS = [
  { pattern: /midjourney/i, label: 'Midjourney metadata signature' },
  { pattern: /stable\s*diffusion|automatic1111|comfyui|invokeai/i, label: 'Stable Diffusion / generation workflow metadata' },
  { pattern: /dall-?e|openai/i, label: 'OpenAI / DALL-E metadata marker' },
  { pattern: /firefly|adobe\s*generative/i, label: 'Adobe Firefly generative marker' },
  { pattern: /imagen|synthid/i, label: 'Google Imagen / SynthID marker' },
  { pattern: /c2pa|content\s*credentials|jumbf/i, label: 'C2PA / Content Credentials provenance block' },
  { pattern: /novelai|dreamstudio|leonardo\.ai|bing\s*image\s*creator/i, label: 'AI image generator tag' },
  { pattern: /negative\s*prompt:|steps:\s*\d+,\s*sampler:/i, label: 'Embedded diffusion prompt parameters' },
];

const EDITING_SOFTWARE_MARKERS = [
  { pattern: /adobe\s*photoshop/i, label: 'Adobe Photoshop editing metadata' },
  { pattern: /gimp/i, label: 'GIMP editing metadata' },
  { pattern: /lightroom/i, label: 'Adobe Lightroom metadata' },
  { pattern: /canva/i, label: 'Canva export metadata' },
  { pattern: /snapseed|picsart|facetune|remini/i, label: 'Mobile retouching / enhancement app tag' },
];

const CAMERA_EXIF_MARKERS = [
  /Exif\x00\x00/,
  /Canon|Nikon|SONY|FUJIFILM|OLYMPUS|Panasonic|LEICA|PENTAX/i,
  /Apple|iPhone|Samsung|SM-[A-Z0-9]+|Pixel\s*\d+|OnePlus|Xiaomi/i,
];

const MEDIA_TOOL_MARKERS = [
  { pattern: /elevenlabs/i, label: 'ElevenLabs synthetic voice marker' },
  { pattern: /suno|udio/i, label: 'AI music generator marker' },
  { pattern: /runway|sora|kling|heygen|d-id|synthesia|pika/i, label: 'AI video generator signature' },
  { pattern: /lavf\d+|lavc\d+|ffmpeg/i, label: 'FFmpeg / Lavf re-encoding signature' },
  { pattern: /handbrake/i, label: 'HandBrake transcoding tag' },
  { pattern: /premiere|after\s*effects|davinci\s*resolve|capcut/i, label: 'Video editor export signature' },
];

const CLICKBAIT_PATTERNS = [
  /\b(breaking|urgent|shocking|exposed|leaked|banned|censored)\b/gi,
  /\b(share\s+before\s+(it'?s|they)\s+delete|wake\s+up|they\s+don'?t\s+want\s+you\s+to\s+know)\b/gi,
  /\b(100%\s+proven|miracle\s+cure|secret\s+truth|guaranteed\s+proof)\b/gi,
];

function isLikelyText(buffer) {
  if (!buffer || buffer.length === 0) return true;
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192));
  let suspiciousBytes = 0;
  for (let i = 0; i < sample.length; i += 1) {
    const byte = sample[i];
    if (byte === 0) return false;
    if (byte < 7 || (byte > 14 && byte < 32)) {
      suspiciousBytes += 1;
    }
  }
  return suspiciousBytes / sample.length < 0.05;
}

function detectFileSignature(buffer, declaredExt = '') {
  if (!buffer || buffer.length === 0) {
    return { detectedType: 'empty', category: 'unknown', matchesDeclared: false };
  }

  const hex4 = buffer.subarray(0, 4).toString('hex').toLowerCase();
  const ascii4 = buffer.subarray(0, 4).toString('ascii');
  const ascii8To12 = buffer.subarray(8, 12).toString('ascii');
  const ascii4To8 = buffer.subarray(4, 8).toString('ascii');

  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { detectedType: 'image/jpeg', category: 'image' };
  }
  if (hex4 === '89504e47') {
    return { detectedType: 'image/png', category: 'image' };
  }
  if (ascii4 === 'GIF8') {
    return { detectedType: 'image/gif', category: 'image' };
  }
  if (ascii4 === 'RIFF' && ascii8To12 === 'WEBP') {
    return { detectedType: 'image/webp', category: 'image' };
  }
  if (buffer[0] === 0x42 && buffer[1] === 0x4d) {
    return { detectedType: 'image/bmp', category: 'image' };
  }
  if (ascii4 === 'RIFF' && ascii8To12 === 'WAVE') {
    return { detectedType: 'audio/wav', category: 'audio' };
  }
  if (ascii4 === 'RIFF' && ascii8To12 === 'AVI ') {
    return { detectedType: 'video/avi', category: 'video' };
  }
  if (buffer.subarray(0, 3).toString('ascii') === 'ID3' || (buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0)) {
    return { detectedType: 'audio/mpeg', category: 'audio' };
  }
  if (ascii4 === 'OggS') {
    return { detectedType: 'audio/ogg', category: 'audio' };
  }
  if (ascii4 === 'fLaC') {
    return { detectedType: 'audio/flac', category: 'audio' };
  }
  if (ascii4To8 === 'ftyp') {
    const brand = buffer.subarray(8, 12).toString('ascii').toLowerCase();
    if (brand.startsWith('m4a') || brand.startsWith('m4b')) {
      return { detectedType: 'audio/mp4', category: 'audio' };
    }
    return { detectedType: 'video/mp4', category: 'video' };
  }
  if (hex4 === '1a45dfa3') {
    return { detectedType: 'video/webm', category: 'video' };
  }
  if (declaredExt === '.txt' || isLikelyText(buffer)) {
    return { detectedType: 'text/plain', category: 'text' };
  }

  return { detectedType: 'application/octet-stream', category: 'unknown' };
}

function resolveDeclaredCategory(mimeType = '', originalName = '') {
  const ext = path.extname(originalName).toLowerCase();
  if (mimeType.startsWith('image/') || ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'].includes(ext)) {
    return 'image';
  }
  if (mimeType.startsWith('video/') || ['.mp4', '.mov', '.avi', '.webm', '.mkv'].includes(ext)) {
    return 'video';
  }
  if (mimeType.startsWith('audio/') || ['.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac'].includes(ext)) {
    return 'audio';
  }
  if (mimeType.startsWith('text/') || ext === '.txt') {
    return 'text';
  }
  return 'unknown';
}

function calculateEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;
  const counts = new Array(256).fill(0);
  const sample = buffer.subarray(0, Math.min(buffer.length, 262144));
  for (let i = 0; i < sample.length; i += 1) {
    counts[sample[i]] += 1;
  }
  let entropy = 0;
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] === 0) continue;
    const p = counts[i] / sample.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

function extractHeaderText(buffer, maxBytes = 131072) {
  const head = buffer.subarray(0, Math.min(buffer.length, maxBytes));
  const tailStart = Math.max(head.length, buffer.length - 65536);
  const tail = buffer.subarray(tailStart);
  return `${head.toString('latin1')}\n${tail.toString('latin1')}`;
}

function analyzeImageBuffer(buffer, detectedType) {
  const signals = [];
  let riskPoints = 15;
  const headerText = extractHeaderText(buffer);

  let aiTagFound = false;
  for (const marker of AI_IMAGE_MARKERS) {
    if (marker.pattern.test(headerText)) {
      signals.push({ severity: 'high', detail: `Detected ${marker.label}.` });
      riskPoints += 55;
      aiTagFound = true;
    }
  }

  for (const marker of EDITING_SOFTWARE_MARKERS) {
    if (marker.pattern.test(headerText)) {
      signals.push({ severity: 'medium', detail: `Detected ${marker.label}.` });
      riskPoints += 20;
    }
  }

  const hasCameraExif = CAMERA_EXIF_MARKERS.some((pattern) => pattern.test(headerText));
  if (hasCameraExif) {
    signals.push({ severity: 'low', detail: 'Camera / device EXIF metadata present.' });
    riskPoints -= 10;
  } else if (!aiTagFound) {
    signals.push({
      severity: 'medium',
      detail: 'No camera EXIF provenance found (common in screenshots, re-saved social media, or AI-generated images).',
    });
    riskPoints += 15;
  }

  if (detectedType === 'image/png' && !hasCameraExif) {
    signals.push({
      severity: 'info',
      detail: 'Lossless PNG without camera EXIF; verify original source context.',
    });
  }

  return { signals, riskPoints };
}

function analyzeMediaContainer(buffer) {
  const signals = [];
  let riskPoints = 20;
  const headerText = extractHeaderText(buffer);

  for (const marker of MEDIA_TOOL_MARKERS) {
    if (marker.pattern.test(headerText)) {
      const isAiTool = /elevenlabs|suno|udio|runway|sora|kling|heygen|d-id|synthesia|pika/i.test(
        marker.pattern.source
      );
      signals.push({
        severity: isAiTool ? 'high' : 'medium',
        detail: `Detected ${marker.label} in container metadata.`,
      });
      riskPoints += isAiTool ? 55 : 15;
    }
  }

  if (signals.length === 0) {
    signals.push({
      severity: 'info',
      detail: 'Container header valid; no explicit synthetic-tool watermarks found in metadata.',
    });
  }

  return { signals, riskPoints };
}

function analyzeTextBuffer(buffer) {
  const text = buffer.toString('utf8').trim();
  const signals = [];
  let riskPoints = 15;

  if (!text) {
    return {
      signals: [{ severity: 'medium', detail: 'Uploaded text file is empty.' }],
      riskPoints: 50,
      textStats: { characters: 0, words: 0, lines: 0 },
      preview: '',
    };
  }

  const words = text.split(/\s+/).filter(Boolean);
  const lines = text.split(/\r?\n/).length;
  const letters = text.replace(/[^a-zA-Z]/g, '');
  const upperLetters = text.replace(/[^A-Z]/g, '');
  const upperRatio = letters.length > 0 ? upperLetters.length / letters.length : 0;
  const exclamations = (text.match(/!/g) || []).length;
  const hasUrl = /https?:\/\/\S+/i.test(text);

  let clickbaitHits = 0;
  for (const regex of CLICKBAIT_PATTERNS) {
    const matches = text.match(regex);
    if (matches) clickbaitHits += matches.length;
  }

  if (clickbaitHits > 0) {
    signals.push({
      severity: 'high',
      detail: `Found ${clickbaitHits} sensationalist or viral-manipulation phrase(s).`,
    });
    riskPoints += Math.min(40, clickbaitHits * 15);
  }

  if (upperRatio > 0.3 && letters.length > 20) {
    signals.push({
      severity: 'medium',
      detail: `High uppercase ratio (${Math.round(upperRatio * 100)}%), typical of emotional or clickbait claims.`,
    });
    riskPoints += 15;
  }

  if (exclamations >= 4) {
    signals.push({
      severity: 'medium',
      detail: `Excessive exclamation marks (${exclamations}) detected.`,
    });
    riskPoints += 10;
  }

  if (!hasUrl && words.length > 15) {
    signals.push({
      severity: 'info',
      detail: 'No external source URLs or citations included in the text.',
    });
    riskPoints += 10;
  } else if (hasUrl) {
    signals.push({
      severity: 'low',
      detail: 'Contains URL reference(s) that can be cross-checked.',
    });
    riskPoints -= 5;
  }

  if (signals.length === 0) {
    signals.push({
      severity: 'low',
      detail: 'Neutral linguistic tone with no obvious clickbait triggers.',
    });
  }

  return {
    signals,
    riskPoints,
    textStats: {
      characters: text.length,
      words: words.length,
      lines,
    },
    preview: text.slice(0, 400),
  };
}

function classifyRisk(score) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  if (clamped >= 65) {
    return {
      verdict: 'High Manipulation / AI Risk',
      authenticityScore: 100 - clamped,
      manipulationRisk: clamped,
    };
  }
  if (clamped >= 35) {
    return {
      verdict: 'Suspicious / Needs Verification',
      authenticityScore: 100 - clamped,
      manipulationRisk: clamped,
    };
  }
  return {
    verdict: 'Low Risk / Likely Authentic',
    authenticityScore: 100 - clamped,
    manipulationRisk: clamped,
  };
}

function runLocalForensics({ buffer, originalName, mimeType }) {
  const ext = path.extname(originalName).toLowerCase();
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
  const entropy = calculateEntropy(buffer);
  const declaredCategory = resolveDeclaredCategory(mimeType, originalName);
  const signature = detectFileSignature(buffer, ext);

  const signals = [];
  let riskPoints = 0;

  if (signature.category === 'unknown') {
    signals.push({
      severity: 'high',
      detail: 'Unrecognized binary file signature; file may be corrupted or unsupported.',
    });
    riskPoints += 40;
  } else if (declaredCategory !== 'unknown' && signature.category !== declaredCategory) {
    signals.push({
      severity: 'high',
      detail: `File signature mismatch: extension/MIME indicates ${declaredCategory}, but binary header is ${signature.detectedType}.`,
    });
    riskPoints += 45;
  } else {
    signals.push({
      severity: 'low',
      detail: `Binary header verified as ${signature.detectedType}.`,
    });
  }

  let extra = {};
  const activeCategory = signature.category !== 'unknown' ? signature.category : declaredCategory;

  if (activeCategory === 'image') {
    const imgResult = analyzeImageBuffer(buffer, signature.detectedType);
    signals.push(...imgResult.signals);
    riskPoints += imgResult.riskPoints;
  } else if (activeCategory === 'audio' || activeCategory === 'video') {
    const mediaResult = analyzeMediaContainer(buffer);
    signals.push(...mediaResult.signals);
    riskPoints += mediaResult.riskPoints;
  } else if (activeCategory === 'text') {
    const txtResult = analyzeTextBuffer(buffer);
    signals.push(...txtResult.signals);
    riskPoints += txtResult.riskPoints;
    extra = {
      textStats: txtResult.textStats,
      preview: txtResult.preview,
    };
  }

  const classification = classifyRisk(riskPoints);

  return {
    mode: 'local-forensics',
    file: {
      name: originalName,
      sizeBytes: buffer.length,
      declaredMimeType: mimeType || 'unknown',
      detectedType: signature.detectedType,
      category: activeCategory,
      sha256,
      entropy,
    },
    ...classification,
    summary:
      activeCategory === 'text'
        ? `Local linguistic & structural check completed (${classification.verdict}). Add GEMINI_API_KEY in .env for deeper semantic fact-checking.`
        : `Local binary & metadata forensic scan completed (${classification.verdict}). Add GEMINI_API_KEY in .env for deep multimodal AI pixel/audio inspection.`,
    signals,
    ...extra,
  };
}

module.exports = {
  detectFileSignature,
  resolveDeclaredCategory,
  runLocalForensics,
};
