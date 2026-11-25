const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { Readable } = require('node:stream');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const config = require('../src/config');
const { createApp } = require('../src/app');
const { analyzeWithGemini, buildPrompt } = require('../src/services/geminiAnalyzer');
const { runLocalForensics } = require('../src/services/forensics');

function invokeApp(app, { method = 'GET', url = '/', headers = {}, body = null }) {
  return new Promise((resolve, reject) => {
    const bodyBuffer = body
      ? Buffer.isBuffer(body)
        ? body
        : Buffer.from(body)
      : Buffer.alloc(0);

    const stream = Readable.from(bodyBuffer.length > 0 ? [bodyBuffer] : []);
    const req = Object.assign(stream, {
      url,
      method,
      headers: {
        host: 'localhost:3000',
        ...headers,
        ...(bodyBuffer.length > 0 ? { 'content-length': String(bodyBuffer.length) } : {}),
      },
      connection: {},
      socket: { remoteAddress: '127.0.0.1' },
    });
    Object.setPrototypeOf(req, http.IncomingMessage.prototype);

    const res = new http.ServerResponse(req);
    const chunks = [];
    const origWrite = res.write.bind(res);
    const origEnd = res.end.bind(res);

    res.write = (chunk, encoding, cb) => {
      if (chunk) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
      }
      origWrite(chunk, encoding, cb);
      return true;
    };

    res.end = (chunk, encoding, cb) => {
      if (chunk) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
      }
      const raw = Buffer.concat(chunks);
      resolve({
        status: res.statusCode,
        headers: res.getHeaders(),
        text: () => raw.toString('utf8'),
        json: () => JSON.parse(raw.toString('utf8')),
      });
      return origEnd(chunk, encoding, cb);
    };

    res.on('error', reject);
    app.handle(req, res, (err) => {
      if (err) reject(err);
    });
  });
}

function buildMultipartBody(fieldName, filename, contentType, fileBuffer) {
  const boundary = '----TruthLensBoundary7MA4YWxkTrZu0gW';
  const head = Buffer.from(
    `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\n` +
      `Content-Type: ${contentType}\r\n\r\n`,
    'utf8'
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf8');
  return {
    contentType: `multipart/form-data; boundary=${boundary}`,
    body: Buffer.concat([head, fileBuffer, tail]),
  };
}

async function setupApp(extraOptions = {}) {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'truthlens-test-'));
  const historyFile = path.join(tempDir, 'history.json');
  const envFilePath = path.join(tempDir, '.env');
  const prevKey = config.geminiApiKey;
  const app = createApp({ historyFile, envFilePath, ...extraOptions });
  return {
    app,
    envFilePath,
    cleanup: async () => {
      config.geminiApiKey = prevKey;
      await fs.rm(tempDir, { recursive: true, force: true });
    },
  };
}

test('GET /api/health and GET / serve API status and upgraded frontend', async () => {
  const { app, cleanup } = await setupApp();
  try {
    const healthRes = await invokeApp(app, { method: 'GET', url: '/api/health' });
    assert.equal(healthRes.status, 200);
    const health = healthRes.json();
    assert.equal(health.status, 'ok');
    assert.deepEqual(health.supportedModalities, ['image', 'video', 'audio', 'text']);

    const htmlRes = await invokeApp(app, { method: 'GET', url: '/' });
    assert.equal(htmlRes.status, 200);
    const html = htmlRes.text();
    assert.match(html, /TRUTHLENS AI/);
    assert.match(html, /\/api\/analyze-text/);
    assert.match(html, /\/api\/config\/gemini-key/);
  } finally {
    await cleanup();
  }
});

test('POST /api/analyze rejects missing file with 400', async () => {
  const { app, cleanup } = await setupApp();
  try {
    const boundary = '----TruthLensEmptyBoundary';
    const emptyForm = Buffer.from(`--${boundary}--\r\n`, 'utf8');
    const res = await invokeApp(app, {
      method: 'POST',
      url: '/api/analyze',
      headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
      body: emptyForm,
    });
    assert.equal(res.status, 400);
    assert.match(res.json().error, /No media file provided/i);
  } finally {
    await cleanup();
  }
});

test('POST /api/analyze supports image, video, and audio uploads', async () => {
  const { app, cleanup } = await setupApp();
  try {
    const pngHeader = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const pngBody = Buffer.concat([pngHeader, Buffer.from('tEXtparameters\x00Stable Diffusion ComfyUI', 'latin1')]);
    const pngMulti = buildMultipartBody('media', 'sample.png', 'image/png', pngBody);
    const pngRes = await invokeApp(app, {
      method: 'POST',
      url: '/api/analyze',
      headers: { 'content-type': pngMulti.contentType },
      body: pngMulti.body,
    });
    assert.equal(pngRes.status, 200);
    assert.equal(pngRes.json().file.category, 'image');
    assert.equal(pngRes.json().verdict, 'High Manipulation / AI Risk');

    const mp4Body = Buffer.concat([
      Buffer.from([0x00, 0x00, 0x00, 0x18]),
      Buffer.from('ftypmp42\x00\x00\x00\x00Runway', 'latin1'),
    ]);
    const mp4Multi = buildMultipartBody('media', 'clip.mp4', 'video/mp4', mp4Body);
    const mp4Res = await invokeApp(app, {
      method: 'POST',
      url: '/api/analyze',
      headers: { 'content-type': mp4Multi.contentType },
      body: mp4Multi.body,
    });
    assert.equal(mp4Res.status, 200);
    assert.equal(mp4Res.json().file.category, 'video');
    assert.equal(mp4Res.json().file.detectedType, 'video/mp4');
    assert.ok(mp4Res.json().manipulationRisk >= 65);

    const wavBody = Buffer.from('RIFF\x24\x00\x00\x00WAVEfmt ElevenLabs', 'latin1');
    const wavMulti = buildMultipartBody('media', 'voice.wav', 'audio/wav', wavBody);
    const wavRes = await invokeApp(app, {
      method: 'POST',
      url: '/api/analyze',
      headers: { 'content-type': wavMulti.contentType },
      body: wavMulti.body,
    });
    assert.equal(wavRes.status, 200);
    assert.equal(wavRes.json().file.category, 'audio');
    assert.equal(wavRes.json().file.detectedType, 'audio/wav');
    assert.ok(wavRes.json().manipulationRisk >= 65);
  } finally {
    await cleanup();
  }
});

test('POST /api/analyze-text and history endpoints persist and return reports', async () => {
  const { app, cleanup } = await setupApp();
  try {
    const analyzeRes = await invokeApp(app, {
      method: 'POST',
      url: '/api/analyze-text',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        title: 'viral-claim',
        text: 'BREAKING!! SHOCKING leaked secret truth! Share before they delete this 100% proven miracle cure!!!',
      }),
    });
    assert.equal(analyzeRes.status, 200);
    const report = analyzeRes.json();
    assert.equal(report.file.category, 'text');
    assert.ok(report.manipulationRisk >= 50);

    const historyRes = await invokeApp(app, { method: 'GET', url: '/api/history' });
    assert.equal(historyRes.status, 200);
    assert.equal(historyRes.json().count, 1);

    const singleRes = await invokeApp(app, { method: 'GET', url: `/api/reports/${report.id}` });
    assert.equal(singleRes.status, 200);
    assert.equal(singleRes.json().id, report.id);
  } finally {
    await cleanup();
  }
});

test('POST /api/config/gemini-key validates key and persists to .env', async () => {
  const { app, envFilePath, cleanup } = await setupApp({
    keyVerifier: async (key) => ({ valid: key.startsWith('AIza'), error: 'Must start with AIza' }),
  });

  try {
    const badRes = await invokeApp(app, {
      method: 'POST',
      url: '/api/config/gemini-key',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ apiKey: 'invalid-key' }),
    });
    assert.equal(badRes.status, 400);

    const okRes = await invokeApp(app, {
      method: 'POST',
      url: '/api/config/gemini-key',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ apiKey: 'AIzaTestKey123456' }),
    });
    assert.equal(okRes.status, 200);
    assert.equal(okRes.json().geminiConfigured, true);
    assert.equal(okRes.json().aiMode, 'gemini-ai');

    const envContent = await fs.readFile(envFilePath, 'utf8');
    assert.match(envContent, /GEMINI_API_KEY=AIzaTestKey123456/);
  } finally {
    await cleanup();
  }
});

test('analyzeWithGemini runs modality-specific AI verification for audio/video/text/image', async () => {
  const audioBuffer = Buffer.from('RIFF\x24\x00\x00\x00WAVEfmt ', 'latin1');
  const localReport = runLocalForensics({
    buffer: audioBuffer,
    originalName: 'sample.wav',
    mimeType: 'audio/wav',
  });

  let capturedPayload = null;
  const mockFetch = async (_url, init) => {
    capturedPayload = JSON.parse(init.body);
    return {
      ok: true,
      json: async () => ({
        candidates: [
          {
            content: {
              parts: [
                {
                  text: JSON.stringify({
                    verdict: 'High Manipulation / AI Risk',
                    authenticityScore: 18,
                    manipulationRisk: 82,
                    summary: 'Synthetic vocoder artifacts detected in speech cadence.',
                    modalityAnalysis: {
                      primaryCheck: 'Uniform pitch contour and missing natural breath pauses.',
                      aiGenerationLikelihood: 'High',
                      recommendedAction: 'Request original unedited studio recording.',
                    },
                    signals: [{ severity: 'high', detail: 'AI voice synthesis markers found.' }],
                  }),
                },
              ],
            },
          },
        ],
      }),
    };
  };

  const result = await analyzeWithGemini({
    buffer: audioBuffer,
    localReport,
    fetchFn: mockFetch,
    apiKey: 'AIzaMockKey',
  });

  assert.equal(result.mode, 'gemini-ai');
  assert.equal(result.authenticityScore, 18);
  assert.equal(result.manipulationRisk, 82);
  assert.equal(result.modalityAnalysis.aiGenerationLikelihood, 'High');
  assert.match(buildPrompt('video', localReport), /lip-sync/i);
  assert.equal(capturedPayload.contents[0].parts[1].inline_data.mime_type, 'audio/wav');
});
