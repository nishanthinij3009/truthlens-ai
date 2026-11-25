const crypto = require('crypto');
const path = require('path');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const config = require('./config');
const { runLocalForensics, resolveDeclaredCategory } = require('./services/forensics');
const { analyzeWithGemini, verifyGeminiApiKey } = require('./services/geminiAnalyzer');
const HistoryStore = require('./services/historyStore');

const ALLOWED_EXTENSIONS = new Set([
  '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp',
  '.mp4', '.mov', '.avi', '.webm', '.mkv',
  '.mp3', '.wav', '.ogg', '.flac', '.m4a', '.aac',
  '.txt',
]);

function isSupportedUpload(file) {
  const ext = path.extname(file.originalname || '').toLowerCase();
  const category = resolveDeclaredCategory(file.mimetype, file.originalname);
  return category !== 'unknown' || ALLOWED_EXTENSIONS.has(ext);
}

async function runVerification({ buffer, originalName, mimeType, aiAnalyzer }) {
  const localReport = runLocalForensics({ buffer, originalName, mimeType });

  let finalReport = localReport;
  if (config.geminiApiKey) {
    try {
      const aiReport = await aiAnalyzer({ buffer, localReport });
      if (aiReport) {
        finalReport = aiReport;
      }
    } catch (aiError) {
      finalReport = {
        ...localReport,
        signals: [
          ...localReport.signals,
          {
            severity: 'info',
            detail: `AI service unavailable (${aiError.message}); showing local forensic results.`,
          },
        ],
      };
    }
  }

  return {
    id: crypto.randomUUID(),
    analyzedAt: new Date().toISOString(),
    ...finalReport,
  };
}

function createApp(options = {}) {
  const app = express();
  const historyStore = new HistoryStore(options.historyFile || config.paths.historyFile);
  const aiAnalyzer = options.aiAnalyzer || analyzeWithGemini;
  const keyVerifier = options.keyVerifier || verifyGeminiApiKey;
  const envFilePath = options.envFilePath || config.paths.envFile;

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
      fileSize: options.maxFileSizeBytes || config.maxFileSizeBytes,
      files: 1,
    },
    fileFilter: (_req, file, cb) => {
      if (!isSupportedUpload(file)) {
        const err = new Error(
          'Unsupported file type. Upload an image, video, audio, or .txt file.'
        );
        err.statusCode = 400;
        return cb(err);
      }
      return cb(null, true);
    },
  });

  app.use(cors());
  app.use(express.json({ limit: '1mb' }));
  app.use(express.static(config.paths.publicDir));

  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'TRUTHLENS AI Backend',
      aiMode: config.geminiApiKey ? 'gemini-ai' : 'local-forensics',
      geminiConfigured: Boolean(config.geminiApiKey),
      geminiKeyHint: config.getMaskedGeminiKey(),
      geminiModel: config.geminiModel,
      supportedModalities: ['image', 'video', 'audio', 'text'],
      maxFileSizeMb: config.maxFileSizeMb,
      timestamp: new Date().toISOString(),
    });
  });

  app.post('/api/config/gemini-key', async (req, res, next) => {
    try {
      const apiKey = typeof req.body?.apiKey === 'string' ? req.body.apiKey.trim() : '';
      if (!apiKey) {
        await config.saveGeminiApiKey('', envFilePath);
        return res.json({
          geminiConfigured: false,
          aiMode: 'local-forensics',
          geminiKeyHint: null,
        });
      }

      const check = await keyVerifier(apiKey);
      if (!check.valid) {
        return res.status(400).json({ error: check.error || 'Invalid Gemini API key.' });
      }

      await config.saveGeminiApiKey(apiKey, envFilePath);
      return res.json({
        geminiConfigured: true,
        aiMode: 'gemini-ai',
        geminiKeyHint: config.getMaskedGeminiKey(),
        geminiModel: config.geminiModel,
      });
    } catch (err) {
      return next(err);
    }
  });

  app.post('/api/analyze', upload.single('media'), async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: 'No media file provided. Send a multipart/form-data request with field "media".',
        });
      }

      const { buffer, originalname, mimetype } = req.file;
      const record = await runVerification({
        buffer,
        originalName: originalname,
        mimeType: mimetype,
        aiAnalyzer,
      });

      await historyStore.add(record);
      return res.status(200).json(record);
    } catch (err) {
      return next(err);
    }
  });

  app.post('/api/analyze-text', async (req, res, next) => {
    try {
      const text = typeof req.body?.text === 'string' ? req.body.text : '';
      const title =
        typeof req.body?.title === 'string' && req.body.title.trim()
          ? req.body.title.trim()
          : 'submitted-text.txt';

      if (!text.trim()) {
        return res.status(400).json({ error: 'Field "text" is required and cannot be empty.' });
      }

      const record = await runVerification({
        buffer: Buffer.from(text, 'utf8'),
        originalName: title.endsWith('.txt') ? title : `${title}.txt`,
        mimeType: 'text/plain',
        aiAnalyzer,
      });

      await historyStore.add(record);
      return res.status(200).json(record);
    } catch (err) {
      return next(err);
    }
  });

  app.get('/api/history', async (_req, res, next) => {
    try {
      const items = await historyStore.list();
      res.json({ count: items.length, items });
    } catch (err) {
      next(err);
    }
  });

  app.get('/api/reports/:id', async (req, res, next) => {
    try {
      const report = await historyStore.getById(req.params.id);
      if (!report) {
        return res.status(404).json({ error: 'Report not found.' });
      }
      return res.json(report);
    } catch (err) {
      return next(err);
    }
  });

  app.delete('/api/history', async (_req, res, next) => {
    try {
      await historyStore.clear();
      res.json({ cleared: true });
    } catch (err) {
      next(err);
    }
  });

  app.use((err, _req, res, _next) => {
    if (err instanceof multer.MulterError) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(413).json({
          error: `File too large. Maximum allowed size is ${config.maxFileSizeMb} MB.`,
        });
      }
      return res.status(400).json({ error: err.message });
    }

    const status = err.statusCode || 500;
    return res.status(status).json({
      error: err.message || 'Internal server error.',
    });
  });

  return app;
}

module.exports = { createApp };
