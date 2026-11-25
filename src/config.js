const fs = require('fs/promises');
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '..', '.env') });

const rootDir = path.resolve(__dirname, '..');
const maxFileSizeMb = Number(process.env.MAX_FILE_SIZE_MB) || 50;

const config = {
  port: Number(process.env.PORT) || 3000,
  maxFileSizeBytes: maxFileSizeMb * 1024 * 1024,
  maxFileSizeMb,
  geminiApiKey: (process.env.GEMINI_API_KEY || '').trim(),
  geminiModel: (process.env.GEMINI_MODEL || 'gemini-2.5-flash').trim(),
  paths: {
    root: rootDir,
    envFile: path.join(rootDir, '.env'),
    publicDir: path.join(rootDir, 'public'),
    uploadsDir: path.join(rootDir, 'uploads'),
    dataDir: path.join(rootDir, 'data'),
    historyFile: path.join(rootDir, 'data', 'history.json'),
  },
  getMaskedGeminiKey() {
    if (!this.geminiApiKey) return null;
    if (this.geminiApiKey.length <= 8) return '********';
    return `${this.geminiApiKey.slice(0, 4)}...${this.geminiApiKey.slice(-4)}`;
  },
  async saveGeminiApiKey(apiKey, envFilePath = this.paths.envFile) {
    const cleanKey = (apiKey || '').trim();
    this.geminiApiKey = cleanKey;

    let lines = [];
    try {
      const existing = await fs.readFile(envFilePath, 'utf8');
      lines = existing.split(/\r?\n/);
    } catch {
      lines = [
        `PORT=${this.port}`,
        `MAX_FILE_SIZE_MB=${this.maxFileSizeMb}`,
        `GEMINI_MODEL=${this.geminiModel}`,
      ];
    }

    let replaced = false;
    const updated = lines.map((line) => {
      if (/^\s*GEMINI_API_KEY\s*=/.test(line)) {
        replaced = true;
        return `GEMINI_API_KEY=${cleanKey}`;
      }
      return line;
    });

    if (!replaced) {
      updated.push(`GEMINI_API_KEY=${cleanKey}`);
    }

    await fs.writeFile(envFilePath, `${updated.filter((l, i, arr) => i < arr.length - 1 || l !== '').join('\n')}\n`, 'utf8');
  },
};

module.exports = config;
