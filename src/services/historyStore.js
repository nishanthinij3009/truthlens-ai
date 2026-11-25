const fs = require('fs/promises');
const path = require('path');

const MAX_HISTORY_ITEMS = 50;

class HistoryStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.writeQueue = Promise.resolve();
  }

  async ensureInitialized() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    try {
      await fs.access(this.filePath);
    } catch {
      await fs.writeFile(this.filePath, '[]', 'utf8');
    }
  }

  async list() {
    await this.ensureInitialized();
    const raw = await fs.readFile(this.filePath, 'utf8');
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  async getById(id) {
    const items = await this.list();
    return items.find((item) => item.id === id) || null;
  }

  async add(entry) {
    this.writeQueue = this.writeQueue.then(async () => {
      const items = await this.list();
      const updated = [entry, ...items].slice(0, MAX_HISTORY_ITEMS);
      await fs.writeFile(this.filePath, JSON.stringify(updated, null, 2), 'utf8');
      return entry;
    });
    return this.writeQueue;
  }

  async clear() {
    this.writeQueue = this.writeQueue.then(async () => {
      await this.ensureInitialized();
      await fs.writeFile(this.filePath, '[]', 'utf8');
    });
    return this.writeQueue;
  }
}

module.exports = HistoryStore;
