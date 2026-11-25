const config = require('./config');
const { createApp } = require('./app');

const app = createApp();

app.listen(config.port, () => {
  console.log(`TRUTHLENS AI backend running at http://localhost:${config.port}`);
  console.log(
    `Verification mode: ${config.geminiApiKey ? `Gemini AI (${config.geminiModel})` : 'Local Forensics (set GEMINI_API_KEY in .env for AI mode)'}`
  );
});
