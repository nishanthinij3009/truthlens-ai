# TRUTHLENS AI

Full-stack multimodal fake media detection platform (**Image, Video, Audio, and Text**).

## Features
- **Real Multimodal Gemini AI Verification (`gemini-2.5-flash`)**:
  - **Image**: Lighting/shadow, anatomy, compositing, and AI-generation forensics.
  - **Video**: Temporal consistency, lip-sync, facial boundary warping, and motion artifact checks (supports files up to 50 MB via inline data or Gemini Files API).
  - **Audio**: Prosody, breath pause, vocoder/TTS cadence, and voice-cloning checks.
  - **Text**: Factuality, sensationalism, clickbait framing, and AI-authorship analysis.
- **In-App Gemini API Key Setup**: Click **Configure Gemini AI Key** in the header to validate and save your key directly to `.env` (`POST /api/config/gemini-key`).
- **Built-in Local Forensic Engine (Offline Fallback)**: Magic-byte signature verification, SHA-256 hashing, byte entropy, AI generator metadata detection, camera EXIF checks, and linguistic clickbait scoring.
- **Interactive UI**: Media preview player (`img`, `video`, `audio`, `.txt`), Direct Text / News Check tab (`POST /api/analyze-text`), and Recent Verifications history (`GET /api/history`, `GET /api/reports/:id`, `DELETE /api/history`).

## Quick Start

```powershell
cd C:\Users\hp\.gemini\antigravity\scratch\truthlens-ai
$env:PORT=3001; node src/server.js
```

Open `http://localhost:3001` in your browser.
