# 🛡 SentinelDLP

> **Browser-native Data Loss Prevention** — Intercepts sensitive data before you paste it anywhere. Runs entirely on-device, zero telemetry.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Manifest V3](https://img.shields.io/badge/Manifest-V3-green.svg)]()
[![Chrome Extension](https://img.shields.io/badge/Chrome-Extension-yellow.svg)]()

---

## The Problem

You copy a config snippet to share with a colleague. In that block:  
`redis://:p@ssw0rd123@192.168.10.5:6379/0`

You paste it into Slack. Done. Password leaked. Server exposed.

This happens every day — in support tickets, GitHub issues, ChatGPT prompts, Notion pages, email. The fix isn't training; it's making leaks **impossible at the moment of paste**.

---

## What SentinelDLP Does

SentinelDLP hooks into every paste event in your browser. Before your text lands anywhere, it scans for 18 sensitive data types and surfaces an overlay showing exactly what it found — plus a sanitized version ready to copy.

**No clipboard access. No background scanning. No data leaves your machine.**

![overlay demo](docs/overlay-demo.png)

---

## Detected Types

| Type | Examples |
|------|---------|
| 🌐 Private IP | `10.x.x.x`, `192.168.x.x`, `172.16-31.x.x` |
| 🖥 SSH Target | `root@192.168.1.10`, `ubuntu@server.internal` |
| 🔑 GitHub / GitLab Token | `ghp_xxx`, `glpat-xxx` |
| ☁️ AWS Access Key | `AKIA...` |
| 🎫 JWT Token | `eyJ...` |
| 📱 Telegram Bot Token | `123456789:AAF3_...` |
| 🗄️ Connection String | `postgres://user:pass@host/db` |
| 🔐 Private Key Header | `-----BEGIN RSA PRIVATE KEY-----` |
| 🔒 FortiGate ENC | `ENC AbCd...` |
| 🔒 PSK / Pre-Shared Key | `preshared-key mysecret` |
| 💳 Credit Card | Luhn-matched Visa/MC/Amex |
| 📞 TW Phone Number | `0912-345-678`, `+886-9-xxx` |
| 📧 Email Address | `user@domain.com` |
| 🌐 Internal Domain | `es01.internal`, `*.corp.lan` |
| 📁 Linux Sensitive Path | `/home/user/`, `/etc/ssl/`, `/root/` |
| 🔑 Password Field (heuristic) | `password=abc123`, `api_key: xyz` |

---

## How It Works

```
Paste event  →  content.js sanitize()  →  findings > 0?
                                                │
                                    ┌───────────┴───────────┐
                                    │   Show overlay         │
                                    │   - Detected types     │
                                    │   - Sanitized output   │
                                    │   - [Copy sanitized]   │
                                    │   - [Paste original]   │
                                    └───────────────────────┘
```

- **Rule-based engine** — 18 regex patterns, zero ML load, deterministic
- **Stable token IDs** — MD5-based: same secret always maps to same `[[TAG_xxxxxx]]` tag  
  → useful for tracking the same credential across multiple paste events
- **Heuristic masking** — keeps the key name, replaces only the value  
  `password=[[HEURISTIC_abc123]]` (not `[[HEURISTIC_password=abc123]]`)
- **Safe values whitelist** — `placeholder`, `changeme`, `<password>` never trigger

---

## Install

> Chrome Web Store submission in progress. Install manually for now:

1. Download this repo (Code → Download ZIP) or `git clone`
2. Open Chrome → `chrome://extensions/`
3. Enable **Developer mode** (top-right toggle)
4. Click **Load unpacked** → select the `SentinelDLP` folder
5. Pin the extension from the puzzle-piece menu

See [`sentinel-dlp-install-guide.html`](sentinel-dlp-install-guide.html) for a full visual walkthrough.

---

## Usage

**Active**: SentinelDLP runs silently. When you paste something suspicious, an overlay appears in the top-right corner.

**Overlay actions:**
- 📋 **Copy sanitized** — copies the redacted version; overlay closes
- **Paste original** — dismisses the overlay; original paste proceeds
- **Don't show on this site** — suppresses future alerts for this domain

**Popup (click extension icon):**
- Total detection count + affected sites
- Recent alert history (last 8)
- Enable/disable toggle
- Per-site trust list management
- Bilingual: 繁中 / EN

---

## Architecture

```
manifest.json          Manifest V3, host_permissions: <all_urls>
├── content.js         Paste listener + rule engine + overlay UI (all inline styles)
├── background.js      Service worker — stats aggregation + badge counter
└── popup.html         Extension popup — stats dashboard + settings
```

**Design constraints:**
- Zero external dependencies (no npm, no CDN)
- All overlay styles inline — no injected `<style>` tags to avoid CSP conflicts
- `chrome.storage.sync` for settings (shared across devices), `.local` for stats
- Works on any site including `https://`, `http://`, internal pages

---

## Privacy

| What | Answer |
|------|--------|
| Data uploaded? | Never |
| External requests? | None |
| Clipboard read? | No — only intercepts `paste` events (clipboardData already provided) |
| Storage? | `chrome.storage.local` only — stays on your device |
| Analytics? | None |

---

## Roadmap

- [ ] Chrome Web Store release
- [ ] Custom rule editor (add your own patterns in popup)
- [ ] Per-rule enable/disable
- [ ] Export detection log (local CSV)
- [ ] Firefox / Edge support

---

## Built by

**Kerr** — Security & DevOps tooling  
[github.com/kerr20801](https://github.com/kerr20801)

---

## License

MIT — use freely, attribution appreciated.
