# Sentinel 🛡️
### Autonomous Desktop AI Privacy Guard Powered by NVIDIA Nemotron & Nebius Token Factory

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Track: Best Apps and Agents](https://img.shields.io/badge/Hackathon-Best%20Apps%20%26%20Agents-purple.svg)](https://nebius.com)
[![Model: NVIDIA Nemotron](https://img.shields.io/badge/NVIDIA-Llama--3.1--Nemotron--70B-green.svg)](https://build.nvidia.com)
[![Platform: Nebius Token Factory](https://img.shields.io/badge/Inference-Nebius%20Token%20Factory-blue.svg)](https://tokenfactory.nebius.com)
[![Tests: 24 Passed](https://img.shields.io/badge/Tests-24%2F24%20Passing-success.svg)](tests/)

---

## 💡 Overview

Modern desktop applications—from web browsers and media players to productivity suites—silently transmit continuous telemetry, behavioral analytics, ad beacons, and hardware fingerprinters. Standard adblockers are confined to browser tabs and rely on static, brittle blocklists that break websites or fail on new telemetry endpoints.

**Sentinel** is an autonomous desktop privacy application that watches what applications on your computer connect to in real time. It uses a local privacy engine combined with **NVIDIA Nemotron hosted on Nebius Token Factory** to:
1. **Detect & Classify**: Identify telemetry, trackers, fingerprinters, and essential infrastructure.
2. **Deep Investigation**: Explain in plain English what remote servers actually do.
3. **Consequence Prediction**: Deduce precisely what will happen if a connection is blocked (e.g. *"Tracking disabled; playback unaffected"* vs *"CRITICAL: payment checkout will fail"*).
4. **Autonomous 'Protect Me' Sweep**: Conduct an end-to-end 10-step agent evaluation recommending which connections to block and which to preserve.
5. **Decision Memory**: Retain user policy preferences across sessions.
6. **'Explain My Privacy' Audit**: Synthesize executive reports on desktop privacy health.

> **Hackathon Submission Track**: **Best Apps and Agents**  
> **NVIDIA Model**: `nvidia/Llama-3.1-Nemotron-70B-Instruct-HF`  
> **Inference Engine**: Nebius Token Factory (`https://api.studio.nebius.ai/v1/`)

---

## 🧠 How NVIDIA Nemotron & Nebius Token Factory Are Used

Sentinel does **not** use LLMs as a conversational toy or generic chatbot. **NVIDIA Nemotron is the core privacy intelligence and decision-making engine**:

```
+---------------------------------------------------------------------------------+
|                                SENTINEL DESKTOP                                 |
|                                                                                 |
|  [ Outbound Network Traffic ]                                                   |
|           │                                                                     |
|           ▼                                                                     |
|  [ Local Privacy Engine ] ──► Extracts: Domain, App, Category, Frequency        |
|           │                   Enforces: Zero PII, Zero Tokens/Credentials       |
|           ▼                                                                     |
|  [ Sanitized Structured Telemetry Object ]                                      |
|           │                                                                     |
|           ▼                                                                     |
|  [ NEBIUS TOKEN FACTORY ] ──► Endpoint: https://api.studio.nebius.ai/v1/       |
|           │                   Model: nvidia/Llama-3.1-Nemotron-70B-Instruct-HF  |
|           ▼                                                                     |
|  [ NVIDIA Nemotron Reasoning ]                                                  |
|           ├─► Behavioral Classification (Ad tracking vs Telemetry vs CDN)       |
|           ├─► Risk Level & Confidence Scoring                                   |
|           ├─► Plain-English Impact Explanation                                  |
|           ├─► Consequence Deduction (What breaks if blocked)                    |
|           └─► Action Plan (Block, Allow, Always Allow, Ask Later)               |
|           │                                                                     |
|           ▼                                                                     |
|  [ Structured JSON Contract ]                                                   |
|           │                                                                     |
|           ▼                                                                     |
|  [ SQLite Policy Store & Local Firewall / DNS Enforcement ]                     |
+---------------------------------------------------------------------------------+
```

### 1. Structured Privacy Investigation
Before consulting Nemotron, Sentinel's local privacy engine sanitizes the event to ensure **no passwords, full URLs, auth tokens, or browsing history** are ever sent:
```json
{
  "application": "chrome",
  "domain": "adservice.google.com",
  "category": "ad_tracking",
  "frequency": 84,
  "known_tracker": true,
  "risk_signals": ["known_tracker", "ad_tracking_network", "high_frequency"]
}
```

Nemotron returns a structured, strictly parsed JSON assessment:
```json
{
  "risk": "high",
  "category": "ad_tracking",
  "recommendation": "block",
  "confidence": 0.95,
  "explanation": "Chrome is contacting Google's advertising network used for cross-site behavioral targeting.",
  "possible_consequences": [
    "Targeted ad personalization will be disabled.",
    "Webpages and search results will load normally and faster."
  ],
  "vendor_profile": "Google Advertising Infrastructure"
}
```

### 2. Autonomous 'Protect Me' Agent Flow
When the user clicks the prominent **Protect Me** shield:
1. Sentinel inspects active network connections.
2. Identifies suspicious candidates across running processes.
3. Formats a sanitized batch payload incorporating past user decisions.
4. Queries NVIDIA Nemotron via Nebius Token Factory.
5. Receives Nemotron's action plan differentiating harmful trackers from critical APIs (e.g. keeping Stripe payments while blocking canvas fingerprinters).
6. Displays the proposal with pre-checked recommendations for user review.
7. User approves the plan.
8. Sentinel applies the rules to the SQLite policy database and active blocklist.
9. Sentinel verifies rule enforcement.
10. Sentinel recalculates the live Privacy Score (e.g., jumping from **68/100 to 94/100**) and presents an instant diff summary.

### 3. 'Explain My Privacy' AI Audit Synthesis
Generates a comprehensive executive report synthesizing tracker volume, highest offending desktop processes, and security hygiene advice.

### 4. Zero-Downtime Offline Fallback Engine
If an evaluator tests Sentinel without a Nebius API key or in an offline environment, Sentinel automatically activates its deterministic **Local Fallback Engine**, guaranteeing a completely functional demo with realistic AI explanations and consequence analyses.

---

## 🖥️ User Interface & Experience

Sentinel is designed as a consumer desktop security tool with:
- **Dynamic Privacy Score Gauge (0–100)**: Real-time visual health indicator.
- **Live Activity Feed**: Filter by *High Risk*, *Trackers*, *Blocked*, or *Active*, with process badges (Chrome, Spotify, Discord, Slack, etc.).
- **One-Click Protect Me Shield**: Autonomous multi-step privacy hardening.
- **Deep Investigation Drawer**: Inspect any domain with Nemotron's plain-English breakdown.
- **One-Click Demo Mode Toggle**: Instantly switch between realistic simulated desktop traffic and live host network monitoring.

---

## 🚀 Quick Start for Hackathon Judges

Sentinel is designed for immediate testing with zero setup friction.

### Prerequisites
- Python 3.10+ (Tested on Python 3.14 / 3.11 / 3.10)
- Windows, macOS, or Linux

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/sentinel.git
cd sentinel
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Nebius Token Factory (Optional)
Copy the example environment file:
```bash
cp .env.example .env
```
Edit `.env` to include your Nebius Token Factory API key:
```ini
NEBIUS_API_KEY=your_nebius_api_key_here
NEBIUS_BASE_URL=https://api.studio.nebius.ai/v1/
NEBIUS_MODEL=nvidia/Llama-3.1-Nemotron-70B-Instruct-HF
SENTINEL_DEMO_MODE=true
```
*(Note: If no API key is provided, Sentinel seamlessly switches to its Local Fallback Engine so you can evaluate the complete user experience immediately.)*

### 4. Launch Sentinel
#### Option A: 1-Click Launcher (Windows)
Double-click:
```cmd
run_sentinel.bat
```

#### Option B: Python Command Line
```bash
python main.py
```
*Sentinel will launch the FastAPI backend and automatically open your default browser to `http://127.0.0.1:8765`.*

#### Option C: Native PyQt6 Desktop Window
```bash
python main.py --desktop
```

---

## 🧪 Demo Mode Walkthrough

For hackathon judges, Sentinel starts in **Demo Mode** by default with realistic desktop network traffic:
1. **Observe the Dashboard**: Notice the Privacy Score (e.g. `82/100`), total connections, and active trackers from Chrome, Spotify, Discord, and Zoom.
2. **Investigate a Tracker**:
   - Locate `fingerprint.device-id.net` (Chrome) or `adservice.google.com`.
   - Click **[Investigate]**.
   - Watch Nemotron analyze the telemetry and provide an explanation with consequence prediction.
   - Click **[Block Domain]**. Notice the connection badge updates to `BLOCKED`.
3. **Execute 'Protect Me'**:
   - Click the big green **Protect Me** button.
   - Sentinel scans all active connections and presents Nemotron's multi-connection defense plan.
   - Click **[Apply Nemotron Protection Plan]**.
   - Notice the animated celebration banner showing your score improving (e.g. from `72` to `94`) and trackers neutralized.
4. **Generate 'Explain My Privacy'**:
   - Click **[Explain My Privacy]**.
   - Review the AI executive audit summarizing top offenders and privacy recommendations.
5. **Toggle Live Monitoring**:
   - Click the **[DEMO MODE]** badge in the header to switch to live host socket monitoring via `psutil`.

---

## 🧪 Automated Test Suite

Sentinel includes a comprehensive test suite covering detection heuristics, PII sanitization, SQLite persistence, Nemotron JSON parsing, and the 10-step Protect Me agent workflow.

Run all tests:
```bash
pytest -v
```

Output:
```
============================= test session starts =============================
tests/test_api.py::test_api_stats PASSED                                 [  4%]
tests/test_api.py::test_api_connections PASSED                           [  8%]
tests/test_api.py::test_api_connections_filtering PASSED                 [ 12%]
tests/test_api.py::test_api_investigate PASSED                           [ 16%]
tests/test_api.py::test_api_quick_decision PASSED                        [ 20%]
tests/test_api.py::test_api_explain_privacy PASSED                       [ 25%]
tests/test_detector.py::test_known_ad_tracker_detection PASSED           [ 29%]
tests/test_detector.py::test_fingerprinting_detection PASSED             [ 33%]
tests/test_detector.py::test_telemetry_detection PASSED                  [ 37%]
tests/test_detector.py::test_cdn_safe_detection PASSED                   [ 41%]
tests/test_detector.py::test_essential_api_safe_detection PASSED         [ 45%]
tests/test_detector.py::test_privacy_score_calculation PASSED            [ 50%]
tests/test_nemotron_agent.py::test_extract_json_from_raw PASSED          [ 54%]
tests/test_nemotron_agent.py::test_extract_json_from_markdown_fences PASSED [ 58%]
tests/test_nemotron_agent.py::test_fallback_engine_investigate PASSED    [ 62%]
tests/test_nemotron_agent.py::test_fallback_engine_essential_api PASSED  [ 66%]
tests/test_nemotron_agent.py::test_agent_investigate_offline_resilience PASSED [ 70%]
tests/test_policy_store.py::test_save_and_retrieve_decision PASSED       [ 75%]
tests/test_policy_store.py::test_wildcard_application_policy PASSED      [ 79%]
tests/test_policy_store.py::test_delete_rule PASSED                      [ 83%]
tests/test_policy_store.py::test_record_events_and_top_offenders PASSED  [ 87%]
tests/test_protect_me.py::test_protect_me_workflow PASSED                [ 91%]
tests/test_sanitizer.py::test_clean_domain_stripping PASSED              [ 95%]
tests/test_sanitizer.py::test_sanitization_for_nemotron PASSED           [100%]
============================= 24 passed in 3.01s ==============================
```

---

## 🔒 Security & Privacy Guarantees

Sentinel adheres to strict local-first privacy principles:
- **No Keystroke / Password Collection**: Sockets are monitored strictly at the network protocol and process metadata level.
- **Payload Sanitization**: URLs are stripped of all paths, query parameters, session tokens, and credentials before any analysis.
- **Local Policy Persistence**: User decisions and rules are stored on-device in a local SQLite database (`sentinel_data.db`).
- **Zero API Key Leakage**: API keys and environment secrets are strictly ignored via `.gitignore` and kept in runtime memory.

---

## 📂 Project Architecture

```
sentinel/
├── backend/
│   ├── app.py                # FastAPI server & REST API
│   ├── config.py             # Pydantic environment configuration
│   └── models.py             # Pydantic data contracts (events, scores, policies)
├── privacy_engine/
│   ├── blocklist.py          # Curated tracker & telemetry knowledge base
│   ├── detector.py           # Local heuristics, classification & scoring
│   └── sanitizer.py          # Data sanitization before LLM evaluation
├── agent/
│   ├── nemotron_agent.py     # NVIDIA Nemotron client via Nebius Token Factory
│   ├── prompts.py            # Structured system & task prompts
│   └── fallback_engine.py    # Zero-downtime offline fallback intelligence
├── monitor/
│   ├── connection_monitor.py # Live socket monitor via psutil & reverse DNS
│   └── demo_traffic.py       # Realistic simulation for evaluators
├── database/
│   └── policy_store.py       # SQLite persistence for decisions & history
├── frontend/
│   ├── static/
│   │   ├── css/sentinel.css  # Dark-mode consumer security UI styling
│   │   ├── js/sentinel.js    # Interactive frontend controller
│   │   └── assets/logo.svg   # Custom cyber shield SVG logo
│   └── templates/
│       └── index.html        # Consumer desktop dashboard
├── desktop/
│   └── window.py             # PyQt6 native desktop window wrapper
├── tests/                    # 24 comprehensive unit & integration tests
├── main.py                   # Unified CLI & application launcher
├── run_sentinel.bat          # 1-click Windows launcher
├── .env.example              # Sample environment template
├── requirements.txt          # Python dependencies
└── LICENSE                   # MIT Open Source License
```

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
