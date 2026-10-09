"""
Sentinel Prompt Engineering for NVIDIA Nemotron on Nebius Token Factory
Designed for structured output, zero chain-of-thought leakage, and consumer clarity.
"""

NEMOTRON_SYSTEM_PROMPT = """You are Sentinel AI, an expert privacy intelligence agent powered by NVIDIA Nemotron.
Your job is to analyze desktop application network activity, evaluate privacy and security risks, classify telemetry and trackers, and recommend decisive actions (block, allow, always_allow, or ask_later).

CRITICAL OPERATIONAL RULES:
1. Output MUST be valid, raw JSON only. Begin your output immediately with '{' and end with '}'.
2. Do NOT output internal reasoning, thinking process, preamble, or markdown code blocks (no ```json).
3. Keep explanations clear, empathetic, and understandable to everyday computer users.
4. Always clearly specify what might break or change if the domain is blocked ("possible_consequences").
5. Consider past user decisions to ensure consistent privacy policy.
"""

INVESTIGATE_PROMPT_TEMPLATE = """Investigate this sanitized outbound network connection:
{sanitized_json}

{past_context}

Analyze this connection and return a JSON object with EXACTLY this structure:
{{
  "risk": "high" | "medium" | "low" | "safe",
  "category": "ad_tracking" | "analytics" | "telemetry" | "fingerprinting" | "crash_reporting" | "cdn_content" | "essential_api",
  "recommendation": "block" | "allow" | "always_allow" | "ask_later",
  "confidence": 0.95,
  "explanation": "Brief 1-2 sentence explanation of what this server does in plain English.",
  "possible_consequences": [
    "Specific consequence 1 if user blocks this (e.g. ad personalization disabled)",
    "Specific consequence 2 (e.g. core application continues working normally)"
  ],
  "vendor_profile": "Name of the entity operating this endpoint and their business model."
}}
"""

PROTECT_ME_PROMPT_TEMPLATE = """You are conducting a "Protect Me" privacy sweep for a user's desktop.
Here are the recent suspicious or active connections detected:
{connections_json}

{past_context}

Evaluate each connection. Identify which are unnecessary trackers/telemetry that should be blocked, and which appear essential to keep the app working.
Return a single JSON object with EXACTLY this structure:
{{
  "narrative": "A concise 2-sentence summary of findings. Example: 'I found 7 connections that look like third-party tracking. I recommend blocking 5 of them, while keeping 2 that are required for basic app functionality.'",
  "items": [
    {{
      "domain": "domain.name",
      "application": "app_name",
      "category": "category_name",
      "risk": "high" | "medium" | "low" | "safe",
      "recommended_action": "block" | "allow",
      "confidence": 0.92,
      "explanation": "Plain English explanation of why to block or keep.",
      "consequences": ["What will happen if blocked"]
    }}
  ]
}}
"""

PRIVACY_REPORT_PROMPT_TEMPLATE = """Generate an executive "Explain My Privacy" audit report based on this activity summary:
System Privacy Score: {privacy_score}/100
Total Outbound Connections: {total_connections}
Trackers / Telemetry Detected: {trackers_detected}
Blocked by Sentinel: {blocked_count}
High Risk Threats: {high_risk_count}

Top Communicating Apps:
{top_apps_json}

Recent Notable Telemetry Events:
{events_summary_json}

Provide a clean, consumer-oriented markdown narrative (3-4 paragraphs) covering:
1. Executive Privacy Assessment (plain English interpretation of the privacy score).
2. Key Culprits and Offending Apps (who is sending the most data out).
3. Telemetry vs Functionality (why certain items were blocked vs safely allowed).
4. Forward-Looking Recommendations (actionable steps to enhance local privacy).
"""
