"""
Sentinel Curated Privacy & Tracker Knowledge Base
Categorizes known domains into Ad Tracking, Analytics, Telemetry, Fingerprinting,
Crash Reporting, and Essential APIs/CDNs.
"""
from typing import Dict, Any, Optional

TRACKER_DATABASE: Dict[str, Dict[str, Any]] = {
    # ------------------ AD TRACKING & TARGETING (High Risk) ------------------
    "doubleclick.net": {
        "vendor": "Google",
        "category": "ad_tracking",
        "risk_level": "high",
        "risk_score": 90,
        "consequences": ["Targeted advertising will be blocked", "No degradation to web functionality"],
        "known_tracker": True
    },
    "adservice.google.com": {
        "vendor": "Google",
        "category": "ad_tracking",
        "risk_level": "high",
        "risk_score": 92,
        "consequences": ["Google behavioral ad tracking disabled", "Search results and pages load faster"],
        "known_tracker": True
    },
    "adnxs.com": {
        "vendor": "AppNexus / Xandr",
        "category": "ad_tracking",
        "risk_level": "high",
        "risk_score": 88,
        "consequences": ["Cross-site programmatic ad tracking stopped"],
        "known_tracker": True
    },
    "criteo.com": {
        "vendor": "Criteo",
        "category": "ad_tracking",
        "risk_level": "high",
        "risk_score": 91,
        "consequences": ["Retargeted product ads across browsing sessions eliminated"],
        "known_tracker": True
    },
    "scorecardresearch.com": {
        "vendor": "Comscore",
        "category": "ad_tracking",
        "risk_level": "high",
        "risk_score": 89,
        "consequences": ["Audience behavior measurement disabled"],
        "known_tracker": True
    },
    "facebook.com/tr": {
        "vendor": "Meta",
        "category": "ad_tracking",
        "risk_level": "high",
        "risk_score": 94,
        "consequences": ["Meta Pixel tracking prevented", "Facebook cannot link external activity to your profile"],
        "known_tracker": True
    },
    "connect.facebook.net": {
        "vendor": "Meta",
        "category": "ad_tracking",
        "risk_level": "high",
        "risk_score": 87,
        "consequences": ["Meta tracking scripts blocked", "Social login widgets might need manual click"],
        "known_tracker": True
    },

    # ------------------ FINGERPRINTING & BEHAVIORAL PROFILING (High Risk) ------------------
    "fingerprint.device-id.net": {
        "vendor": "Device Fingerprint Aggregator",
        "category": "fingerprinting",
        "risk_level": "high",
        "risk_score": 96,
        "consequences": ["Hardware canvas and font fingerprinting thwarted", "Anonymous device tracking stopped"],
        "known_tracker": True
    },
    "fpjs.io": {
        "vendor": "FingerprintJS",
        "category": "fingerprinting",
        "risk_level": "high",
        "risk_score": 95,
        "consequences": ["Persistent cross-browser device identification blocked"],
        "known_tracker": True
    },
    "fullstory.com": {
        "vendor": "FullStory",
        "category": "fingerprinting",
        "risk_level": "high",
        "risk_score": 92,
        "consequences": ["Session replay and screen interaction recording stopped"],
        "known_tracker": True
    },
    "hotjar.com": {
        "vendor": "Hotjar",
        "category": "fingerprinting",
        "risk_level": "high",
        "risk_score": 89,
        "consequences": ["Heatmaps and mouse movement recording disabled"],
        "known_tracker": True
    },

    # ------------------ TELEMETRY & BACKGROUND BEACONS (Medium Risk) ------------------
    "spclient.wg.spotify.com": {
        "vendor": "Spotify",
        "category": "telemetry",
        "risk_level": "medium",
        "risk_score": 65,
        "consequences": ["Background telemetry & listening stats paused", "Music playback and playlists continue normally"],
        "known_tracker": True
    },
    "telemetry.zoom.us": {
        "vendor": "Zoom",
        "category": "telemetry",
        "risk_level": "medium",
        "risk_score": 60,
        "consequences": ["Meeting diagnostics and usage telemetry stopped", "Video calls work uninterrupted"],
        "known_tracker": True
    },
    "vortex.data.microsoft.com": {
        "vendor": "Microsoft",
        "category": "telemetry",
        "risk_level": "medium",
        "risk_score": 68,
        "consequences": ["Windows / Office diagnostic data upload halted", "Core OS and desktop apps work normally"],
        "known_tracker": True
    },
    "edge.activity.windows.com": {
        "vendor": "Microsoft",
        "category": "telemetry",
        "risk_level": "medium",
        "risk_score": 67,
        "consequences": ["Edge timeline and browsing sync telemetry stopped"],
        "known_tracker": True
    },

    # ------------------ ANALYTICS & EVENT LOGGING (Medium Risk) ------------------
    "google-analytics.com": {
        "vendor": "Google",
        "category": "analytics",
        "risk_level": "medium",
        "risk_score": 75,
        "consequences": ["Website usage tracking blocked", "Page content remains intact"],
        "known_tracker": True
    },
    "analytics.discord.com": {
        "vendor": "Discord",
        "category": "analytics",
        "risk_level": "medium",
        "risk_score": 62,
        "consequences": ["Discord UI interaction metrics disabled", "Voice, text, and servers work normally"],
        "known_tracker": True
    },
    "mixpanel.com": {
        "vendor": "Mixpanel",
        "category": "analytics",
        "risk_level": "medium",
        "risk_score": 74,
        "consequences": ["User interaction funnels blocked", "App core features unaffected"],
        "known_tracker": True
    },
    "segment.io": {
        "vendor": "Twilio Segment",
        "category": "analytics",
        "risk_level": "medium",
        "risk_score": 73,
        "consequences": ["Customer data routing disabled"],
        "known_tracker": True
    },
    "amplitude.com": {
        "vendor": "Amplitude",
        "category": "analytics",
        "risk_level": "medium",
        "risk_score": 72,
        "consequences": ["Product behavioral analytics halted"],
        "known_tracker": True
    },

    # ------------------ CRASH REPORTING (Low/Medium Risk) ------------------
    "sentry.io": {
        "vendor": "Sentry",
        "category": "crash_reporting",
        "risk_level": "low",
        "risk_score": 40,
        "consequences": ["Automated crash logs will not be sent to developers"],
        "known_tracker": False
    },
    "bugsnag.com": {
        "vendor": "Bugsnag",
        "category": "crash_reporting",
        "risk_level": "low",
        "risk_score": 42,
        "consequences": ["Crash diagnosis reports stopped"],
        "known_tracker": False
    },

    # ------------------ ESSENTIAL CDN & INFRASTRUCTURE (Safe) ------------------
    "cloudflare.net": {
        "vendor": "Cloudflare",
        "category": "cdn_content",
        "risk_level": "safe",
        "risk_score": 10,
        "consequences": ["Blocking may break images, styles, and web loading"],
        "known_tracker": False
    },
    "cdn.cloudflare.net": {
        "vendor": "Cloudflare",
        "category": "cdn_content",
        "risk_level": "safe",
        "risk_score": 10,
        "consequences": ["Essential asset delivery; blocking breaks UI rendering"],
        "known_tracker": False
    },
    "cdn.slack-edge.com": {
        "vendor": "Slack",
        "category": "cdn_content",
        "risk_level": "safe",
        "risk_score": 12,
        "consequences": ["Slack avatars, attachments, and scripts will fail to load"],
        "known_tracker": False
    },
    "api.stripe.com": {
        "vendor": "Stripe",
        "category": "essential_api",
        "risk_level": "safe",
        "risk_score": 5,
        "consequences": ["CRITICAL: Payment transactions and checkouts will fail"],
        "known_tracker": False
    },
    "gateway.discord.gg": {
        "vendor": "Discord",
        "category": "essential_api",
        "risk_level": "safe",
        "risk_score": 15,
        "consequences": ["CRITICAL: Discord live messaging and voice connect will disconnect"],
        "known_tracker": False
    }
}

def lookup_domain(domain: str) -> Optional[Dict[str, Any]]:
    """Lookup a domain or its parent root in the tracker database."""
    clean = domain.lower().strip().rstrip(".")
    if clean in TRACKER_DATABASE:
        return TRACKER_DATABASE[clean]
    
    # Try suffix match (e.g. sub.adservice.google.com -> adservice.google.com -> google.com)
    parts = clean.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in TRACKER_DATABASE:
            return TRACKER_DATABASE[parent]
            
    return None
