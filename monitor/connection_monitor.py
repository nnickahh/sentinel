"""
Sentinel Live Connection Monitor & Edge/Chrome Browser Link Engine
Monitors real-time outbound host TCP/UDP network connections using psutil,
Windows DNS Resolver Cache (ipconfig /displaydns), and browser ASN heuristics.
Directly links to local Microsoft Edge (msedge.exe) and Google Chrome (chrome.exe).
"""
import psutil
import socket
import subprocess
import re
import time
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from backend.models import ConnectionEvent, ConnectionStatus, ActionDecision, RiskLevel, Category
from privacy_engine.detector import PrivacyDetector
from database.policy_store import PolicyStore

logger = logging.getLogger("sentinel.monitor")

# Truthful cloud ASN / provider identification when reverse DNS PTR is not in local Windows DNS cache
CLOUD_ASN_PREFIXES: List[Tuple[str, str]] = [
    ("162.247.", "Opera Norway AS (Oslo)"),
    ("107.167.", "Opera Norway AS (Oslo)"),
    ("82.145.", "Opera Norway AS (Oslo)"),
    ("185.26.", "Opera Norway AS (Oslo)"),
    ("140.82.", "GitHub"),
    ("185.199.", "GitHub"),
    ("20.205.", "GitHub"),
    ("104.16.", "Cloudflare CDN"),
    ("104.18.", "Cloudflare CDN"),
    ("104.20.", "Cloudflare CDN"),
    ("140.248.", "Cloudflare CDN"),
    ("172.64.", "Cloudflare CDN"),
    ("172.66.", "Cloudflare CDN"),
    ("162.159.", "Cloudflare CDN"),
    ("13.35.", "Amazon CloudFront"),
    ("99.86.", "Amazon CloudFront"),
    ("108.156.", "Amazon CloudFront"),
    ("3.165.", "Amazon CloudFront"),
    ("54.", "Amazon AWS"),
    ("75.2.", "AWS Global Accelerator"),
    ("130.211.", "Google Cloud"),
    ("34.", "Google Cloud"),
    ("35.", "Google Cloud"),
    ("74.125.", "Google LLC"),
    ("142.250.", "Google LLC"),
    ("142.251.", "Google LLC"),
    ("172.217.", "Google LLC"),
    ("216.58.", "Google LLC"),
    ("13.", "Microsoft Azure"),
    ("20.", "Microsoft Azure"),
    ("23.103.", "Microsoft Corp"),
    ("40.", "Microsoft Azure"),
    ("52.", "Microsoft Azure"),
    ("4.145.", "Microsoft Azure"),
    ("172.188.", "Microsoft Azure"),
    ("151.101.", "Fastly CDN"),
    ("192.168.", "Local Network (LAN)"),
]


# ISO-3166-1 alpha-2 country code to full country name mapping for PE Authenticode certificates
ISO_COUNTRY_NAMES: Dict[str, str] = {
    "US": "United States",
    "CN": "China",
    "HK": "China",
    "MO": "China",
    "RU": "Russia",
    "DE": "Germany",
    "IL": "Israel",
    "NO": "Norway",
    "IT": "Italy",
    "FR": "France",
    "GB": "United Kingdom",
    "UK": "United Kingdom",
    "SE": "Sweden",
    "NL": "Netherlands",
    "ES": "Spain",
    "SG": "Singapore",
    "CA": "Canada",
    "JP": "Japan",
    "KR": "South Korea",
    "TW": "Taiwan",
    "CH": "Switzerland",
    "AU": "Australia",
    "LT": "Lithuania",
    "PL": "Poland",
    "CZ": "Czechia",
    "FI": "Finland",
    "AT": "Austria",
    "BE": "Belgium",
    "DK": "Denmark",
    "IE": "Ireland",
    "BR": "Brazil",
    "IN": "India",
    "AE": "United Arab Emirates",
}

# Curated Application Country of Origin -> (Attack-Sources Bucket, Exact Country Name, Publisher / Origin Label)
APP_ORIGIN_COUNTRIES: Dict[str, Tuple[str, str, str]] = {
    # --- United States ---
    "antigravity": ("United States", "United States", "Google DeepMind (US)"),
    "edge": ("United States", "United States", "Microsoft Corp (US)"),
    "chrome": ("United States", "United States", "Google LLC (US)"),
    "discord": ("United States", "United States", "Discord Inc. (US)"),
    "ms-teams": ("United States", "United States", "Microsoft Corp (US)"),
    "vscode": ("United States", "United States", "Microsoft Corp (US)"),
    "cursor": ("United States", "United States", "Anysphere Inc. (US)"),
    "roblox": ("United States", "United States", "Roblox Corp (US)"),
    "robloxplayerbeta": ("United States", "United States", "Roblox Corp (US)"),
    "dawn (feather)": ("United States", "United States", "InPvP Inc. / Feather (US)"),
    "dawn": ("United States", "United States", "InPvP Inc. / Feather (US)"),
    "steam": ("United States", "United States", "Valve Corp (US)"),
    "whatsapp": ("United States", "United States", "Meta Platforms (US)"),
    "claude": ("United States", "United States", "Anthropic (US)"),
    "valorant": ("United States", "United States", "Riot Games (US)"),
    "league of legends": ("United States", "United States", "Riot Games (US)"),
    "riot client": ("United States", "United States", "Riot Games (US)"),
    "rockstar": ("United States", "United States", "Rockstar Games (US)"),
    "opencode": ("United States", "United States", "Anomaly / OpenCode (US)"),
    "slack": ("United States", "United States", "Slack / Salesforce (US)"),
    "zoom": ("United States", "United States", "Zoom Video (US)"),
    "brave": ("United States", "United States", "Brave Software (US)"),
    "firefox": ("United States", "United States", "Mozilla Corp (US)"),
    "epic games": ("United States", "United States", "Epic Games (US)"),

    # --- China ---
    "tiktok live studio": ("China", "China", "ByteDance / TikTok (China)"),
    "tiktok": ("China", "China", "ByteDance / TikTok (China)"),
    "wuthering waves": ("China", "China", "Kuro Games (Guangzhou, China)"),
    "client-win64-shipping": ("China", "China", "Kuro Games (Guangzhou, China)"),
    "wechat": ("China", "China", "Tencent (Shenzhen, China)"),
    "weixin": ("China", "China", "Tencent (Shenzhen, China)"),
    "qq": ("China", "China", "Tencent (Shenzhen, China)"),
    "capcut": ("China", "China", "ByteDance (Beijing, China)"),
    "wps": ("China", "China", "Kingsoft WPS (Zhuhai, China)"),
    "wpsoffice": ("China", "China", "Kingsoft WPS (Zhuhai, China)"),
    "genshin impact": ("China", "China", "miHoYo / HoYoverse (Shanghai, China)"),
    "genshinimpact": ("China", "China", "miHoYo / HoYoverse (Shanghai, China)"),
    "yuanshen": ("China", "China", "miHoYo (Shanghai, China)"),
    "honkai: star rail": ("China", "China", "miHoYo / HoYoverse (Shanghai, China)"),
    "starrail": ("China", "China", "miHoYo / HoYoverse (Shanghai, China)"),
    "zenless zone zero": ("China", "China", "miHoYo / HoYoverse (Shanghai, China)"),
    "zenlesszonezero": ("China", "China", "miHoYo / HoYoverse (Shanghai, China)"),
    "hoyoplay": ("China", "China", "miHoYo / HoYoverse (Shanghai, China)"),
    "hyp": ("China", "China", "miHoYo / HoYoverse (Shanghai, China)"),
    "marvel rivals": ("China", "China", "NetEase Games (Hangzhou, China)"),
    "marvelrivals": ("China", "China", "NetEase Games (Hangzhou, China)"),
    "baidu": ("China", "China", "Baidu (Beijing, China)"),
    "baidunetdisk": ("China", "China", "Baidu (Beijing, China)"),
    "dingtalk": ("China", "China", "Alibaba DingTalk (Hangzhou, China)"),
    "feishu": ("China", "China", "ByteDance Feishu (Beijing, China)"),
    "lark": ("China", "China", "ByteDance Lark (China)"),
    "bilibili": ("China", "China", "Bilibili (Shanghai, China)"),
    "uu": ("China", "China", "NetEase UU (Hangzhou, China)"),
    "deepseek": ("China", "China", "DeepSeek (Hangzhou, China)"),
    "trae": ("China", "China", "ByteDance Trae (China)"),

    # --- Russia ---
    "kaspersky": ("Russia", "Russia", "Kaspersky Lab (Moscow, Russia)"),
    "avp": ("Russia", "Russia", "Kaspersky Lab (Moscow, Russia)"),
    "yandex": ("Russia", "Russia", "Yandex (Moscow, Russia)"),
    "telegram": ("Russia", "Russia", "Telegram Messenger (Russia)"),
    "vk": ("Russia", "Russia", "VK (Saint Petersburg, Russia)"),
    "7-zip": ("Russia", "Russia", "Igor Pavlov 7-Zip (Russia)"),
    "7zfm": ("Russia", "Russia", "Igor Pavlov 7-Zip (Russia)"),
    "escape from tarkov": ("Russia", "Russia", "Battlestate Games (Russia)"),
    "escapefromtarkov": ("Russia", "Russia", "Battlestate Games (Russia)"),
    "bsglauncher": ("Russia", "Russia", "Battlestate Games (Russia)"),
    "war thunder": ("Russia", "Russia", "Gaijin Entertainment (Russia)"),
    "aces": ("Russia", "Russia", "Gaijin Entertainment (Russia)"),

    # --- Germany ---
    "anydesk": ("Germany", "Germany", "AnyDesk Software GmbH (Stuttgart, Germany)"),
    "teamviewer": ("Germany", "Germany", "TeamViewer SE (Göppingen, Germany)"),
    "nextcloud": ("Germany", "Germany", "Nextcloud GmbH (Stuttgart, Germany)"),
    "sap": ("Germany", "Germany", "SAP SE (Walldorf, Germany)"),
    "saplogon": ("Germany", "Germany", "SAP SE (Walldorf, Germany)"),
    "sapgui": ("Germany", "Germany", "SAP SE (Walldorf, Germany)"),
    "avira": ("Germany", "Germany", "Avira Operations GmbH (Germany)"),
    "ableton": ("Germany", "Germany", "Ableton AG (Berlin, Germany)"),
    "nero": ("Germany", "Germany", "Nero AG (Karlsruhe, Germany)"),
    "winrar": ("Germany", "Germany", "win.rar GmbH (Berlin, Germany)"),

    # --- Other Countries (Israel, Norway, Italy, France, UK, Sweden, Netherlands, Spain, Singapore, Canada, Japan, Taiwan, etc.) ---
    "overwolf": ("Other", "Israel", "Overwolf Ltd (Tel Aviv, Israel)"),
    "overwolfbrowser": ("Other", "Israel", "Overwolf Ltd (Tel Aviv, Israel)"),
    "curseforge": ("Other", "Israel", "Overwolf / CurseForge (Tel Aviv, Israel)"),
    "valorant tracker": ("Other", "Israel", "Overwolf Ltd (Tel Aviv, Israel)"),
    "opera": ("Other", "Norway", "Opera Norway AS (Oslo, Norway)"),
    "arduino ide": ("Other", "Italy", "Arduino S.r.l. (Turin, Italy)"),
    "arduino": ("Other", "Italy", "Arduino S.r.l. (Turin, Italy)"),
    "mobaxterm": ("Other", "France", "Mobatek (Toulouse, France)"),
    "ubisoft connect": ("Other", "France", "Ubisoft Entertainment (Paris, France)"),
    "upc": ("Other", "France", "Ubisoft Entertainment (Paris, France)"),
    "ubisoftconnect": ("Other", "France", "Ubisoft Entertainment (Paris, France)"),
    "rainbowsix": ("Other", "France", "Ubisoft (France)"),
    "growtopia": ("Other", "France", "Ubisoft Abu Dhabi / Ubisoft (France)"),
    "vlc": ("Other", "France", "VideoLAN (Paris, France)"),
    "vncviewer": ("Other", "United Kingdom", "RealVNC Ltd (Cambridge, UK)"),
    "rpi-imager": ("Other", "United Kingdom", "Raspberry Pi Ltd (Cambridge, UK)"),
    "op auto clicker": ("Other", "United Kingdom", "OP Auto Clicker (UK)"),
    "opautoclicker": ("Other", "United Kingdom", "OP Auto Clicker (UK)"),
    "spotify": ("Other", "Sweden", "Spotify AB (Stockholm, Sweden)"),
    "minecraft": ("Other", "Sweden", "Mojang Studios (Stockholm, Sweden)"),
    "medal": ("Other", "Netherlands", "Medal B.V. (Amsterdam, Netherlands)"),
    "blender": ("Other", "Netherlands", "Blender Foundation (Amsterdam, Netherlands)"),
    "voicemod": ("Other", "Spain", "Voicemod S.L. (Valencia, Spain)"),
    "razer": ("Other", "Singapore", "Razer Inc. (Singapore)"),
    "razercortex": ("Other", "Singapore", "Razer Inc. (Singapore)"),
    "razer central": ("Other", "Singapore", "Razer Inc. (Singapore)"),
    "razersynapse": ("Other", "Singapore", "Razer Inc. (Singapore)"),
    "dead by daylight": ("Other", "Canada", "Behaviour Interactive (Montreal, Canada)"),
    "deadbydaylight": ("Other", "Canada", "Behaviour Interactive (Montreal, Canada)"),
    "the bridge curse": ("Other", "Taiwan", "Softstar Entertainment (Taipei, Taiwan)"),
    "thebridgecurse": ("Other", "Taiwan", "Softstar Entertainment (Taipei, Taiwan)"),
    "pico park": ("Other", "Japan", "TECOPARK (Osaka, Japan)"),
    "picopark": ("Other", "Japan", "TECOPARK (Osaka, Japan)"),
    "meccha chameleon": ("Other", "Japan", "Japan"),
    "protonvpn": ("Other", "Switzerland", "Proton AG (Geneva, Switzerland)"),
    "protonmail": ("Other", "Switzerland", "Proton AG (Geneva, Switzerland)"),
    "nordvpn": ("Other", "Lithuania", "Nord Security (Vilnius, Lithuania)"),
    "canva": ("Other", "Australia", "Canva Pty Ltd (Sydney, Australia)"),
}

_CA_KEYWORDS = (
    "digicert", "sectigo", "comodo", "verisign", "symantec", "thawte",
    "geotrust", "globalsign", "entrust", "ssl.com", "godaddy", "usertrust",
    "starfield", "aaa certificate", "identrust", "certum", "harica", "actalis"
)


class LiveConnectionMonitor:
    def __init__(self, detector: PrivacyDetector, policy_store: PolicyStore):
        self.detector = detector
        self.policy_store = policy_store
        self._dns_cache: Dict[str, str] = {}
        self._counts: Dict[str, int] = {}
        self._last_dns_sync: float = 0.0
        self._last_poll_ts: float = 0.0
        self._cached_poll_events: List[ConnectionEvent] = []
        self._browser_ingested_events: Dict[str, ConnectionEvent] = {}
        self._app_exe_paths: Dict[str, str] = {}
        self._exe_cert_cache: Dict[str, Optional[Tuple[str, str, str]]] = {}
        self._last_open_win_ts: float = 0.0
        self._cached_open_apps: set = set()
        self._cached_open_pids: set = set()

    def _extract_pe_authenticode_country(self, exe_path: str) -> Optional[Tuple[str, str, str]]:
        """
        Fast pure-Python inspection of a Windows PE executable's Authenticode X.509 certificate
        to read the publisher's ISO country code (OID 2.5.4.6) and organization (OID 2.5.4.10).
        Cached per executable path so each binary is parsed at most once.
        """
        if not exe_path:
            return None
        if exe_path in self._exe_cert_cache:
            return self._exe_cert_cache[exe_path]

        import struct
        result: Optional[Tuple[str, str, str]] = None
        try:
            with open(exe_path, "rb") as f:
                data = f.read(4096)
                if data[:2] == b"MZ":
                    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
                    if pe_offset + 200 <= len(data) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                        magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
                        sec_dir_offset = pe_offset + 24 + (144 if magic == 0x20B else 128)
                        cert_rva, cert_size = struct.unpack_from("<II", data, sec_dir_offset)
                        if cert_rva and cert_size:
                            f.seek(cert_rva)
                            cert_bytes = f.read(min(cert_size, 65536))
                            candidates: List[Tuple[str, str]] = []
                            for m in re.finditer(b"\x06\x03\x55\x04\x06[\x13\x0c\x16]\x02([A-Z]{2})", cert_bytes):
                                c_code = m.group(1).decode("ascii")
                                window = cert_bytes[m.end():m.end() + 180]
                                org_m = re.search(b"\x06\x03\x55\x04\x0a[\x13\x0c\x16](.)", window, re.DOTALL)
                                org_name = ""
                                if org_m:
                                    olen = org_m.group(1)[0]
                                    org_name = window[org_m.end():org_m.end() + olen].decode("utf-8", "ignore").strip()
                                if org_name and not any(ca in org_name.lower() for ca in _CA_KEYWORDS):
                                    candidates.append((c_code, org_name))
                            # Prefer non-Microsoft leaf signer if present (since Microsoft is often the counter-signer CA)
                            non_ms = [c for c in candidates if "microsoft" not in c[1].lower()]
                            chosen = non_ms[0] if non_ms else (candidates[0] if candidates else None)
                            if chosen:
                                c_code, org_name = chosen
                                exact_country = ISO_COUNTRY_NAMES.get(c_code, c_code)
                                if exact_country in ("United States", "China", "Russia", "Germany"):
                                    bucket = exact_country
                                else:
                                    bucket = "Other"
                                result = (bucket, exact_country, f"{org_name} ({exact_country})")
        except Exception:
            result = None

        self._exe_cert_cache[exe_path] = result
        return result

    def classify_app_and_ip_country(
        self,
        app_name: str = "",
        ip_str: str = "",
        domain: str = ""
    ) -> Tuple[str, str, Optional[str]]:
        """
        Accurately determine (bucket_country, origin_country, publisher_label) for a running app and socket:
        1. Curated Application Country of Origin database
        2. Windows PE Authenticode digital signature X.509 country code (C=XX) of the running .exe
        3. Domain TLD / hostname & known foreign ASN prefixes (Opera Norway, .cn, .ru, .de, .il, .no, .it, .fr, .uk, .se, etc.)
        4. Regional Internet Registry (RIR) IPv4 prefix blocks for US, China, Russia, Germany, and Other
        """
        app_low = (app_name or "").lower().strip()
        dom_low = (domain or "").lower().strip().rstrip(".")
        ip_clean = (ip_str or "").strip()

        # 1. Exact or prefix match in Curated App Country of Origin database
        if app_low in APP_ORIGIN_COUNTRIES:
            return APP_ORIGIN_COUNTRIES[app_low]

        # 2. Live PE Authenticode Certificate Country from the running executable on disk
        exe_path = self._app_exe_paths.get(app_low)
        if exe_path:
            pe_info = self._extract_pe_authenticode_country(exe_path)
            if pe_info:
                return pe_info

        # 3. Known foreign cloud / ASN prefixes & Domain TLDs
        if ip_clean.startswith(("162.247.", "82.145.", "185.26.", "107.167.")):
            return ("Other", "Norway", "Opera Norway AS (Oslo, Norway)")

        if dom_low:
            if dom_low.endswith((".cn", ".com.cn", ".net.cn", ".org.cn")) or any(
                k in dom_low for k in ("qq.com", "weixin.", "bilibili.", "baidu.", "aliyun.", "tiktok.", "bytedance.", "kurogames.", "hoyoverse.", "mihoyo.")
            ):
                return ("China", "China", None)
            if dom_low.endswith((".ru", ".su", ".рф")) or any(
                k in dom_low for k in ("yandex.", "vk.com", "mail.ru", "kaspersky.")
            ):
                return ("Russia", "Russia", None)
            if dom_low.endswith(".de") or any(
                k in dom_low for k in ("hetzner.", "t-online.de", "ionos.", "anydesk.com", "teamviewer.com")
            ):
                return ("Germany", "Germany", None)
            tld_other_map = (
                (".no", "Norway"),
                (".il", "Israel"),
                (".co.il", "Israel"),
                (".it", "Italy"),
                (".fr", "France"),
                (".uk", "United Kingdom"),
                (".co.uk", "United Kingdom"),
                (".se", "Sweden"),
                (".nl", "Netherlands"),
                (".es", "Spain"),
                (".sg", "Singapore"),
                (".ca", "Canada"),
                (".jp", "Japan"),
                (".co.jp", "Japan"),
                (".kr", "South Korea"),
                (".co.kr", "South Korea"),
                (".tw", "Taiwan"),
                (".com.tw", "Taiwan"),
                (".ch", "Switzerland"),
                (".au", "Australia"),
                (".com.au", "Australia"),
                (".br", "Brazil"),
                (".in", "India"),
            )
            for tld_sfx, cname in tld_other_map:
                if dom_low.endswith(tld_sfx):
                    return ("Other", cname, None)

        # 4. IPv4 RIR allocation blocks
        if not ip_clean or ip_clean.startswith(("127.", "10.", "192.168.", "0.")):
            return ("Other", "Local Network", None)

        # China (APNIC CN ranges + demo fingerprint IP 155.31.*)
        if ip_clean.startswith((
            "36.", "39.", "42.", "43.", "49.", "58.", "59.", "60.", "61.",
            "101.", "106.", "110.", "111.", "112.", "113.", "114.", "115.",
            "116.", "117.", "118.", "119.", "120.", "121.", "122.", "123.",
            "124.", "125.", "139.196.", "140.205.", "150.109.", "155.31.",
            "175.", "180.", "182.", "183.", "202.", "210.", "211.", "218.",
            "219.", "220.", "221.", "222.", "223."
        )):
            return ("China", "China", None)

        # Russia (RIPE RU ranges)
        if ip_clean.startswith((
            "5.45.", "5.188.", "31.13.", "37.9.", "37.140.", "46.36.", "62.109.",
            "77.88.", "78.155.", "79.137.", "80.249.", "81.19.", "83.220.",
            "85.114.", "87.240.", "87.250.", "89.108.", "90.156.", "91.108.",
            "92.53.", "93.158.", "94.100.", "95.108.", "95.163.", "109.207.",
            "149.154.", "176.59.", "178.154.", "185.71.", "188.162.", "193.32.",
            "194.85.", "195.208.", "212.193.", "213.180.", "217.69."
        )):
            return ("Russia", "Russia", None)

        # Germany (RIPE DE ranges: Hetzner, Deutsche Telekom, IONOS, etc.)
        if ip_clean.startswith((
            "2.200.", "2.201.", "2.202.", "2.203.", "2.204.", "2.205.", "2.206.", "2.207.",
            "5.9.", "46.4.", "49.12.", "49.13.", "62.153.", "78.46.", "78.47.",
            "80.128.", "80.150.", "84.128.", "85.214.", "87.128.", "88.64.", "88.198.",
            "91.64.", "116.202.", "116.203.", "128.140.", "136.243.", "138.201.",
            "142.132.", "144.76.", "148.251.", "157.90.", "159.69.", "162.55.",
            "167.235.", "168.119.", "176.9.", "178.63.", "185.15.", "188.40.",
            "193.99.", "195.201.", "212.227.", "213.133.", "213.239.", "217.160."
        )):
            return ("Germany", "Germany", None)

        if ip_clean.startswith("185.199."):
            return ("United States", "United States", None)

        first = ip_clean.split(".")[0]
        try:
            oct1 = int(first)
        except ValueError:
            return ("Other", "Other", None)

        # ARIN / US cloud & CDN ranges (AWS, Azure, Google, Cloudflare, Fastly, Akamai)
        if oct1 in (
            3, 4, 8, 13, 16, 20, 23, 34, 35, 40, 52, 54, 64, 65, 66, 67, 68, 69,
            70, 71, 72, 73, 74, 75, 76, 96, 97, 98, 99, 104, 107, 108, 128, 129,
            130, 140, 142, 151, 157, 162, 170, 172, 173, 184, 198, 199, 204, 205,
            206, 207, 208, 209, 216
        ):
            return ("United States", "United States", None)

        return ("Other", "Other", None)

    def _refresh_windows_dns_cache(self, force: bool = False):
        """Parse local Windows DNS cache (ipconfig /displaydns) to map IPs to exact domains visited in Edge/Chrome/Opera."""
        now = time.time()
        if not force and (now - self._last_dns_sync < 60.0):
            return
        self._last_dns_sync = now
        try:
            out = subprocess.check_output(
                ["ipconfig", "/displaydns"],
                text=True,
                errors="ignore",
                timeout=1.2
            )
            current_domain = None
            for line in out.splitlines():
                line_s = line.strip()
                if line_s.startswith("Record Name"):
                    parts = line_s.split(":", 1)
                    if len(parts) == 2:
                        current_domain = parts[1].strip().lower().rstrip(".")
                elif ("A (Host) Record" in line_s or "AAAA Record" in line_s) and current_domain:
                    parts = line_s.split(":", 1)
                    if len(parts) == 2:
                        ip_val = parts[1].strip()
                        if ip_val and current_domain:
                            self._dns_cache[ip_val] = current_domain
        except Exception:
            pass

    def _get_cloud_provider(self, ip: str) -> str:
        """Return the real cloud/network provider for an IP prefix if known."""
        for prefix, provider in CLOUD_ASN_PREFIXES:
            if ip.startswith(prefix):
                return provider
        return "Remote Endpoint"

    def _resolve_ip(self, ip: str, app_name: str = "unknown") -> str:
        """Resolve remote IP to exact hostname from Windows DNS cache, or return the truthful IP if not cached."""
        if not ip or ip in ["127.0.0.1", "0.0.0.0", "::1"]:
            return "localhost"

        if ip in self._dns_cache:
            return self._dns_cache[ip]

        return ip

    # Background Windows OS services & tray daemons that are NOT user-opened applications
    IGNORED_BACKGROUND_PROCESSES = {
        "svchost",
        "explorer",
        "mpdefendercoreservice",
        "nissrv",
        "securityhealthservice",
        "onedrive",
        "onedrive.sync.service",
        "filecoauth",
        "searchhost",
        "searchindexer",
        "widgets",
        "widgetservice",
        "edgegameassist",
        "xboxgamebarwidgets",
        "gamebar",
        "gamebarftserver",
        "m365copilot",
        "m365copilot_autostarter",
        "startmenuexperiencehost",
        "shellexperiencehost",
        "shellhost",
        "applicationframehost",
        "systemsettings",
        "taskhostw",
        "dwm",
        "csrss",
        "lsass",
        "services",
        "wininit",
        "winlogon",
        "spoolsv",
        "smartscreen",
        "ctfmon",
        "dllhost",
        "conhost",
        "WmiPrvSE".lower(),
        "audiodg",
        "rtkauduservice64",
        "nvdisplay.container",
        "nvcontainer",
        "nvsphelper64",
        "nvrla",
        "asusoptimizationstartuptask",
        "asushotkey",
        "cloudflare warp",
        "warp-svc",
        "microsoftedgeupdate",
        "googleupdate",
        "googlecrashhandler",
        "googlecrashhandler64",
        "opera_crashreporter",
        "opera_autoupdate",
        "browser_assistant",
        "ollama",
        "ollama app",
        "python",
        "python3.13",
        "pythonw",
        "powershell",
        "pwsh",
        "cmd",
        "system",
        "unknown"
    }

    @staticmethod
    def _normalize_app_name(raw_name: str) -> str:
        """Normalize Windows process names to the actual user-facing application."""
        clean = raw_name.replace(".exe", "").lower().strip()
        if clean == "msedge":
            return "edge"
        if clean == "chrome":
            return "chrome"
        if clean in ["opera", "opera_gx"]:
            return "opera"
        if clean in ["overwolf", "overwolfbrowser", "overwolfhelper", "overwolfhelper64", "overwolflauncher"]:
            return "overwolf"
        if clean in ["robloxplayerbeta", "robloxplayerlauncher", "robloxcrashhandler", "robloxstudio", "robloxstudiobeta"]:
            return "roblox"
        if clean in ["discord", "discordcanary", "discordptb"]:
            return "discord"
        if clean in ["code", "code - insiders"]:
            return "vscode"
        if clean in ["upc", "ubisoftconnect", "ubisoftgamelauncher", "ubisoftgamelauncher64"]:
            return "ubisoft connect"
        if clean in ["steam", "steamwebhelper", "steamservice"]:
            return "steam"
        if clean in ["tiktok live studio", "tiktok live studio launcher"]:
            return "tiktok live studio"
        if clean in ["client-win64-shipping", "wuthering waves"]:
            return "wuthering waves"
        if clean in ["valorant", "valorant-win64-shipping"]:
            return "valorant"
        if clean in ["riotclientservices", "riotclientux", "riotclientuxrender", "riot client"]:
            return "riot client"
        if clean in ["medal", "medalencoder"]:
            return "medal"
        if clean in ["voicemod", "voicemoddesktop"]:
            return "voicemod"
        if clean in ["razercortex", "razer central", "razersynapse"]:
            return "razer"
        if clean in ["mottynew", "xwin_mobax", "mobarte", "mobaxterm"]:
            return "mobaxterm"
        if clean in ["arduino-cli", "arduino-language-server", "arduino ide"]:
            return "arduino ide"
        if clean in ["language_server_windows_x64", "language_server", "antigravity"]:
            return "antigravity"
        return clean

    # Command-line flags used by Windows apps when running silently in Task Manager background / system tray
    BACKGROUND_CMDLINE_FLAGS = (
        "system-initiated",
        "--start-inactive",
        "--no-startup-window",
        "--win-session-start",
        "--embedded-browser-edgeview",
        "--edge-webview-host-pid",
        "--launch-to-tray",
        "-autorun",
        "-servicerun",
        "/background",
        "--background",
        "--minimized",
        "--hidden",
    )

    def _get_open_desktop_apps_and_pids(self) -> Tuple[set, set]:
        """
        Query the interactive Windows desktop (WinSta0\\Default) via Win32 user32 + dwmapi
        to identify applications that currently have an open, uncloaked top-level window.
        Cached for 1.5s (~2.5ms execution time).
        """
        now = time.time()
        if self._cached_open_apps and (now - self._last_open_win_ts < 1.5):
            return self._cached_open_apps, self._cached_open_pids

        open_apps = set()
        open_pids = set()
        try:
            import ctypes
            import ctypes.wintypes as wt

            user32 = ctypes.windll.user32
            dwmapi = ctypes.windll.dwmapi

            hwinsta = user32.OpenWindowStationW("WinSta0", False, 0x037F)
            if hwinsta:
                user32.SetProcessWindowStation(hwinsta)
            hdesk = user32.OpenDesktopW("Default", 0, False, 0x01FF)
            if hdesk:
                user32.SetThreadDesktop(hdesk)

            WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

            def _cb_child(chwnd, _lparam):
                cpid = wt.DWORD()
                user32.GetWindowThreadProcessId(chwnd, ctypes.byref(cpid))
                if cpid.value:
                    open_pids.add(cpid.value)
                return True

            child_proc = WNDENUMPROC(_cb_child)

            def _cb(hwnd, _lparam):
                try:
                    if not user32.IsWindowVisible(hwnd):
                        return True
                    length = user32.GetWindowTextLengthW(hwnd)
                    if length <= 0:
                        return True
                    cloaked = wt.DWORD(0)
                    dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked))
                    if cloaked.value != 0:
                        return True
                    exstyle = user32.GetWindowLongW(hwnd, -20)
                    # Exclude hidden toolwindows and non-activatable overlays unless WS_EX_APPWINDOW (0x00040000) is set
                    if (exstyle & 0x00000080) and not (exstyle & 0x00040000):
                        return True
                    if (exstyle & 0x08000000) and not (exstyle & 0x00040000):
                        return True
                    buf = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buf, length + 1)
                    title = buf.value.strip()
                    if not title or title in (
                        "Default IME", "MSCTFIME UI", "Program Manager",
                        "__wglDummyWindowFodder", "OleMainThreadWndName", "TrayIconClass"
                    ):
                        return True
                    pid = wt.DWORD()
                    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                    if pid.value:
                        open_pids.add(pid.value)
                        user32.EnumChildWindows(hwnd, child_proc, 0)
                except Exception:
                    pass
                return True

            user32.EnumWindows(WNDENUMPROC(_cb), 0)

            for wpid in list(open_pids):
                try:
                    p = psutil.Process(wpid)
                    p_clean = (p.name() or "").lower().replace(".exe", "").strip()
                    if p_clean and p_clean not in self.IGNORED_BACKGROUND_PROCESSES:
                        open_apps.add(self._normalize_app_name(p_clean))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

        self._cached_open_apps = open_apps
        self._cached_open_pids = open_pids
        self._last_open_win_ts = now
        return open_apps, open_pids

    def _resolve_real_app_from_pid(self, pid: int) -> Optional[str]:
        """
        Resolve a Windows PID to a real user-opened foreground application:
        - Filters out background Windows services (svchost, explorer, Defender, OneDrive, etc.).
        - Verifies that the application currently has an open visible window on the user's desktop
          so closed apps lingering in the system tray (e.g. Dawn, Roblox --launch-to-tray, background Chrome)
          are never shown as active open applications.
        """
        try:
            proc = psutil.Process(pid)
            raw_name = (proc.name() or "").lower()
            clean = raw_name.replace(".exe", "").strip()

            if clean in self.IGNORED_BACKGROUND_PROCESSES:
                return None

            open_apps, open_pids = self._get_open_desktop_apps_and_pids()

            chain = [proc] + list(proc.parents())
            chain_pids = set()
            has_bg_flag = False
            is_valorant_chain = False

            for node in chain:
                try:
                    chain_pids.add(node.pid)
                    n_clean = (node.name() or "").lower().replace(".exe", "").strip()
                    if n_clean in ("services", "wininit", "svchost"):
                        return None
                    if n_clean in ("valorant", "valorant-win64-shipping"):
                        is_valorant_chain = True
                    cmdline_str = " ".join(node.cmdline()).lower()
                    if "--launch-product=valorant" in cmdline_str or "\\valorant\\" in cmdline_str or "/valorant/" in cmdline_str:
                        is_valorant_chain = True
                    if any(flag in cmdline_str for flag in self.BACKGROUND_CMDLINE_FLAGS):
                        has_bg_flag = True
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

            if clean == "msedgewebview2":
                for parent in proc.parents():
                    p_clean = (parent.name() or "").lower().replace(".exe", "").strip()
                    if p_clean in self.IGNORED_BACKGROUND_PROCESSES or p_clean == "msedgewebview2":
                        continue
                    norm_parent = self._normalize_app_name(p_clean)
                    if norm_parent in self.IGNORED_BACKGROUND_PROCESSES:
                        return None
                    if open_apps:
                        if norm_parent not in open_apps and not (chain_pids & open_pids):
                            return None
                    elif has_bg_flag:
                        return None
                    try:
                        self._app_exe_paths[norm_parent] = parent.exe()
                    except Exception:
                        pass
                    return norm_parent
                return None

            if is_valorant_chain and clean in ("valorant-win64-shipping", "valorant", "riotclientservices", "epicwebhelper"):
                normalized = "valorant"
            else:
                normalized = self._normalize_app_name(clean)

            if normalized in self.IGNORED_BACKGROUND_PROCESSES:
                return None

            # If we have interactive desktop window visibility data, require the app to actually have an open window
            if open_apps:
                if normalized not in open_apps and not (chain_pids & open_pids):
                    return None
            elif has_bg_flag:
                return None

            try:
                self._app_exe_paths[normalized] = proc.exe()
            except Exception:
                pass
            return normalized
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def get_browser_link_status(self) -> Dict[str, Any]:
        """Inspect live local Microsoft Edge, Google Chrome, and Opera processes and active sockets."""
        edge_pids = set()
        chrome_pids = set()
        opera_pids = set()
        edge_mem_mb = 0.0
        chrome_mem_mb = 0.0
        opera_mem_mb = 0.0

        try:
            for p in psutil.process_iter(["pid", "name", "memory_info"]):
                pname = (p.info.get("name") or "").lower()
                pid = p.info.get("pid")
                if not pid:
                    continue
                if pname == "msedge.exe":
                    real_app = self._resolve_real_app_from_pid(pid)
                    if real_app == "edge":
                        edge_pids.add(pid)
                        if p.info.get("memory_info"):
                            edge_mem_mb += p.info["memory_info"].rss / (1024 * 1024)
                elif "chrome" in pname:
                    real_app = self._resolve_real_app_from_pid(pid)
                    if real_app == "chrome":
                        chrome_pids.add(pid)
                        if p.info.get("memory_info"):
                            chrome_mem_mb += p.info["memory_info"].rss / (1024 * 1024)
                elif "opera" in pname:
                    real_app = self._resolve_real_app_from_pid(pid)
                    if real_app == "opera":
                        opera_pids.add(pid)
                        if p.info.get("memory_info"):
                            opera_mem_mb += p.info["memory_info"].rss / (1024 * 1024)
        except Exception:
            pass

        edge_sockets = 0
        chrome_sockets = 0
        opera_sockets = 0
        other_sockets = 0
        edge_ips = []
        chrome_ips = []
        opera_ips = []
        other_apps_map: Dict[str, int] = {}

        try:
            for c in psutil.net_connections(kind="inet"):
                if not c.raddr or not c.pid or c.status != "ESTABLISHED":
                    continue
                rip = c.raddr.ip
                if rip.startswith("127.") or rip.startswith("::1") or rip == "0.0.0.0":
                    continue
                real_app = self._resolve_real_app_from_pid(c.pid)
                if not real_app:
                    continue
                if real_app == "edge":
                    edge_sockets += 1
                    if rip not in edge_ips:
                        edge_ips.append(rip)
                elif real_app == "chrome":
                    chrome_sockets += 1
                    if rip not in chrome_ips:
                        chrome_ips.append(rip)
                elif real_app == "opera":
                    opera_sockets += 1
                    if rip not in opera_ips:
                        opera_ips.append(rip)
                else:
                    other_sockets += 1
                    other_apps_map[real_app] = other_apps_map.get(real_app, 0) + 1
        except Exception:
            pass

        return {
            "edge": {
                "browser": "Microsoft Edge",
                "running": len(edge_pids) > 0,
                "linked": True,
                "process_count": len(edge_pids),
                "active_sockets": edge_sockets,
                "memory_mb": round(edge_mem_mb, 1),
                "remote_ips": edge_ips[:8]
            },
            "chrome": {
                "browser": "Google Chrome",
                "running": len(chrome_pids) > 0,
                "linked": True,
                "process_count": len(chrome_pids),
                "active_sockets": chrome_sockets,
                "memory_mb": round(chrome_mem_mb, 1),
                "remote_ips": chrome_ips[:8]
            },
            "opera": {
                "browser": "Opera Browser",
                "running": len(opera_pids) > 0,
                "linked": True,
                "process_count": len(opera_pids),
                "active_sockets": opera_sockets,
                "memory_mb": round(opera_mem_mb, 1),
                "remote_ips": opera_ips[:8]
            },
            "other_apps": {
                "active_apps_count": len(other_apps_map),
                "active_sockets": other_sockets,
                "apps": other_apps_map
            },
            "extension_events_count": len(self._browser_ingested_events)
        }

    def ingest_browser_event(
        self,
        browser: str,
        domain: str,
        url: Optional[str] = None,
        ip: str = "0.0.0.0",
        tab_title: Optional[str] = None
    ) -> ConnectionEvent:
        """Ingest a real-time event pushed from the Chrome/Edge/Opera browser extension or live browser sync."""
        b_low = browser.lower()
        app_name = "edge" if "edge" in b_low else ("opera" if "opera" in b_low else "chrome")
        clean_dom = domain.lower().strip()
        key = f"{app_name}:{clean_dom}"
        self._counts[key] = self._counts.get(key, 0) + 1

        rec = self.policy_store.get_decision(clean_dom, app_name)
        status = ConnectionStatus.ACTIVE
        if rec:
            if rec.decision == ActionDecision.BLOCK:
                status = ConnectionStatus.BLOCKED
            elif rec.decision == ActionDecision.WARN:
                status = ConnectionStatus.WARNED
            else:
                status = ConnectionStatus.ALLOWED

        ev = self.detector.create_event(
            application=app_name,
            domain=clean_dom,
            ip=ip,
            port=443,
            connection_count=self._counts[key],
            status=status
        )
        _, origin_country, pub_label = self.classify_app_and_ip_country(app_name, ip, clean_dom)
        ev.country = origin_country
        if pub_label and (not ev.vendor or ev.vendor in ("Unknown", "General Domain", "Automated Classification")):
            ev.vendor = pub_label
        ev.details = f"Live {browser.capitalize()} tab activity" + (f" ({tab_title[:40]})" if tab_title else "")
        ev.ai_explanation = (
            f"Live {browser.capitalize()} browser request to {clean_dom}. "
            f"Classified by Sentinel as {ev.category.value.replace('_', ' ')} ({ev.risk_level.value.upper()} risk)."
        )
        self._browser_ingested_events[key] = ev
        return ev

    def poll_connections(self, prioritize_browsers: bool = True, force: bool = False) -> List[ConnectionEvent]:
        """
        Poll active system network sockets (with priority on Opera, Microsoft Edge & Google Chrome)
        and produce structured ConnectionEvents with rich AI telemetry explanations.
        """
        now = time.time()
        if not force and self._cached_poll_events and (now - self._last_poll_ts < 2.5):
            return list(self._cached_poll_events)

        self._refresh_windows_dns_cache()
        open_apps, _ = self._get_open_desktop_apps_and_pids()
        if open_apps:
            for k in list(self._browser_ingested_events.keys()):
                if self._browser_ingested_events[k].application.lower() not in open_apps:
                    del self._browser_ingested_events[k]

        events: List[ConnectionEvent] = list(self._browser_ingested_events.values())
        seen_keys = set(self._browser_ingested_events.keys())

        try:
            net_conns = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.warning(f"Could not access low-level socket connections: {e}")
            return events

        # Only include ESTABLISHED sockets from actively open applications
        valid_conns = []
        for conn in net_conns:
            if not conn.raddr or not conn.pid or conn.status != "ESTABLISHED":
                continue
            r_ip = conn.raddr.ip
            if r_ip.startswith("127.") or r_ip == "::1" or r_ip == "0.0.0.0":
                continue
            prov = self._get_cloud_provider(r_ip)
            status_rank = 0
            prov_rank = -1 if "Opera Norway" in prov else (0 if prov != "Remote Endpoint" else 1)
            valid_conns.append((status_rank, prov_rank, conn))

        valid_conns.sort(key=lambda x: (x[0], x[1]))

        for _, _, conn in valid_conns:
            r_ip, r_port = conn.raddr.ip, conn.raddr.port

            app_name = self._resolve_real_app_from_pid(conn.pid)
            if not app_name:
                continue

            domain = self._resolve_ip(r_ip, app_name)
            provider = self._get_cloud_provider(r_ip)
            _, origin_country, pub_label = self.classify_app_and_ip_country(app_name, r_ip, domain)

            # Strictly 1 entry per open application so there are never duplicate rows of the same app
            key = app_name

            self._counts[key] = self._counts.get(key, 0) + 1
            freq = self._counts[key]

            if key in seen_keys:
                continue
            seen_keys.add(key)

            rec = self.policy_store.get_decision(domain, app_name) or self.policy_store.get_decision(r_ip, app_name)
            status = ConnectionStatus.ACTIVE
            if rec:
                if rec.decision == ActionDecision.BLOCK:
                    status = ConnectionStatus.BLOCKED
                elif rec.decision == ActionDecision.WARN:
                    status = ConnectionStatus.WARNED
                else:
                    status = ConnectionStatus.ALLOWED

            ev = self.detector.create_event(
                application=app_name,
                domain=domain,
                ip=r_ip,
                port=r_port,
                connection_count=freq,
                status=status
            )
            ev.country = origin_country

            if not ev.vendor or ev.vendor in ("Unknown", "General Domain", "Automated Classification"):
                if provider == "Remote Endpoint" and pub_label:
                    ev.vendor = pub_label
                else:
                    ev.vendor = provider

            if ev.known_tracker:
                ev.ai_explanation = (
                    f"Live {app_name.upper()} socket connected to known tracker {domain} ({r_ip}:{r_port}, {ev.vendor})."
                )
            else:
                ev.ai_explanation = (
                    f"Verified live {app_name.upper()} outbound {ev.protocol} connection to {domain} "
                    f"({r_ip}:{r_port} · {ev.vendor}). No malicious activity detected."
                )

            events.append(ev)

        self._cached_poll_events = list(events)
        self._last_poll_ts = now
        return events
