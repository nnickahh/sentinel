"""
Sentinel - AI Privacy Desktop Application
Powered by NVIDIA Nemotron via Nebius Token Factory
NVIDIA x Nebius Global AI Hackathon (Best Apps & Agents Track)
"""
import sys
import time
import threading
import argparse
import webbrowser
import uvicorn
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.config import settings
from backend.app import app, state

def print_banner(host: str, port: int, mode_str: str, nebius_status: str):
    banner = rf"""
========================================================================
   ____  ____  _   _ _____ ___ _   _ _____ _     
  / ___|| ____| \ | |_   _|_ _| \ | | ____| |    
  \___ \|  _| |  \| | | |  | ||  \| |  _| | |    
   ___) | |___| |\  | | |  | || |\  | |___| |___ 
  |____/|_____|_| \_| |_| |___|_| \_|_____|_____|
  AI Privacy Desktop Guard | NVIDIA Nemotron x Nebius Token Factory
========================================================================
  * Local Dashboard:       http://{host}:{port}
  * Active Mode:           {mode_str}
  * Nebius Token Factory:  {nebius_status}
  * Nemotron Model:        {settings.nebius_model}
  * Privacy Engine:        Active (Local Heuristics + SQLite Policy DB)
========================================================================
"""
    print(banner)

def _run_mirror_listener(host: str, port: int):
    """Run an auxiliary listener thread so both IPv4/IPv6 localhost and common ports resolve cleanly."""
    try:
        uvicorn.run(app, host=host, port=port, log_level="error")
    except Exception:
        pass

def start_server(host: str, port: int):
    """Run FastAPI uvicorn server on IPv4 (127.0.0.1 / 0.0.0.0) + IPv6 (::1) and mirror ports."""
    threading.Thread(target=_run_mirror_listener, args=("::1", port), daemon=True).start()
    for extra_port in [80, 8000, 8080, 3000, 5000]:
        if extra_port != port:
            threading.Thread(target=_run_mirror_listener, args=("0.0.0.0", extra_port), daemon=True).start()
            threading.Thread(target=_run_mirror_listener, args=("::1", extra_port), daemon=True).start()

    bind_host = "0.0.0.0" if host in ["127.0.0.1", "localhost"] else host
    uvicorn.run(app, host=bind_host, port=port, log_level="warning")

def main():
    parser = argparse.ArgumentParser(description="Sentinel - AI Privacy Desktop")
    parser.add_argument("--host", default=settings.sentinel_host, help="Bind host")
    parser.add_argument("--port", type=int, default=settings.sentinel_port, help="Bind port")
    parser.add_argument("--web-only", action="store_true", help="Run web server only, do not launch window")
    parser.add_argument("--desktop", action="store_true", default=False, help="Launch native PyQt6 desktop window")
    parser.add_argument("--live", action="store_true", help="Start with live host network monitor")
    parser.add_argument("--demo", action="store_true", help="Start in demo mode (recommended for judges)")
    
    args = parser.parse_args()

    # Configure runtime mode
    if args.live:
        state["demo_mode"] = False
    elif args.demo:
        state["demo_mode"] = True

    mode_str = "DEMO MODE (Simulated Traffic)" if state["demo_mode"] else "LIVE SYSTEM NETWORK MONITOR"
    nebius_status = "Connected & Active" if settings.is_nebius_configured() else "Ready / Local Fallback Mode"

    print_banner("127.0.0.1", args.port, mode_str, nebius_status)
    app_url = f"http://127.0.0.1:{args.port}"

    if args.desktop:
        # Start server in daemon thread and run PyQt6 desktop window in main thread
        server_thread = threading.Thread(target=start_server, args=(args.host, args.port), daemon=True)
        server_thread.start()
        time.sleep(1.0)
        from desktop.window import launch_desktop_window
        launch_desktop_window(app_url)
    elif not args.web_only:
        # Automatically open browser using numeric IPv4 127.0.0.1 (bypasses DNS issues with 'localhost')
        threading.Timer(1.2, lambda: webbrowser.open(app_url)).start()
        start_server(args.host, args.port)
    else:
        start_server(args.host, args.port)

if __name__ == "__main__":
    main()

