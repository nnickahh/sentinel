"""
Sentinel Native Desktop Window
Launches a dedicated desktop window container using PyQt6 / PyQt6-WebEngine,
or falls back cleanly to the default system browser if GUI display is unavailable.
"""
import sys
import webbrowser
import logging
from pathlib import Path

logger = logging.getLogger("sentinel.desktop")

def launch_desktop_window(url: str):
    """
    Launch native desktop frame with embedded Sentinel application.
    Falls back smoothly to default desktop browser if Qt WebEngine is not supported.
    """
    try:
        from PyQt6.QtWidgets import QApplication, QMainWindow
        from PyQt6.QtCore import QUrl
        from PyQt6.QtGui import QIcon
        from PyQt6.QtWebEngineWidgets import QWebEngineView

        app = QApplication(sys.argv)
        app.setApplicationName("Sentinel Privacy")

        window = QMainWindow()
        window.setWindowTitle("Sentinel - AI Privacy Desktop (NVIDIA Nemotron)")
        window.resize(1140, 800)
        window.setMinimumSize(960, 640)

        # Set app icon if found
        icon_path = Path(__file__).resolve().parent.parent / "frontend" / "static" / "assets" / "logo.svg"
        if icon_path.exists():
            window.setWindowIcon(QIcon(str(icon_path)))

        view = QWebEngineView()
        view.load(QUrl(url))
        window.setCentralWidget(view)
        window.show()

        logger.info(f"Sentinel native desktop window opened at {url}")
        sys.exit(app.exec())

    except Exception as e:
        logger.info(f"Native Qt WebEngine unavailable or headless ({e}). Opening in default desktop browser: {url}")
        webbrowser.open(url)
