import threading

try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

def send_alert_notification(title: str, message: str):
    """Triggers a native Windows 11 desktop notification asynchronously."""
    if not PLYER_AVAILABLE:
        return

    def _notify():
        try:
            notification.notify(
                title=title,
                message=message[:256],
                app_name="SFTMS Active Defense",
                timeout=6
            )
        except Exception:
            pass
            
    threading.Thread(target=_notify, daemon=True).start()