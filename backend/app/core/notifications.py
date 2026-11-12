import threading
from plyer import notification

def send_alert_notification(title: str, message: str):
    """Triggers a native Windows 11 desktop notification asynchronously."""
    def _notify():
        try:
            notification.notify(
                title=title,
                message=message[:256],  # Truncate long messages
                app_name="SFTMS Active Defense",
                timeout=6
            )
        except Exception:
            pass
            
    threading.Thread(target=_notify, daemon=True).start()