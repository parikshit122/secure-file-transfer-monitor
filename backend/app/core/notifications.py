import threading
import json
import urllib.request

try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

# Set your webhook URL (Discord, Slack, or SIEM receiver endpoint)
WEBHOOK_URL = ""  # e.g., "https://discord.com/api/webhooks/..."

def send_alert_notification(title: str, message: str, severity: str = "HIGH"):
    """Triggers both native Windows desktop toast and remote Webhook alerts asynchronously."""
    
    # 1. Desktop Notification
    if PLYER_AVAILABLE:
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

    # 2. Remote Webhook Alert (SIEM / Discord / Slack)
    if WEBHOOK_URL:
        def _webhook():
            try:
                payload = json.dumps({
                    "username": "SFTMS Active Defense",
                    "content": f"🚨 **[{severity}] {title}**\n```{message}```"
                }).encode('utf-8')
                req = urllib.request.Request(WEBHOOK_URL, data=payload, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req, timeout=3)
            except Exception:
                pass
        threading.Thread(target=_webhook, daemon=True).start()