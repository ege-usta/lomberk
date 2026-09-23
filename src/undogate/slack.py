import urllib.request
import urllib.error
import json
import os
from pydantic import BaseModel

class SlackNotifier:
    def __init__(self):
        # Read from environment
        self.webhook_url = os.environ.get("UNDOGATE_SLACK_WEBHOOK")

    def send_approval_request(self, token: str, sql: str, agent: str, reason: str):
        if not self.webhook_url:
            return # Silent skip if not configured
            
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "⚠️ Undogate: Approval Required",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Agent:* {agent}\n*Reason:* {reason}\n*Token:* `{token}`"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"```sql\n{sql}\n```"
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Approve",
                                "emoji": True
                            },
                            "style": "primary",
                            "value": f"approve_{token}"
                        },
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Reject",
                                "emoji": True
                            },
                            "style": "danger",
                            "value": f"reject_{token}"
                        }
                    ]
                }
            ]
        }
        
        req = urllib.request.Request(
            self.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"Failed to send Slack notification: {e}")
