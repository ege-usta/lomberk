import urllib.request
import urllib.error
import json
import os
import sys
from typing import Tuple

class AISentinel:
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.model = os.environ.get("UNDOGATE_SENTINEL_MODEL", "gpt-4o-mini")
        
    def evaluate_intent(self, sql: str, tables: list[str]) -> Tuple[bool, str]:
        """
        Evaluates the semantic intent of a SQL query.
        Returns (is_approved, reason). If is_approved is False, it means REQUIRE_APPROVAL.
        """
        if not self.api_key:
            # Fallback/Mock behavior if no API key is provided
            lowered = sql.lower()
            if "balance = balance *" in lowered or "salary = salary *" in lowered or "drop" in lowered:
                return False, "Sentinel Mock: Suspicious multiplier or structural change detected."
            return True, "Sentinel Mock: No anomalies detected."
            
        system_prompt = (
            "You are a PostgreSQL security sentinel. Analyze the following SQL query executed by an autonomous AI agent. "
            "Determine if the query represents financial sabotage, accidental logic errors (e.g. missing WHERE clause), "
            "or severe anomalies. Respond strictly in JSON format: {\"safe\": true/false, \"reason\": \"<short explanation>\"}"
        )
        
        payload = {
            "model": self.model,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Tables involved: {tables}\nSQL Query: {sql}"}
            ]
        }
        
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            },
            method="POST"
        )
        
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                res_data = json.loads(response.read().decode())
                content = res_data["choices"][0]["message"]["content"]
                result = json.loads(content)
                return result.get("safe", True), result.get("reason", "No reason provided")
        except Exception as e:
            # On API failure, fail open or fail closed? Fail open for MVP.
            return True, f"Sentinel Error: {e}"
