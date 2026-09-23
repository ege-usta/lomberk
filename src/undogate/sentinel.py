import json
import os
import urllib.error
import urllib.request


class AISentinel:
    def __init__(self):
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.model = os.environ.get("UNDOGATE_SENTINEL_MODEL", "gpt-4o-mini")
        

    def _ast_firewall(self, sql: str) -> tuple[bool, str]:
        import pglast
        try:
            ast = pglast.parse_sql(sql)
            for stmt_dict in ast:
                stmt = stmt_dict.stmt
                stmt_type = type(stmt).__name__
                
                # Rule 1: No un-scoped DML (Missing WHERE clause)
                if stmt_type == "UpdateStmt" and getattr(stmt, 'whereClause', None) is None:
                    return False, "AST Firewall: UPDATE statement missing WHERE clause (Full table scan blocked)."
                if stmt_type == "DeleteStmt" and getattr(stmt, 'whereClause', None) is None:
                    return False, "AST Firewall: DELETE statement missing WHERE clause (Full table scan blocked)."
                    
                # Rule 2: Multi-statement execution blocking (SQL Injection prevention)
                if len(ast) > 1:
                    return False, "AST Firewall: Multiple stacked SQL statements detected. Possible injection."
                    
                # Rule 3: Ban highly destructive operations entirely unless explicitly whitelisted
                if stmt_type in ["TruncateStmt", "DropdbStmt", "DropRoleStmt"]:
                    return False, f"AST Firewall: Command {stmt_type} is structurally banned for AI agents."
                    
        except pglast.parser.ParseError as e:
            return False, f"AST Firewall: Malformed SQL syntax. {e!s}"
            
        return True, ""

    def evaluate_intent(self, sql: str, tables: list[str]) -> tuple[bool, str]:
        # Step 1: Deterministic AST Firewall
        ast_safe, ast_reason = self._ast_firewall(sql)
        if not ast_safe:
            return ast_safe, ast_reason

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
