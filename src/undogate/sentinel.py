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
        violations = []
        
        ALLOWED_STMTS = {'RawStmt', 'SelectStmt', 'InsertStmt', 'UpdateStmt', 'DeleteStmt'}

        def traverse(node):
            if isinstance(node, dict):
                node_type = node.get('@')
                
                if node_type and node_type.endswith('Stmt'):
                    if node_type not in ALLOWED_STMTS:
                        violations.append(f"Command {node_type} is structurally banned")
                
                if node_type == 'SelectStmt':
                    if node.get('intoClause') is not None:
                        violations.append("SELECT INTO is structurally banned")
                elif node_type == 'UpdateStmt':
                    if node.get('whereClause') is None:
                        violations.append("UPDATE statement missing WHERE clause")
                elif node_type == 'DeleteStmt':
                    if node.get('whereClause') is None:
                        violations.append("DELETE statement missing WHERE clause")
                
                if node_type in ['InsertStmt', 'UpdateStmt', 'DeleteStmt']:
                    relation = node.get('relation')
                    if relation and isinstance(relation, dict) and relation.get('schemaname') is None:
                        violations.append(f"Unqualified relation write in {node_type} (missing schema)")
                        
                if node_type == 'FuncCall':
                    violations.append("Function calls are structurally banned in Round 1A")
                            
                for k, v in node.items():
                    traverse(v)
            elif isinstance(node, (list, tuple)):
                for item in node:
                    traverse(item)
            elif hasattr(node, '__call__'):
                try:
                    traverse(node(skip_none=True))
                except Exception:
                    # Do not silently pass errors during AST traversal
                    violations.append("AST traversal encountered an unsupported structure")

        try:
            ast = pglast.parse_sql(sql)
            if len(ast) > 1:
                return False, "AST Firewall: Multiple stacked SQL statements detected."
                
            for raw_stmt in ast:
                traverse(raw_stmt(skip_none=True))
            
            if violations:
                return False, "AST Firewall: " + " | ".join(violations)
                
        except pglast.parser.ParseError as e:
            return False, f"AST Firewall: Malformed SQL syntax. {str(e)}"
        except Exception as e:
            return False, f"AST Firewall: Unexpected error during parsing: {str(e)}"
            
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
                safe_val = result.get("safe")
                if not isinstance(safe_val, bool):
                    return False, "Sentinel Error: Invalid boolean format in LLM response"
                return safe_val, result.get("reason", "No reason provided")
        except Exception as e:
            # On API failure, fail closed for security.
            return False, f"Sentinel Error: Network/API failure ({e})"
