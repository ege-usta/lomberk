
import pglast
from pglast import enums
from pglast.visitors import Visitor, referenced_relations

from undogate.models import ClassifiedStatement, StatementClass


class StatementTypeVisitor(Visitor):
    def __init__(self):
        super().__init__()
        self.found_types = set()

    def visit(self, ancestors, node):
        self.found_types.add(type(node).__name__)

def get_sql_slice(sql: str, stmt_dict) -> str:
    loc = stmt_dict.stmt_location
    length = stmt_dict.stmt_len
    if length == 0:
        return sql[loc:].strip()
    return sql[loc:loc+length].strip()

def classify_sql(sql: str) -> list[ClassifiedStatement]:
    try:
        ast = pglast.parse_sql(sql)
    except pglast.parser.ParseError:
        return [ClassifiedStatement(sql=sql.strip(), stmt_class=StatementClass.UNKNOWN, tables=[], is_multistatement=False)]

    if not ast:
        return []

    results = []
    is_multi = len(ast) > 1

    for stmt_dict in ast:
        stmt = stmt_dict.stmt
        raw_sql = get_sql_slice(sql, stmt_dict)
        tables = list(referenced_relations(stmt_dict))
        
        visitor = StatementTypeVisitor()
        visitor(stmt)
        types = visitor.found_types
        
        stmt_class = StatementClass.UNKNOWN
        
        # Priority classification
        if any(t.startswith("AlterRole") or t.startswith("CreateRole") or t.startswith("DropRole") 
               or t in ("GrantStmt", "RevokeStmt", "VariableSetStmt", "AlterSystemStmt") for t in types):
            stmt_class = StatementClass.BLOCKED
            
        elif any(t in ("DropdbStmt", "DropdbStmt") for t in types):
            stmt_class = StatementClass.DDL_DANGEROUS
            
        elif "DropStmt" in types:
            remove_type = getattr(stmt, "removeType", None)
            behavior = getattr(stmt, "behavior", None)
            if remove_type == enums.ObjectType.OBJECT_TABLE:
                if behavior == enums.DropBehavior.DROP_CASCADE:
                    stmt_class = StatementClass.DDL_DANGEROUS
                else:
                    stmt_class = StatementClass.DDL_REVERSIBLE
            elif remove_type in (enums.ObjectType.OBJECT_SCHEMA, enums.ObjectType.OBJECT_DATABASE):
                stmt_class = StatementClass.DDL_DANGEROUS
            else:
                stmt_class = StatementClass.DDL_REVERSIBLE
                
        elif any(t in ("TruncateStmt", "AlterTableStmt", "CreateStmt", "IndexStmt", "ViewStmt", "CreateTableAsStmt", "RenameStmt", "CreateEnumStmt", "CompositeTypeStmt", "DefineStmt") for t in types):
            stmt_class = StatementClass.DDL_REVERSIBLE
            
        elif any(t in ("PrepareStmt", "ExecuteStmt", "DoStmt", "CreateFunctionStmt") for t in types):
            stmt_class = StatementClass.UNKNOWN
            
        elif any(t in ("InsertStmt", "UpdateStmt", "DeleteStmt", "MergeStmt") for t in types):
            stmt_class = StatementClass.WRITE_DML
            
        elif any(t in ("SelectStmt", "ExplainStmt", "VariableShowStmt") for t in types):
            stmt_class = StatementClass.READ

        # Check for blocked schemas
        for table in tables:
            if table.startswith("undogate.") or table.startswith("undogate_trash.") or table == "undogate" or table == "undogate_trash":
                stmt_class = StatementClass.BLOCKED
                
        results.append(ClassifiedStatement(
            sql=raw_sql,
            stmt_class=stmt_class,
            tables=tables,
            is_multistatement=is_multi
        ))
        
    return results

def extract_tables_from_ast(ast):
    tables = []
    for stmt_dict in ast:
        refs = list(referenced_relations(stmt_dict))
        for ref in refs:
            # ref is a string like 'public.users' or '"public"."users"'
            # pglast's referenced_relations returns the string. We need to parse it safely.
            # actually referenced_relations already formats it.
            # But wait, pglast provides `stmt.relation` for updates/deletes!
            # Let's write a safe string parser or use psycopg.sql ?
            # Actually, instead of split('.'), let's just find the last dot that isn't inside quotes.
            # For simplicity, if we know we only support unquoted or properly quoted, we can just split by '.'
            # But the requirement is: "Noktalı/quoted/mixed-case identifier hedeflerini AST üzerinden doğru çöz."
            pass
            
def extract_tables_from_ast(ast):
    tables = []
    for stmt_dict in ast:
        refs = list(referenced_relations(stmt_dict))
        for ref in refs:
            # A safe way to split a SQL identifier by dot, respecting double quotes
            parts = []
            current = ""
            in_quotes = False
            for char in ref:
                if char == '"':
                    in_quotes = not in_quotes
                    current += char
                elif char == '.' and not in_quotes:
                    parts.append(current)
                    current = ""
                else:
                    current += char
            parts.append(current)
            
            if len(parts) == 1:
                tables.append(('public', parts[0].strip('"')))
            elif len(parts) == 2:
                tables.append((parts[0].strip('"'), parts[1].strip('"')))
    return tables
