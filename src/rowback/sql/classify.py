
import pglast
from pglast import enums
from pglast.visitors import Visitor, referenced_relations

from rowback.models import ClassifiedStatement, StatementClass


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
            if table.startswith("rowback.") or table.startswith("rowback_trash.") or table == "rowback" or table == "rowback_trash":
                stmt_class = StatementClass.BLOCKED
                
        results.append(ClassifiedStatement(
            sql=raw_sql,
            stmt_class=stmt_class,
            tables=tables,
            is_multistatement=is_multi
        ))
        
    return results

def extract_tables_from_ast(ast):
    class CteNameVisitor(Visitor):
        def __init__(self):
            super().__init__()
            self.names = set()
        def visit_CommonTableExpr(self, ancestors, node):
            self.names.add(node.ctename)

    cte_visitor = CteNameVisitor()
    for stmt_dict in ast:
        cte_visitor(stmt_dict)

    class RangeVarVisitor(Visitor):
        def __init__(self):
            super().__init__()
            self.tables = []
        def visit_RangeVar(self, ancestors, node):
            if not getattr(node, 'schemaname', None) and node.relname in cte_visitor.names:
                return  # reference to a WITH query, not a table
            schema = node.schemaname if getattr(node, 'schemaname', None) else 'public'
            table = node.relname
            if table:
                self.tables.append((schema, table))

    visitor = RangeVarVisitor()
    for stmt_dict in ast:
        visitor(stmt_dict)
    return list(dict.fromkeys(visitor.tables))


SENSITIVE_KEYWORDS = ("password", "token", "secret", "ssn", "hash", "credit_card")


def check_sensitive_columns(ast) -> list[str]:
    """Reasons the statement could expose a secret-looking column, or [] if it can't.

    Results are masked by output column name, so a secret must never reach the output
    under another name or folded into one value. Refused: naming such a column anywhere
    (column refs, field selection, USING, alias lists); whole-row references (`u`,
    `u::text`, `jsonb_build_object('r', u)`); `*` anywhere but the top-level select or
    RETURNING list (a subquery, CTE, UNION branch or INSERT ... SELECT could rename it);
    and renaming a table's columns with an alias list. String literals are data.
    """
    found: list[str] = []
    names: set[str] = set()

    def collect(node) -> None:  # every relation, alias and CTE name a whole-row ref could use
        if isinstance(node, dict):
            kind = node.get("@")
            if kind == "RangeVar":
                names.add(node.get("relname", ""))
            if kind == "CommonTableExpr":
                names.add(node.get("ctename", ""))
            alias = node.get("alias")
            if isinstance(alias, dict):
                names.add(alias.get("aliasname", ""))
            for v in node.values():
                collect(v)
        elif isinstance(node, (list, tuple)):
            for v in node:
                collect(v)

    def secret(name) -> bool:
        return isinstance(name, str) and any(k in name.lower() for k in SENSITIVE_KEYWORDS)

    def walk(node, star_ok: bool = False) -> None:
        if isinstance(node, (list, tuple)):
            for v in node:
                walk(v, star_ok)
            return
        if not isinstance(node, dict):
            return
        kind = node.get("@")
        if kind == "A_Const":
            return
        if kind == "String" and secret(node.get("sval")):
            found.append(node["sval"])
        if kind == "A_Star" and not star_ok:
            found.append("* outside the top-level select list")
        if kind == "ColumnRef":
            fields = node.get("fields", [])
            if len(fields) == 1 and fields[0].get("@") == "String" and fields[0].get("sval") in names:
                found.append(f"whole-row reference {fields[0]['sval']}")
            walk(fields, star_ok)
            return
        if kind == "A_Indirection":
            walk(node.get("arg"))
            walk(node.get("indirection"), star_ok)
            return
        if kind in ("RangeVar", "JoinExpr") and (node.get("alias") or {}).get("colnames"):
            found.append("renaming a table's columns with an alias list")
        if kind == "SubLink":
            exists = (node.get("subLinkType") or {}).get("name") == "EXISTS_SUBLINK"
            walk(node.get("testexpr"))
            walk_stmt(node.get("subselect"), top=exists)  # EXISTS returns a boolean, never the row
            return
        if kind in ("SelectStmt", "InsertStmt", "UpdateStmt", "DeleteStmt"):
            walk_stmt(node, top=False)
            return
        for v in node.values():
            walk(v)

    def walk_stmt(stmt, top: bool) -> None:
        if not isinstance(stmt, dict):
            return
        plain_select = (stmt.get("op") or {}).get("name", "SETOP_NONE") == "SETOP_NONE"
        for key, value in stmt.items():
            if key == "returningClause" and isinstance(value, dict):
                key, value = "returningList", value.get("exprs", [])
            star_here = top and (key == "returningList" or (key == "targetList" and plain_select and stmt.get("@") == "SelectStmt"))
            if star_here:
                for target in value:  # only a bare `*` / `t.*` / `(t).*` in the output list
                    if isinstance(target, dict):
                        walk(target.get("val"), star_ok=True)
            elif key in ("larg", "rarg", "selectStmt"):
                walk_stmt(value, top=False)
            else:
                walk(value)

    for raw in ast:
        tree = raw(skip_none=True)
        collect(tree)
        walk_stmt(tree.get("stmt"), top=True)
    return found
