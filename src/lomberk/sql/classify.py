
import re

import pglast
from pglast import enums
from pglast.visitors import Visitor, referenced_relations

from lomberk.models import ClassifiedStatement, StatementClass


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
        if any(t.startswith(("AlterRole", "CreateRole", "DropRole"))
               or t in ("GrantStmt", "RevokeStmt", "VariableSetStmt", "AlterSystemStmt") for t in types):
            stmt_class = StatementClass.BLOCKED

        elif any(t in ("DropdbStmt", "DropTableSpaceStmt") for t in types):
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
            if table.startswith(("lomberk.", "lomberk_trash.")) or table in ("lomberk", "lomberk_trash"):
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


# Substring match on column names, case-insensitive. A false hit only refuses or masks.
SENSITIVE_KEYWORDS = ("password", "passwd", "pwd", "token", "secret", "ssn", "hash", "credit_card",
                      "api_key", "apikey", "private_key", "credential")


# JSON operators whose right side names a key or path: settings->>'api_key', settings ? 'token'.
# `@?` and `@@` take a jsonpath. Text pattern matching (LIKE, ~) is not here: a word in a value is data.
JSON_KEY_OPERATORS = {"->", "->>", "#>", "#>>", "?", "?|", "?&", "@>", "<@", "#-", "@?", "@@"}


def is_secret(name, extra=()) -> bool:
    """A secret-looking column name: a built-in keyword inside it, or exactly a configured name."""
    if not isinstance(name, str):
        return False
    low = name.lower()
    return any(k in low for k in SENSITIVE_KEYWORDS) or low in {e.lower() for e in extra}


# JSON (\u0061) and jsonpath (\u0061, \u{61}, \x61) decode escapes inside a key, so
# '$."\u0061pi_key"' names api_key. Decode them before looking for a secret name.
_ESCAPE = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")


def _unescape(text: str) -> str:
    def char(m):
        code = int(next(g for g in m.groups() if g), 16)
        return chr(code) if code < 0x110000 else ""
    return _ESCAPE.sub(char, text)


def _secret_literal(node, extra) -> bool:
    """A string constant (possibly cast) naming a secret key, e.g. 'api_key' or '{auth,token}'."""
    while isinstance(node, dict) and node.get("@") == "TypeCast":
        node = node.get("arg")
    if not (isinstance(node, dict) and node.get("@") == "A_Const"):
        return False
    val = node.get("val") or {}
    text = _unescape(val.get("sval", ""))
    return val.get("@") == "String" and any(is_secret(t, extra) for t in re.split(r"[^\w]+", text) if t)


# Operators that pick a value out of JSON by key or path. Their key must be written out (a
# literal, or an ARRAY of literals) so it can be checked: a key computed at run time, from
# jsonb_object_keys(), a table column or 'api_' || 'key', can be any key (security-audit run-3).
JSON_PICK_OPERATORS = {"->", "->>", "#>", "#>>", "?", "?|", "?&", "#-"}
# JSON functions whose arguments after the first are a key path, by the same rule.
JSON_PATH_FUNCS = {"jsonb_extract_path", "jsonb_extract_path_text", "json_extract_path", "json_extract_path_text",
                   "jsonb_set", "jsonb_set_lax", "jsonb_insert"}


def _constant(node) -> bool:
    """A literal, a cast or negated literal, or an ARRAY[...] of them: a key the checks can read."""
    while isinstance(node, dict) and node.get("@") == "TypeCast":
        node = node.get("arg")
    if not isinstance(node, dict):
        return False
    kind = node.get("@")
    if kind == "A_Const":
        return True
    if kind == "A_ArrayExpr":
        return all(_constant(e) for e in node.get("elements") or ())
    if kind == "A_Expr" and node.get("lexpr") is None and [n.get("sval") for n in node.get("name", ())] == ["-"]:
        return _constant(node.get("rexpr"))
    return False


def _secret_constant(node, extra) -> bool:
    """A literal key naming a secret, including inside ARRAY['auth', 'api_key']."""
    while isinstance(node, dict) and node.get("@") == "TypeCast":
        node = node.get("arg")
    if isinstance(node, dict) and node.get("@") == "A_ArrayExpr":
        return any(_secret_constant(e, extra) for e in node.get("elements") or ())
    return _secret_literal(node, extra)


def check_sensitive_columns(ast, extra=()) -> list[str]:
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
            # `FROM generate_series(...) d`, `unnest(tags) tag`: every function the hard gate
            # allows in FROM returns a scalar, so its alias names one value, not a table's row.
            if isinstance(alias, dict) and kind != "RangeFunction":
                names.add(alias.get("aliasname", ""))
            for v in node.values():
                collect(v)
        elif isinstance(node, (list, tuple)):
            for v in node:
                collect(v)

    def secret(name) -> bool:
        return is_secret(name, extra)

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
        op = [n.get("sval") for n in node.get("name", ()) if isinstance(n, dict)] if kind == "A_Expr" else []
        json_op = any(o in JSON_KEY_OPERATORS for o in op)
        if json_op and (_secret_constant(node.get("lexpr"), extra) or _secret_constant(node.get("rexpr"), extra)):
            found.append("a secret-looking JSON key")
        if any(o in JSON_PICK_OPERATORS for o in op) and not _constant(node.get("rexpr")):
            found.append("a JSON key chosen at run time (write the key as a literal)")
        if kind == "FuncCall":
            args = node.get("args") or ()
            if any(_secret_constant(a, extra) for a in args):
                # strpos(settings::text, 'api_key'), jsonb_extract_path_text(settings, 'token'):
                # a function argument naming a secret key reaches it as surely as `->>` does.
                found.append("a secret-looking key named in a function argument")
            name = (node.get("funcname") or [{}])[-1].get("sval")
            if name in JSON_PATH_FUNCS and (node.get("func_variadic") or not all(
                    _constant(a) for a in (args[1:2] if name.startswith("jsonb_set") or name == "jsonb_insert" else args[1:]))):
                found.append("a JSON key chosen at run time (write the key path as literals)")
        if kind == "A_Indirection":
            for ind in node.get("indirection", ()):
                if isinstance(ind, dict) and ind.get("@") == "A_Indices":
                    if _secret_literal(ind.get("uidx"), extra) or _secret_literal(ind.get("lidx"), extra):
                        found.append("a secret-looking JSON key")
                    if any(i is not None and not _constant(i) for i in (ind.get("uidx"), ind.get("lidx"))):
                        found.append("a JSON key or index chosen at run time (write it as a literal)")
            walk(node.get("arg"))
            walk(node.get("indirection"), star_ok)
            return
        if kind in ("RangeVar", "JoinExpr") and (node.get("alias") or {}).get("colnames"):
            found.append("renaming a table's columns with an alias list")
        if kind == "JoinExpr" and node.get("isNatural"):
            found.append("NATURAL JOIN, which compares columns the query never names")
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

    def has_star(node) -> bool:
        if isinstance(node, dict):
            return node.get("@") == "A_Star" or any(has_star(v) for v in node.values())
        return isinstance(node, (list, tuple)) and any(has_star(v) for v in node)

    def walk_stmt(stmt, top: bool) -> None:
        if not isinstance(stmt, dict):
            return
        if stmt.get("@") == "SelectStmt" and has_star(stmt.get("targetList")):
            # `SELECT * ... ORDER BY 4` sorts by a masked column without naming it: an oracle.
            for key in ("sortClause", "groupClause", "distinctClause"):
                for item in stmt.get(key) or ():
                    node = item.get("node", item) if isinstance(item, dict) else None
                    if isinstance(node, dict) and node.get("@") == "A_Const" and (node.get("val") or {}).get("@") == "Integer":
                        found.append("ordering or grouping by column position next to *")
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
            elif key == "sortClause" and stmt.get("@") == "SelectStmt":
                # `COUNT(*) AS orders ... ORDER BY orders`: a bare ORDER BY name means the output
                # column first (SQL92 rule), so it is that column, not the table's whole row.
                # GROUP BY prefers input columns, so it gets no such pass.
                out = {r.get("name") for r in stmt.get("targetList") or () if isinstance(r, dict) and r.get("name")}
                for item in value or ():
                    ref = item.get("node") if isinstance(item, dict) else None
                    fields = (ref or {}).get("fields") or [] if isinstance(ref, dict) and ref.get("@") == "ColumnRef" else []
                    if len(fields) == 1 and fields[0].get("sval") in out:
                        continue
                    walk(item)
            else:
                walk(value)

    for raw in ast:
        tree = raw(skip_none=True)
        collect(tree)
        stmt = tree.get("stmt") or {}
        # Plain EXPLAIN returns the plan, never rows, so its query keeps the top-level `*` rules.
        walk_stmt(stmt.get("query") if stmt.get("@") == "ExplainStmt" else stmt, top=True)
    return found
