
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
    class RangeVarVisitor(Visitor):
        def __init__(self):
            super().__init__()
            self.tables = []
        def visit_RangeVar(self, ancestors, node):
            schema = node.schemaname if getattr(node, 'schemaname', None) else 'public'
            table = node.relname
            if table:
                self.tables.append((schema, table))
            
    visitor = RangeVarVisitor()
    for stmt_dict in ast:
        visitor(stmt_dict)
    return list(dict.fromkeys(visitor.tables))


def check_sensitive_columns(ast):
    from pglast.visitors import Visitor
    class ColumnRefVisitor(Visitor):
        def __init__(self):
            super().__init__()
            self.sensitive_found = []
            self.sensitive_keywords = {"password", "token", "secret", "ssn", "hash", "credit_card"}
            
        def visit_ColumnRef(self, ancestors, node):
            # Fields is a list of String or A_Star nodes
            for field in node.fields:
                if hasattr(field, 'sval'):
                    val = field.sval.lower()
                    if any(k in val for k in self.sensitive_keywords):
                        self.sensitive_found.append(field.sval)
                        
    visitor = ColumnRefVisitor()
    for stmt_dict in ast:
        visitor(stmt_dict)
    return visitor.sensitive_found
