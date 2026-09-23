
from psycopg import Cursor
from psycopg.sql import SQL, Identifier


def handle_drop_table(cur: Cursor, schema: str, table: str, cp_id: str) -> dict:
    backup_name = f"{table}__cp_{cp_id}"
    # Move to trash schema and rename
    cur.execute(SQL("ALTER TABLE {schema}.{table} SET SCHEMA undogate_trash").format(
        schema=Identifier(schema),
        table=Identifier(table)
    ))
    cur.execute(SQL("ALTER TABLE undogate_trash.{table} RENAME TO {backup}").format(
        table=Identifier(table),
        backup=Identifier(backup_name)
    ))
    return {
        "type": "drop_table",
        "schema": schema,
        "table": table,
        "backup_name": backup_name
    }

def handle_truncate(cur: Cursor, schema: str, table: str, cp_id: str) -> dict:
    backup_name = f"{table}__cp_{cp_id}"
    # Duplicate table structure and data to trash
    cur.execute(SQL("CREATE TABLE undogate_trash.{backup} (LIKE {schema}.{table} INCLUDING ALL)").format(
        backup=Identifier(backup_name),
        schema=Identifier(schema),
        table=Identifier(table)
    ))
    cur.execute(SQL("INSERT INTO undogate_trash.{backup} SELECT * FROM {schema}.{table}").format(
        backup=Identifier(backup_name),
        schema=Identifier(schema),
        table=Identifier(table)
    ))
    # Note: TRUNCATE itself will be run by the executor later
    return {
        "type": "truncate",
        "schema": schema,
        "table": table,
        "backup_name": backup_name
    }

def handle_drop_column(cur: Cursor, schema: str, table: str, column: str, cp_id: str) -> dict:
    # Minimal MVP: just back up the column data with the primary key 'id'
    backup_name = f"{table}_{column}__cp_{cp_id}"
    
    # Get column type
    cur.execute(
        "SELECT data_type FROM information_schema.columns WHERE table_schema = %s AND table_name = %s AND column_name = %s",
        (schema, table, column)
    )
    col_type = cur.fetchone()[0]

    cur.execute(SQL("CREATE TABLE undogate_trash.{backup} AS SELECT id, {col} FROM {schema}.{table}").format(
        backup=Identifier(backup_name),
        col=Identifier(column),
        schema=Identifier(schema),
        table=Identifier(table)
    ))
    
    return {
        "type": "drop_column",
        "schema": schema,
        "table": table,
        "column": column,
        "col_type": col_type,
        "backup_name": backup_name
    }
