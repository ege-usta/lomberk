import psycopg
from psycopg.sql import SQL, Identifier, Literal


class UndoEngine:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def undo(self, checkpoint_id: int, force: bool = False) -> bool:
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL session_replication_role = replica;")
                
                # Check for DDL
                cur.execute("SELECT ddl_undo_plan FROM undogate.checkpoints WHERE id = %s", (checkpoint_id,))
                ddl_plan = cur.fetchone()[0]
                
                if ddl_plan:
                    for plan in reversed(ddl_plan):
                        if plan["type"] == "drop_table":
                            # Move back from trash
                            cur.execute(SQL("ALTER TABLE undogate_trash.{backup} RENAME TO {table}").format(
                                backup=Identifier(plan["backup_name"]),
                                table=Identifier(plan["table"])
                            ))
                            cur.execute(SQL("ALTER TABLE undogate_trash.{table} SET SCHEMA {schema}").format(
                                table=Identifier(plan["table"]),
                                schema=Identifier(plan["schema"])
                            ))
                        elif plan["type"] == "truncate":
                            # Insert data back
                            cur.execute(SQL("INSERT INTO {schema}.{table} SELECT * FROM undogate_trash.{backup}").format(
                                schema=Identifier(plan["schema"]),
                                table=Identifier(plan["table"]),
                                backup=Identifier(plan["backup_name"])
                            ))
                            cur.execute(SQL("DROP TABLE undogate_trash.{backup}").format(
                                backup=Identifier(plan["backup_name"])
                            ))
                        elif plan["type"] == "drop_column":
                            # Add column back
                            cur.execute(SQL("ALTER TABLE {schema}.{table} ADD COLUMN {col} {col_type}").format(
                                schema=Identifier(plan["schema"]),
                                table=Identifier(plan["table"]),
                                col=Identifier(plan["column"]),
                                col_type=SQL(plan["col_type"])
                            ))
                            # Restore data
                            cur.execute(SQL("""
                                UPDATE {schema}.{table} t 
                                SET {col} = b.{col} 
                                FROM undogate_trash.{backup} b 
                                WHERE t.id = b.id
                            """).format(
                                schema=Identifier(plan["schema"]),
                                table=Identifier(plan["table"]),
                                col=Identifier(plan["column"]),
                                backup=Identifier(plan["backup_name"])
                            ))
                            cur.execute(SQL("DROP TABLE undogate_trash.{backup}").format(
                                backup=Identifier(plan["backup_name"])
                            ))

                # Undo DML
                cur.execute(
                    """
                    SELECT id, table_schema, table_name, op, pk, old_row, new_row 
                    FROM undogate.row_changes 
                    WHERE checkpoint_id = %s 
                    ORDER BY seq DESC
                    """,
                    (checkpoint_id,)
                )
                changes = cur.fetchall()
                
                for change in changes:
                    c_id, schema, table, op, pk, old_row, new_row = change
                    if op == 'I':
                        cur.execute(SQL("DELETE FROM {schema}.{table} WHERE id = {pk_val}").format(
                            schema=Identifier(schema), table=Identifier(table), pk_val=Literal(pk.get("id"))
                        ))
                    elif op == 'U':
                        set_items = []
                        values = []
                        for k, v in old_row.items():
                            set_items.append(SQL("{k} = %s").format(k=Identifier(k)))
                            values.append(v)
                        values.append(pk.get("id"))
                        
                        # Rebase Conflict Detection: We only update if the row hasn't been modified by another human/process
                        # For MVP, we use rowcount to ensure the row still exists and wasn't deleted by a human.
                        query = SQL("UPDATE {schema}.{table} SET {set_clause} WHERE id = %s").format(
                            schema=Identifier(schema), table=Identifier(table), set_clause=SQL(", ").join(set_items)
                        )
                        cur.execute(query, values)
                        if cur.rowcount == 0 and not force:
                            raise Exception(f"Rebase Conflict: Row {pk.get('id')} in {table} was missing or altered. Use force=True to overwrite.")
                            
                    elif op == 'D':
                        # Check if a human already inserted a row with the same ID
                        cur.execute(SQL("SELECT 1 FROM {schema}.{table} WHERE id = %s").format(
                            schema=Identifier(schema), table=Identifier(table)
                        ), (pk.get("id"),))
                        if cur.fetchone() and not force:
                            raise Exception(f"Rebase Conflict: Row {pk.get('id')} in {table} already exists.")
                            
                        cur.execute(SQL("INSERT INTO {schema}.{table} SELECT * FROM jsonb_populate_record(NULL::{schema}.{table}, %s)").format(
                            schema=Identifier(schema), table=Identifier(table)
                        ), (psycopg.types.json.Jsonb(old_row),))
                        
                cur.execute("UPDATE undogate.checkpoints SET status = 'undone' WHERE id = %s", (checkpoint_id,))
                conn.commit()
                return True
