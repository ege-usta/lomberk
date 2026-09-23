import psycopg
from psycopg.sql import SQL, Identifier, Literal

class UndoEngine:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def undo(self, checkpoint_id: int, force: bool = False) -> bool:
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                # Disable triggers and FK constraints for this transaction
                cur.execute("SET LOCAL session_replication_role = replica;")
                
                # Get all row changes for this checkpoint in reverse order
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
                
                if not changes:
                    # Check if it was a DDL or something else
                    pass
                    
                for change in changes:
                    c_id, schema, table, op, pk, old_row, new_row = change
                    
                    if op == 'I':
                        # Undo Insert -> Delete
                        cur.execute(
                            SQL("DELETE FROM {schema}.{table} WHERE id = {pk_val}").format(
                                schema=Identifier(schema),
                                table=Identifier(table),
                                pk_val=Literal(pk.get("id"))
                            )
                        )
                    elif op == 'U':
                        # Undo Update -> Update back to old_row
                        # Using jsonb_populate_record is tricky for UPDATE without knowing columns, 
                        # but we can construct the SET clause from old_row keys.
                        set_items = []
                        values = []
                        for k, v in old_row.items():
                            set_items.append(SQL("{k} = %s").format(k=Identifier(k)))
                            values.append(v)
                            
                        values.append(pk.get("id")) # for WHERE
                        
                        query = SQL("UPDATE {schema}.{table} SET {set_clause} WHERE id = %s").format(
                            schema=Identifier(schema),
                            table=Identifier(table),
                            set_clause=SQL(", ").join(set_items)
                        )
                        cur.execute(query, values)
                        
                    elif op == 'D':
                        # Undo Delete -> Insert back
                        cur.execute(
                            SQL("INSERT INTO {schema}.{table} SELECT * FROM jsonb_populate_record(NULL::{schema}.{table}, %s)").format(
                                schema=Identifier(schema),
                                table=Identifier(table)
                            ),
                            (psycopg.types.json.Jsonb(old_row),)
                        )
                        
                # Mark as undone
                cur.execute("UPDATE undogate.checkpoints SET status = 'undone' WHERE id = %s", (checkpoint_id,))
                conn.commit()
                return True
