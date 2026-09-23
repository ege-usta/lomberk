import psycopg
from testcontainers.postgres import PostgresContainer

with PostgresContainer("postgres:16-alpine") as postgres:
    dsn = postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE parent (id INT PRIMARY KEY);
                CREATE TABLE child (id INT, p_id INT REFERENCES parent(id));
            """)
            
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SET session_replication_role = replica;")
            # Insert child first, normally fails FK
            cur.execute("INSERT INTO child VALUES (1, 1);")
            cur.execute("INSERT INTO parent VALUES (1);")
            conn.commit()
            print("SUCCESS")
