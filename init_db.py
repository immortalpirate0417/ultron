import os
from dotenv import load_dotenv
from db import get_db_connection

load_dotenv()

def init_db():
    conn = get_db_connection()
    if not conn:
        print("Could not connect to database. Aborting.")
        return

    cursor = conn.cursor()
    with open('schema.sql', 'r') as f:
        schema = f.read()

    # Execute each statement separately
    for statement in schema.split(';'):
        statement = statement.strip()
        if statement:
            cursor.execute(statement)

    conn.commit()
    cursor.close()
    conn.close()
    print("Database schema initialized successfully.")

if __name__ == '__main__':
    init_db()