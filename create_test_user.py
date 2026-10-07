import os
from dotenv import load_dotenv
from db import get_db_connection
from auth_utils import hash_password

load_dotenv()

def create_test_user():
    conn = get_db_connection()
    if not conn:
        print("Could not connect to database. Aborting.")
        return

    cursor = conn.cursor()
    hashed = hash_password("TestPassword123")

    cursor.execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
        ("testadmin", "testadmin@ultron.local", hashed, "admin")
    )
    conn.commit()
    cursor.close()
    conn.close()
    print("Test user created: username=testadmin, password=TestPassword123")

if __name__ == '__main__':
    create_test_user()