import os
import mysql.connector
from mysql.connector import Error

def get_db_connection():
    """Create and return a new MySQL connection."""
    try:
        conn = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            port=int(os.getenv('DB_PORT', 3306)),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
        return conn
    except Error as e:
        print(f"Database connection error: {e}")
        return None