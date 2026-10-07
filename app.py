import os
from flask import Flask
from dotenv import load_dotenv
from db import get_db_connection

load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-placeholder-change-later')

    @app.route('/')
    def index():
        return "ULTRON is running."

    @app.route('/health')
    def health():
        return {"status": "ok"}

    @app.route('/db-check')
    def db_check():
        conn = get_db_connection()
        if conn and conn.is_connected():
            conn.close()
            return {"database": "connected"}
        return {"database": "connection failed"}, 500

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)