import os
from flask import Flask, render_template, request, redirect, url_for, session
from dotenv import load_dotenv
from db import get_db_connection
from auth_utils import verify_password, login_required, role_required

load_dotenv()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-placeholder-change-later')
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    @app.route('/')
    def index():
        if 'user_id' in session:
            return f"ULTRON is running. Logged in as {session['username']} ({session['role']})"
        return "ULTRON is running. <a href='/login'>Login</a>"

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

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return render_template('login.html')

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db_connection()
        if not conn:
            return render_template('login.html', error="Database unavailable.")

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, username, password_hash, role, is_active FROM users WHERE username = %s",
            (username,)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user or not user['is_active'] or not verify_password(password, user['password_hash']):
            return render_template('login.html', error="Invalid username or password.")

        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        return redirect(url_for('index'))

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.route('/protected')
    @login_required
    def protected():
        return f"Protected page. Welcome, {session['username']}."

    @app.route('/admin-test')
    @role_required('admin')
    def admin_test():
        return "Admin-only page. Access granted."

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)