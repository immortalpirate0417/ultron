import os
from flask import Flask, render_template, request, redirect, url_for, session
from dotenv import load_dotenv
from db import get_db_connection
from auth_utils import verify_password, login_required, role_required
from audit import log_audit
from audit import log_audit
from stats import get_total_events

load_dotenv()

EVENTS_PER_PAGE = 25

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-placeholder-change-later')
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        return render_template(
        'dashboard.html',
        active_page='dashboard',
        total_events=get_total_events()
    )

    @app.route('/events')
    @login_required
    def events():
        page = request.args.get('page', 1, type=int)
        if page < 1:
            page = 1

        conn = get_db_connection()
        if not conn:
            return "Database unavailable.", 503

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS total FROM security_events")
        total = cursor.fetchone()['total']

        total_pages = max(1, -(-total // EVENTS_PER_PAGE))
        if page > total_pages:
            page = total_pages
        offset = (page - 1) * EVENTS_PER_PAGE

        cursor.execute(
            "SELECT event_id, timestamp, username, source_ip, device_id, event_type, "
            "status, resource, bytes_transferred, severity, source_type "
            "FROM security_events ORDER BY timestamp DESC, event_id DESC "
            "LIMIT %s OFFSET %s",
            (EVENTS_PER_PAGE, offset)
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return render_template('events.html', events=rows, page=page,
                               total_pages=total_pages, total=total,
                               active_page='events')

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
        ip = request.remote_addr

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
            log_audit('LOGIN', 'FAILURE',
                      user_id=user['id'] if user else None,
                      username=username[:50],
                      ip_address=ip,
                      details='Invalid credentials or inactive account')
            return render_template('login.html', error="Invalid username or password.")

        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        log_audit('LOGIN', 'SUCCESS', user_id=user['id'],
                  username=user['username'], ip_address=ip)
        return redirect(url_for('dashboard'))

    @app.route('/logout')
    def logout():
        if 'user_id' in session:
            log_audit('LOGOUT', 'SUCCESS', user_id=session['user_id'],
                      username=session['username'], ip_address=request.remote_addr)
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