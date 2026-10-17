import json
import os
import secrets
from flask import (Flask, render_template, request, redirect, url_for,
                   session, abort)
from dotenv import load_dotenv
from db import get_db_connection
from auth_utils import verify_password, login_required, role_required
from audit import log_audit, get_incident_audit_history
from stats import get_total_events, get_incident_counts, get_top_incidents
from incident_store import (update_incident_status, VALID_STATUSES,
                            add_incident_note, get_incident_notes)

load_dotenv()

EVENTS_PER_PAGE = 25
INCIDENTS_LIMIT = 50
RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def parse_risk_factors(value):
    """Return a list of factor dicts from the JSON column (string or list), or []."""
    if not value:
        return []
    try:
        data = json.loads(value) if isinstance(value, (str, bytes)) else value
    except (ValueError, TypeError):
        return []
    return data if isinstance(data, list) else []


def get_csrf_token():
    """Return this session's CSRF token, creating it if needed."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']


def csrf_valid(sent):
    """True if the submitted token matches the session token (safe for any input)."""
    expected = session.get('csrf_token', '')
    if not expected or not sent:
        return False
    return secrets.compare_digest(sent.encode('utf-8'), expected.encode('utf-8'))


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
        return render_template('dashboard.html', active_page='dashboard',
                               total_events=get_total_events(),
                               counts=get_incident_counts(),
                               top_incidents=get_top_incidents())

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

    @app.route('/incidents')
    @login_required
    def incidents():
        status = request.args.get('status', '')
        risk = request.args.get('risk', '')

        if status not in VALID_STATUSES:
            status = ''
        if risk not in RISK_LEVELS:
            risk = ''

        # Only fixed clause strings are added; values are always parameterized.
        where = []
        params = []

        if status:
            where.append("status = %s")
            params.append(status)

        if risk:
            where.append("risk_level = %s")
            params.append(risk)

        where_sql = (" WHERE " + " AND ".join(where)) if where else ""

        conn = get_db_connection()
        if not conn:
            return "Database unavailable.", 503

        cursor = None
        try:
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                "SELECT COUNT(*) AS total FROM incidents" + where_sql,
                tuple(params)
            )
            total = cursor.fetchone()['total']

            cursor.execute(
                "SELECT id, incident_code, classification, affected_user, source_ip, "
                "severity, status, summary, first_seen, last_seen, risk_score, risk_level "
                "FROM incidents" + where_sql +
                " ORDER BY first_seen DESC, id DESC LIMIT %s",
                tuple(params) + (INCIDENTS_LIMIT,)
            )
            rows = cursor.fetchall()

        except Exception as e:
            print(f"Incidents query error: {e}")
            return "Unable to load incidents.", 500

        finally:
            if cursor:
                cursor.close()
            conn.close()

        return render_template(
            'incidents.html',
            incidents=rows,
            total=total,
            statuses=VALID_STATUSES,
            risk_levels=RISK_LEVELS,
            selected_status=status,
            selected_risk=risk,
            active_page='incidents'
        )

    @app.route('/incidents/<int:incident_id>')
    @login_required
    def incident_detail(incident_id):
        conn = get_db_connection()
        if not conn:
            return "Database unavailable.", 503

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, incident_code, rule, classification, affected_user, source_ip, "
            "severity, status, summary, first_seen, last_seen, "
            "risk_score, risk_level, risk_factors "
            "FROM incidents WHERE id = %s",
            (incident_id,)
        )
        incident = cursor.fetchone()

        if not incident:
            cursor.close()
            conn.close()
            abort(404)

        cursor.execute(
            "SELECT e.event_id, e.timestamp, e.username, e.source_ip, e.device_id, "
            "e.event_type, e.status, e.severity, e.source_type "
            "FROM incident_events ie "
            "JOIN security_events e ON e.event_id = ie.event_id "
            "WHERE ie.incident_id = %s ORDER BY e.timestamp, e.event_id",
            (incident_id,)
        )
        evidence = cursor.fetchall()
        cursor.close()
        conn.close()

        return render_template(
            'incident_detail.html',
            incident=incident,
            evidence=evidence,
            notes=get_incident_notes(incident_id),
            audit_history=get_incident_audit_history(incident_id),
            risk_factors=parse_risk_factors(incident['risk_factors']),
            statuses=VALID_STATUSES,
            csrf_token=get_csrf_token(),
            active_page='incidents'
        )

    @app.route('/incidents/<int:incident_id>/status', methods=['POST'])
    @role_required('admin', 'analyst')
    def update_status(incident_id):
        if not csrf_valid(request.form.get('csrf_token', '')):
            abort(400)

        new_status = request.form.get('status', '')
        result = update_incident_status(incident_id, new_status)
        if result is None:
            abort(400)

        old_status, new_status = result
        log_audit(
            'INCIDENT_STATUS', 'SUCCESS',
            user_id=session['user_id'],
            username=session['username'],
            ip_address=request.remote_addr,
            details=f"incident_id={incident_id}: {old_status} -> {new_status}"
        )
        return redirect(url_for('incident_detail', incident_id=incident_id))

    @app.route('/incidents/<int:incident_id>/notes', methods=['POST'])
    @role_required('admin', 'analyst')
    def add_note(incident_id):
        if not csrf_valid(request.form.get('csrf_token', '')):
            abort(400)

        note = request.form.get('note', '')
        if not add_incident_note(
            incident_id, session['user_id'], session['username'], note
        ):
            abort(400)

        log_audit(
            'INCIDENT_NOTE', 'SUCCESS',
            user_id=session['user_id'],
            username=session['username'],
            ip_address=request.remote_addr,
            details=f"incident_id={incident_id}: note added"
        )
        return redirect(url_for('incident_detail', incident_id=incident_id))

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
            "SELECT id, username, password_hash, role, is_active "
            "FROM users WHERE username = %s",
            (username,)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if (not user or not user['is_active']
                or not verify_password(password, user['password_hash'])):
            log_audit(
                'LOGIN', 'FAILURE',
                user_id=user['id'] if user else None,
                username=username[:50],
                ip_address=ip,
                details='Invalid credentials or inactive account'
            )
            return render_template(
                'login.html', error="Invalid username or password."
            )

        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']

        log_audit(
            'LOGIN', 'SUCCESS',
            user_id=user['id'],
            username=user['username'],
            ip_address=ip
        )
        return redirect(url_for('dashboard'))

    @app.route('/logout')
    def logout():
        if 'user_id' in session:
            log_audit(
                'LOGOUT', 'SUCCESS',
                user_id=session['user_id'],
                username=session['username'],
                ip_address=request.remote_addr
            )
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