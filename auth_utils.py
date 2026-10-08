from functools import wraps
from flask import session, redirect, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(plain_password: str) -> str:
    """Hash a plain-text password for storing in the database."""
    return generate_password_hash(plain_password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    """Check a plain-text password against a stored hash."""
    return check_password_hash(password_hash, plain_password)

def login_required(f):
    """Redirect to login page if user is not logged in."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

def role_required(*roles):
    """Allow only users whose role is in `roles`. Returns 403 otherwise."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') not in roles:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator