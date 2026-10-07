from werkzeug.security import generate_password_hash, check_password_hash

def hash_password(plain_password: str) -> str:
    """Hash a plain-text password for storing in the database."""
    return generate_password_hash(plain_password)

def verify_password(plain_password: str, password_hash: str) -> bool:
    """Check a plain-text password against a stored hash."""
    return check_password_hash(password_hash, plain_password)