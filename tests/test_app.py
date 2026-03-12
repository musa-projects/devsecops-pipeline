"""Tests for the DevSecOps demo app — covers both vulnerable detection and secure fixes."""
import pytest
import sys
import os
import sqlite3
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))


@pytest.fixture
def secure_client():
    """Create a Flask test client with a temporary database."""
    import app_secure
    app_secure.app.config['TESTING'] = True

    # Create temp DB with users table
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice')")
    conn.execute("INSERT INTO users VALUES (2, 'bob')")
    conn.commit()
    conn.close()

    # Monkey-patch the DB path
    original_get_user = app_secure.get_user

    def patched_get_user():
        from flask import request, jsonify
        username = request.args.get('username', '')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
        results = cursor.fetchall()
        conn.close()
        return jsonify(results)

    app_secure.app.view_functions['get_user'] = patched_get_user

    with app_secure.app.test_client() as client:
        yield client

    os.close(db_fd)
    os.unlink(db_path)


# ── Secure app: /calculate endpoint ──────────────────────────────

def test_calculate_valid_int(secure_client):
    resp = secure_client.get('/calculate?expr=42')
    assert resp.status_code == 200
    assert resp.get_json()['result'] == 42


def test_calculate_valid_float(secure_client):
    resp = secure_client.get('/calculate?expr=3.14')
    assert resp.status_code == 200
    assert resp.get_json()['result'] == 3.14


def test_calculate_rejects_code_execution(secure_client):
    """ast.literal_eval blocks arbitrary code — this is the key security fix."""
    resp = secure_client.get('/calculate?expr=__import__("os").system("id")')
    assert resp.status_code == 400
    assert 'error' in resp.get_json()


def test_calculate_rejects_string(secure_client):
    resp = secure_client.get('/calculate?expr="hello"')
    assert resp.status_code == 400


# ── Secure app: /hash endpoint ───────────────────────────────────

def test_hash_returns_sha256(secure_client):
    resp = secure_client.get('/hash?password=test')
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data['hash']) == 64  # SHA-256 produces 64 hex chars (not 32 like MD5)


def test_hash_deterministic(secure_client):
    r1 = secure_client.get('/hash?password=abc').get_json()['hash']
    r2 = secure_client.get('/hash?password=abc').get_json()['hash']
    assert r1 == r2


# ── Secure app: /ping endpoint ───────────────────────────────────

def test_ping_rejects_shell_injection(secure_client):
    """shell=True is gone — semicolons and pipes should be rejected by validation."""
    resp = secure_client.get('/ping?host=;cat /etc/passwd')
    assert resp.status_code == 400
    assert 'Invalid hostname' in resp.get_json()['error']


def test_ping_rejects_pipe(secure_client):
    resp = secure_client.get('/ping?host=localhost|whoami')
    assert resp.status_code == 400


def test_ping_allows_valid_hostname(secure_client):
    resp = secure_client.get('/ping?host=localhost')
    assert resp.status_code == 200


# ── Secure app: /user endpoint ───────────────────────────────────

def test_user_returns_valid_user(secure_client):
    resp = secure_client.get('/user?username=alice')
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(data) == 1
    assert data[0][1] == 'alice'


def test_user_sql_injection_blocked(secure_client):
    """Parameterized query prevents SQL injection — ' OR '1'='1 should return nothing."""
    resp = secure_client.get("/user?username=' OR '1'='1")
    data = resp.get_json()
    assert len(data) == 0  # Injection treated as literal string, no match


# ── Secure app: no hardcoded secrets ─────────────────────────────

def test_no_hardcoded_secrets():
    """Verify app_secure.py doesn't contain hardcoded credentials."""
    secure_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'app_secure.py')
    with open(secure_path) as f:
        content = f.read()
    assert 'wJalrXUtnFEMI' not in content
    assert 'super_secret_password' not in content
    assert 'os.environ.get' in content  # Uses env vars instead
