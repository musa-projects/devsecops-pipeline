"""
DevSecOps Demo Application
INTENTIONALLY VULNERABLE — for pipeline demo purposes only

Contains deliberate vulnerabilities so each security gate catches something:
  - SQL injection via string concat   → Bandit + Semgrep (Gate 1)
  - eval(user_input)                  → Semgrep (Gate 1)
  - subprocess shell=True             → Bandit (Gate 1)
  - Hardcoded AWS secret key          → Gitleaks (Gate 3)
  - MD5 usage                         → Bandit (Gate 1)
"""
from flask import Flask, request, jsonify
import sqlite3
import hashlib
import subprocess

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded secret — Gitleaks will catch this
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_PASSWORD = "super_secret_password_123"


# VULNERABILITY 2: SQL Injection — Semgrep/Bandit catches this
@app.route('/user')
def get_user():
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


# VULNERABILITY 3: eval() of user input — Semgrep catches this
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr', '1+1')
    result = eval(expression)
    return jsonify({'result': result})


# VULNERABILITY 4: Insecure MD5 hash — Bandit catches this
@app.route('/hash')
def hash_password():
    password = request.args.get('password', '')
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({'hash': hashed})


# VULNERABILITY 5: Shell injection — Bandit catches this
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)
    return jsonify({'output': result.stdout.decode()})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
