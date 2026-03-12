"""
DevSecOps Demo Application — SECURE VERSION
All vulnerabilities from app.py have been fixed.
Use this version to show the pipeline passing all 5 gates.
"""
from flask import Flask, request, jsonify
import sqlite3
import hashlib
import ast
import os
import subprocess

app = Flask(__name__)

# FIX 1: No hardcoded secrets — use environment variables
AWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY', '')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')


# FIX 2: Parameterized query — no SQL injection
@app.route('/user')
def get_user():
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)


# FIX 3: ast.literal_eval — safe, only evaluates literals
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr', '1+1')
    try:
        result = ast.literal_eval(expression)
        if not isinstance(result, (int, float)):
            return jsonify({'error': 'Only numeric expressions allowed'}), 400
    except (ValueError, SyntaxError):
        return jsonify({'error': 'Invalid expression'}), 400
    return jsonify({'result': result})


# FIX 4: SHA-256 instead of MD5
@app.route('/hash')
def hash_password():
    password = request.args.get('password', '')
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return jsonify({'hash': hashed})


# FIX 5: No shell=True, validated input
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    if not host.replace('.', '').replace('-', '').isalnum():
        return jsonify({'error': 'Invalid hostname'}), 400
    result = subprocess.run(['ping', '-c', '1', host],
                            capture_output=True, timeout=5)
    return jsonify({'output': result.stdout.decode()})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
