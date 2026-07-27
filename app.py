import os
import time
import sqlite3
import bcrypt
import jwt
from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS

app = Flask(__name__, static_folder='public', static_url_path='')
CORS(app, supports_credentials=True, origins="*")

JWT_SECRET = os.environ.get('JWT_SECRET', 'antigravity-secure-jwt-secret-key-2026')
DB_PATH = 'users.db'

# ----------------------------------------------------
# DATABASE INITIALIZATION
# ----------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Helper JWT token generator
def generate_token(user_id, username, email):
    payload = {
        'userId': user_id,
        'username': username,
        'email': email,
        'exp': time.time() + (24 * 3600)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except Exception:
        return None

def get_current_user_from_req():
    auth_header = request.headers.get('Authorization')
    token = None
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
    elif 'token' in request.cookies:
        token = request.cookies.get('token')
    
    if not token:
        return None
    return verify_token(token)

# ----------------------------------------------------
# STATIC FRONTEND ROUTES
# ----------------------------------------------------
@app.route('/')
def index():
    return send_from_directory('public', 'index.html')

@app.route('/<path:path>')
def static_proxy(path):
    if os.path.exists(os.path.join('public', path)):
        return send_from_directory('public', path)
    return send_from_directory('public', 'index.html')

# ----------------------------------------------------
# AUTHENTICATION API ENDPOINTS
# ----------------------------------------------------

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400

    if len(username) < 3:
        return jsonify({'success': False, 'message': 'Username must be at least 3 characters.'}), 400

    if '@' not in email or '.' not in email:
        return jsonify({'success': False, 'message': 'Invalid email address.'}), 400

    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Password must be at least 6 characters.'}), 400

    conn = get_db()
    cursor = conn.cursor()

    # Check duplicate
    cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'An account with this email already exists.'}), 400

    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Username is already taken.'}), 400

    # Hash password using Bcrypt
    start_time = time.time()
    salt = bcrypt.gensalt(rounds=10)
    password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    hash_time_ms = round((time.time() - start_time) * 1000, 2)

    cursor.execute(
        'INSERT INTO users (username, email, password_hash, last_login) VALUES (?, ?, ?, CURRENT_TIMESTAMP)',
        (username, email, password_hash)
    )
    user_id = cursor.lastrowid
    conn.commit()

    cursor.execute('SELECT id, username, email, created_at, last_login FROM users WHERE id = ?', (user_id,))
    user_row = dict(cursor.fetchone())
    conn.close()

    token = generate_token(user_id, username, email)
    user_row['passwordHashPreview'] = password_hash

    resp = make_response(jsonify({
        'success': True,
        'message': 'User registered successfully!',
        'token': token,
        'user': user_row,
        'securityInfo': {
            'algorithm': 'bcrypt',
            'saltRounds': 10,
            'hashTimeMs': hash_time_ms,
            'hashPreview': password_hash[:20] + '...'
        }
    }), 201)

    resp.set_cookie('token', token, max_age=86400, httponly=True)
    return resp

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    login_id = data.get('loginId', '').strip()
    password = data.get('password', '')

    if not login_id or not password:
        return jsonify({'success': False, 'message': 'Username/Email and password are required.'}), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users WHERE email = ? OR username = ?', (login_id.lower(), login_id))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid credentials.'}), 401

    user_dict = dict(user_row)
    stored_hash = user_dict['password_hash']

    # Verify password with bcrypt.checkpw
    start_time = time.time()
    is_valid = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    verify_time_ms = round((time.time() - start_time) * 1000, 2)

    if not is_valid:
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid credentials.'}), 401

    cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user_dict['id'],))
    conn.commit()

    cursor.execute('SELECT id, username, email, created_at, last_login FROM users WHERE id = ?', (user_dict['id'],))
    updated_user = dict(cursor.fetchone())
    conn.close()

    token = generate_token(updated_user['id'], updated_user['username'], updated_user['email'])
    updated_user['passwordHashPreview'] = stored_hash

    resp = make_response(jsonify({
        'success': True,
        'message': 'Login successful!',
        'token': token,
        'user': updated_user,
        'securityInfo': {
            'hashComparison': 'bcrypt.checkpw() matched',
            'verifyTimeMs': verify_time_ms
        }
    }))

    resp.set_cookie('token', token, max_age=86400, httponly=True)
    return resp

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'success': True, 'message': 'Logged out successfully.'}))
    resp.set_cookie('token', '', expires=0)
    return resp

@app.route('/api/auth/me', methods=['GET'])
def me():
    decoded = get_current_user_from_req()
    if not decoded:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (decoded['userId'],))
    user_row = cursor.fetchone()
    
    cursor.execute('SELECT COUNT(*) as count FROM users')
    total_users = cursor.fetchone()['count']
    conn.close()

    if not user_row:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    user_dict = dict(user_row)
    password_hash = user_dict.pop('password_hash')

    return jsonify({
        'success': True,
        'user': {
            **user_dict,
            'passwordHashPreview': password_hash
        },
        'systemStats': {
            'totalRegisteredUsers': total_users
        }
    })

@app.route('/api/auth/change-password', methods=['POST'])
def change_password():
    decoded = get_current_user_from_req()
    if not decoded:
        return jsonify({'success': False, 'message': 'Authentication required'}), 401

    data = request.get_json() or {}
    current_password = data.get('currentPassword', '')
    new_password = data.get('newPassword', '')

    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'Both current and new passwords are required.'}), 400

    if len(new_password) < 6:
        return jsonify({'success': False, 'message': 'New password must be at least 6 characters.'}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (decoded['userId'],))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return jsonify({'success': False, 'message': 'User not found'}), 404

    user_dict = dict(user_row)
    if not bcrypt.checkpw(current_password.encode('utf-8'), user_dict['password_hash'].encode('utf-8')):
        conn.close()
        return jsonify({'success': False, 'message': 'Current password is incorrect.'}), 400

    new_salt = bcrypt.gensalt(rounds=10)
    new_hash = bcrypt.hashpw(new_password.encode('utf-8'), new_salt).decode('utf-8')

    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, decoded['userId']))
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'message': 'Password updated successfully with new bcrypt hash!',
        'newHashPreview': new_hash
    })

# ----------------------------------------------------
# BCRYPT VISUALIZER SANDBOX ENDPOINTS
# ----------------------------------------------------

@app.route('/api/bcrypt/hash', methods=['POST'])
def bcrypt_sandbox_hash():
    data = request.get_json() or {}
    text = data.get('text', '')
    salt_rounds = int(data.get('saltRounds', 10))
    salt_rounds = max(4, min(14, salt_rounds)) # Clamp 4 to 14

    if not text:
        return jsonify({'success': False, 'message': 'Input text is required.'}), 400

    start = time.perf_counter()
    salt = bcrypt.gensalt(rounds=salt_rounds)
    hashed_bytes = bcrypt.hashpw(text.encode('utf-8'), salt)
    hash_str = hashed_bytes.decode('utf-8')
    duration_ms = round((time.perf_counter() - start) * 1000, 2)

    # Deconstruct hash format: $2b$10$22charsSalt31charsHash
    parts = hash_str.split('$')
    algo = f"${parts[1]}$" if len(parts) > 1 else "$2b$"
    cost = parts[2] if len(parts) > 2 else str(salt_rounds)
    salt_and_hash = parts[3] if len(parts) > 3 else ""
    salt_part = salt_and_hash[:22]
    hash_part = salt_and_hash[22:]

    return jsonify({
        'success': True,
        'plainText': text,
        'hash': hash_str,
        'salt': salt.decode('utf-8'),
        'saltRounds': salt_rounds,
        'durationMs': duration_ms,
        'breakdown': {
            'algorithm': algo,
            'costFactor': cost,
            'salt22Chars': salt_part,
            'hash31Chars': hash_part
        }
    })

@app.route('/api/bcrypt/verify', methods=['POST'])
def bcrypt_sandbox_verify():
    data = request.get_json() or {}
    plain_text = data.get('plainText', '')
    target_hash = data.get('hash', '').strip()

    if not plain_text or not target_hash:
        return jsonify({'success': False, 'message': 'Plaintext and Hash are required.'}), 400

    try:
        start = time.perf_counter()
        is_match = bcrypt.checkpw(plain_text.encode('utf-8'), target_hash.encode('utf-8'))
        duration_ms = round((time.perf_counter() - start) * 1000, 2)

        return jsonify({
            'success': True,
            'isMatch': is_match,
            'durationMs': duration_ms,
            'message': 'Match! The password produces this exact hash.' if is_match else 'No match! Passwords do not match.'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Invalid bcrypt hash format or error verifying.'}), 400

# ----------------------------------------------------
# MAIN EXECUTION
# ----------------------------------------------------
if __name__ == '__main__':
    print("================================================")
    print("[AUTH] Bcrypt Authentication Server running (Python/Flask)!")
    print("[WEB] Web App available at: http://localhost:3000")
    print("================================================")
    app.run(host='0.0.0.0', port=3000, debug=False)
