# Security Vulnerability Examples

This file contains detailed examples for each security vulnerability category. Organized with clear section headers for easy agent search.

---

## # Authentication Examples

### Weak Password Storage
```python
# ❌ BAD: Plain text password storage
user.password = request.form['password']
user.save()

# ❌ BAD: Weak hashing (MD5, SHA1)
import hashlib
user.password = hashlib.md5(password.encode()).hexdigest()

# ✅ GOOD: Use bcrypt, argon2, or PBKDF2
from werkzeug.security import generate_password_hash, check_password_hash
user.password = generate_password_hash(password, method='pbkdf2:sha256')
```

### Missing Authorization Checks
```python
# ❌ BAD: No authorization check
@app.route('/user/<user_id>/delete')
def delete_user(user_id):
    User.query.filter_by(id=user_id).delete()
    return 'Deleted'

# ✅ GOOD: Verify ownership or admin role
@app.route('/user/<user_id>/delete')
@login_required
def delete_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    User.query.filter_by(id=user_id).delete()
    return 'Deleted'
```

### Insecure Session Management
```javascript
// ❌ BAD: Session without secure flags
app.use(session({
    secret: 'mysecret',
    cookie: {}
}));

// ✅ GOOD: Secure session configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: {
        secure: true,      // HTTPS only
        httpOnly: true,    // No JS access
        sameSite: 'strict', // CSRF protection
        maxAge: 3600000    // 1 hour expiry
    }
}));
```

### JWT Token Vulnerabilities
```python
# ❌ BAD: Weak secret, no expiration
token = jwt.encode({'user_id': user.id}, 'secret123')

# ❌ BAD: No signature verification
data = jwt.decode(token, options={"verify_signature": False})

# ✅ GOOD: Strong secret, expiration, verification
import os
from datetime import datetime, timedelta

token = jwt.encode({
    'user_id': user.id,
    'exp': datetime.utcnow() + timedelta(hours=1)
}, os.environ['JWT_SECRET'], algorithm='HS256')

# Verify with signature
data = jwt.decode(token, os.environ['JWT_SECRET'], algorithms=['HS256'])
```

---

## # Injection Examples

### SQL Injection
```python
# ❌ BAD: String concatenation
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# ❌ BAD: String formatting
query = "SELECT * FROM users WHERE id = %s" % user_id
cursor.execute(query)

# ✅ GOOD: Parameterized queries
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))

# ✅ GOOD: ORM usage
user = User.query.filter_by(username=username).first()
```

### Command Injection
```python
# ❌ BAD: Direct shell command with user input
import os
os.system(f"ping {user_host}")

# ❌ BAD: Using shell=True
import subprocess
subprocess.run(f"ping {user_host}", shell=True)

# ✅ GOOD: Use subprocess with list arguments
import subprocess
subprocess.run(['ping', '-c', '4', user_host], shell=False, capture_output=True)

# ✅ BETTER: Validate input against whitelist
import re
if re.match(r'^[a-zA-Z0-9.-]+$', user_host):
    subprocess.run(['ping', '-c', '4', user_host], shell=False)
else:
    raise ValueError("Invalid host")
```

### NoSQL Injection
```javascript
// ❌ BAD: Direct object injection
db.users.find({ username: req.body.username, password: req.body.password });

// Attacker sends: {"username": {"$ne": null}, "password": {"$ne": null}}

// ✅ GOOD: Sanitize input
const username = String(req.body.username);
const password = String(req.body.password);
db.users.find({ username: username, password: hashedPassword });

// ✅ BETTER: Use schema validation
const User = mongoose.model('User', new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
}));
```

### LDAP Injection
```python
# ❌ BAD: Unsanitized LDAP query
search_filter = f"(uid={username})"
ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter)

# ✅ GOOD: Escape special characters
import ldap
username_escaped = ldap.filter.escape_filter_chars(username)
search_filter = f"(uid={username_escaped})"
```

### Path Traversal
```python
# ❌ BAD: Direct file access with user input
@app.route('/download/<filename>')
def download(filename):
    return send_file(f'/var/data/{filename}')

# Attacker: /download/../../../etc/passwd

# ✅ GOOD: Validate and restrict path
import os
from werkzeug.utils import secure_filename

@app.route('/download/<filename>')
def download(filename):
    safe_filename = secure_filename(filename)
    filepath = os.path.join('/var/data', safe_filename)

    # Ensure path doesn't escape base directory
    if not os.path.abspath(filepath).startswith('/var/data/'):
        abort(400)

    return send_file(filepath)
```

---

## # Secrets Examples

### Hardcoded API Keys
```python
# ❌ BAD: API key in source code
API_KEY = "sk_live_51HqK2jKl3m4n5o6p7q8r9s0"
STRIPE_SECRET = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"

# ❌ BAD: AWS credentials in code
aws_access_key = "AKIAIOSFODNN7EXAMPLE"
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ✅ GOOD: Use environment variables
import os
API_KEY = os.environ.get('API_KEY')
STRIPE_SECRET = os.environ.get('STRIPE_SECRET')

# ✅ BETTER: Use secret management service
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://myvault.vault.azure.net", credential=credential)
api_key = client.get_secret("api-key").value
```

### Database Credentials
```python
# ❌ BAD: Credentials in connection string
SQLALCHEMY_DATABASE_URI = "postgresql://admin:password123@localhost/mydb"

# ✅ GOOD: Use environment variables
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
```

### Private Keys in Repository
```bash
# ❌ BAD: Committing private keys
git add id_rsa
git add .env
git add config/credentials.json

# ✅ GOOD: Add to .gitignore
echo "*.pem" >> .gitignore
echo "*.key" >> .gitignore
echo ".env" >> .gitignore
echo "credentials.json" >> .gitignore
```

### Secrets in Logs
```python
# ❌ BAD: Logging sensitive data
logger.info(f"User {username} logged in with password {password}")
logger.debug(f"API request with key: {api_key}")

# ✅ GOOD: Mask sensitive data
logger.info(f"User {username} logged in successfully")
logger.debug(f"API request with key: {api_key[:8]}...")
```

---

## # XSS Examples

### Reflected XSS
```python
# ❌ BAD: Unsanitized output
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Results for: {query}</h1>"

# Attacker: /search?q=<script>alert('XSS')</script>

# ✅ GOOD: Escape output
from flask import escape
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Results for: {escape(query)}</h1>"

# ✅ BETTER: Use template engine with auto-escaping
@app.route('/search')
def search():
    query = request.args.get('q')
    return render_template('search.html', query=query)
```

### Stored XSS
```javascript
// ❌ BAD: Rendering user content without sanitization
function displayComment(comment) {
    document.getElementById('comments').innerHTML += comment.text;
}

// ✅ GOOD: Use textContent or sanitize HTML
function displayComment(comment) {
    const div = document.createElement('div');
    div.textContent = comment.text; // Auto-escapes
    document.getElementById('comments').appendChild(div);
}

// ✅ GOOD: Use DOMPurify for rich text
import DOMPurify from 'dompurify';
function displayComment(comment) {
    const clean = DOMPurify.sanitize(comment.text);
    document.getElementById('comments').innerHTML += clean;
}
```

### DOM-based XSS
```javascript
// ❌ BAD: Using user input in dangerous sinks
const name = window.location.hash.substring(1);
document.write("<h1>Hello " + name + "</h1>");

// ❌ BAD: eval with user data
eval("var x = " + userInput);

// ✅ GOOD: Avoid dangerous functions
const name = window.location.hash.substring(1);
const h1 = document.createElement('h1');
h1.textContent = "Hello " + name;
document.body.appendChild(h1);
```

---

## # CSRF Examples

### Missing CSRF Protection
```python
# ❌ BAD: State-changing operation without CSRF token
@app.route('/transfer', methods=['POST'])
def transfer():
    amount = request.form['amount']
    to_account = request.form['to_account']
    transfer_funds(current_user, to_account, amount)
    return 'Transfer complete'

# ✅ GOOD: CSRF token validation
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

@app.route('/transfer', methods=['POST'])
@csrf_required
def transfer():
    amount = request.form['amount']
    to_account = request.form['to_account']
    transfer_funds(current_user, to_account, amount)
    return 'Transfer complete'
```

### SameSite Cookie Missing
```javascript
// ❌ BAD: No SameSite attribute
res.cookie('session', sessionId, { httpOnly: true });

// ✅ GOOD: SameSite=Strict or Lax
res.cookie('session', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
});
```

---

## # CORS Examples

### Overly Permissive CORS
```python
# ❌ BAD: Allow all origins with credentials
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response

# ✅ GOOD: Whitelist specific origins
ALLOWED_ORIGINS = ['https://myapp.com', 'https://staging.myapp.com']

@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

---

## # Security Headers Examples

### Missing Security Headers
```python
# ❌ BAD: No security headers
@app.route('/')
def index():
    return render_template('index.html')

# ✅ GOOD: Comprehensive security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    return response
```

---

## # Insecure Deserialization Examples

### Pickle Deserialization
```python
# ❌ BAD: Unpickling untrusted data
import pickle
user_data = pickle.loads(request.data)

# ✅ GOOD: Use JSON instead
import json
user_data = json.loads(request.data)

# ✅ GOOD: If pickle needed, sign data
import hmac
import pickle

def safe_pickle_loads(data, secret):
    signature, pickled = data.split(b':', 1)
    if hmac.compare_digest(signature, hmac.new(secret, pickled).digest()):
        return pickle.loads(pickled)
    raise ValueError("Invalid signature")
```

---

## # SSRF Examples

### Server-Side Request Forgery
```python
# ❌ BAD: Fetching user-provided URL
import requests

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)
    return response.content

# Attacker: /fetch?url=http://169.254.169.254/latest/meta-data/

# ✅ GOOD: Whitelist domains and validate
import requests
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    parsed = urlparse(url)

    # Check protocol
    if parsed.scheme not in ['http', 'https']:
        abort(400, "Invalid protocol")

    # Check domain whitelist
    if parsed.netloc not in ALLOWED_DOMAINS:
        abort(400, "Domain not allowed")

    # Prevent internal network access
    if parsed.netloc.startswith('192.168.') or parsed.netloc.startswith('10.') or parsed.netloc == 'localhost':
        abort(400, "Internal network access denied")

    response = requests.get(url, timeout=5)
    return response.content
```

---

## # Race Condition Examples

### TOCTOU Vulnerability
```python
# ❌ BAD: Check-then-use pattern
def withdraw(account_id, amount):
    balance = get_balance(account_id)
    if balance >= amount:
        # Race condition: balance could change here
        time.sleep(0.1)  # Simulating delay
        set_balance(account_id, balance - amount)
        return True
    return False

# ✅ GOOD: Atomic operation with database lock
def withdraw(account_id, amount):
    with transaction.atomic():
        account = Account.objects.select_for_update().get(id=account_id)
        if account.balance >= amount:
            account.balance -= amount
            account.save()
            return True
    return False
```

---

## # Mass Assignment Examples

### Parameter Tampering
```python
# ❌ BAD: Allowing all fields to be updated
@app.route('/user/update', methods=['POST'])
def update_user():
    user = User.query.get(current_user.id)
    for key, value in request.json.items():
        setattr(user, key, value)  # Attacker can set is_admin=True
    db.session.commit()
    return 'Updated'

# ✅ GOOD: Whitelist allowed fields
@app.route('/user/update', methods=['POST'])
def update_user():
    ALLOWED_FIELDS = ['email', 'name', 'bio']
    user = User.query.get(current_user.id)
    for key, value in request.json.items():
        if key in ALLOWED_FIELDS:
            setattr(user, key, value)
    db.session.commit()
    return 'Updated'
```

---

## # Cryptography Examples

### Weak Encryption
```python
# ❌ BAD: Weak algorithms
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha1(password.encode()).hexdigest()

# ❌ BAD: ECB mode
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)

# ✅ GOOD: Strong algorithms and modes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# For symmetric encryption
key = Fernet.generate_key()
f = Fernet(key)
encrypted = f.encrypt(b"my data")

# For AES with proper mode
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
```

---

## # Rate Limiting Examples

### Missing Rate Limiting
```python
# ❌ BAD: No rate limiting on login
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = authenticate(username, password)
    if user:
        login_user(user)
        return redirect('/dashboard')
    return 'Invalid credentials'

# ✅ GOOD: Implement rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.form['username']
    password = request.form['password']
    user = authenticate(username, password)
    if user:
        login_user(user)
        return redirect('/dashboard')
    return 'Invalid credentials'
```

---

*This examples file should be referenced by the security review agent when detailed vulnerability patterns are needed for specific categories.*
