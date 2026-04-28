from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
import bcrypt
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# ─── MySQL Config ───────────────────────────────────────────
DB_CONFIG = {
    'host': 'mysql-service',
    'user': 'root',         # Change to your MySQL username
    'password': 'Root@1234',         # Change to your MySQL password
    'database': 'auth_db'
}

def get_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    return conn

def init_db():
    conn = mysql.connector.connect(
        host=DB_CONFIG['host'],
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password']
    )
    cursor = conn.cursor()
    cursor.execute("CREATE DATABASE IF NOT EXISTS auth_db")
    cursor.execute("USE auth_db")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100),
            mobile VARCHAR(15),
            password VARCHAR(255) NOT NULL
        )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

# ─── Home ────────────────────────────────────────────────────
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ─── Signup ──────────────────────────────────────────────────
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name     = request.form['name'].strip()
        email    = request.form.get('email', '').strip()
        mobile   = request.form.get('mobile', '').strip()
        password = request.form['password']
        confirm  = request.form['confirm_password']

        if not name or not password:
            flash('Name and password are required.', 'danger')
            return render_template('signup.html')

        if not email and not mobile:
            flash('Provide at least an email or mobile number.', 'danger')
            return render_template('signup.html')

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('signup.html')

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (name, email, mobile, password) VALUES (%s, %s, %s, %s)",
                (name, email or None, mobile or None, hashed.decode('utf-8'))
            )
            conn.commit()
            flash('Account created! Please log in.', 'success')
            return redirect(url_for('login'))
        except mysql.connector.IntegrityError:
            flash('Email or mobile already registered.', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('signup.html')

# ─── Login ───────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['identifier'].strip()
        password   = request.form['password']

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM users WHERE email = %s OR mobile = %s",
            (identifier, identifier)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            flash(f"Welcome back, {user['name']}!", 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

# ─── Dashboard ───────────────────────────────────────────────
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', name=session['user_name'])

# ─── Logout ──────────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
