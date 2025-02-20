from flask import Flask, render_template, session, redirect, url_for, flash
from app import LoginForm, SignUpForm
from flask_wtf.csrf import CSRFProtect
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from flask_wtf.csrf import generate_csrf

app = Flask(__name__)
app.config['SECRET_KEY'] =''  # Generates a random secret key
csrf = CSRFProtect(app)  # Enable CSRF protection

# @app.before_request
# def before_request():
#     session['csrf_token'] = generate_csrf()
#     print("Generated CSRF Token:", session['csrf_token'])

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        phone TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )''')
    conn.commit()
    conn.close()

init_db()  # Initialize database

def sign_up():
    form = SignUpForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        phone = form.phone.data
        password = form.password.data  # Store securely (hashed in production)

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, phone, password) VALUES (?, ?, ?, ?)",
                           (username, email, phone, password))
            conn.commit()
            conn.close()

            flash('Sign-up successful! Please log in.', 'success')
            return redirect(url_for('login'))  # Redirect to login page
        except sqlite3.IntegrityError:
            flash('Username, email, or phone number already exists.', 'danger')

    return render_template('sign_up.html', form=form)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():  # Corrected indentation
    form = LoginForm()  # Create form instance
    if form.validate_on_submit():  # If form is valid
        flash(f"Login successful for {form.username.data}!", "success")  # Flash success message
        return redirect(url_for('dashboard'))  # Redirect to dashboard
    return render_template('login.html', form=form)  # Render form template

# 🔹 Create the sign-up route
@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    form = SignUpForm()

    if form.validate_on_submit():  # If form is valid
        username = form.username.data
        email = form.email.data
        phone = form.phone.data
        password_hash = generate_password_hash(form.password.data)  # Hash the password

        # 🛠️ Connect to SQLite and store the data
        conn = sqlite3.connect('members.db')
        cursor = conn.cursor()

        # ✅ Create the users table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            phone TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL
                          )''')

        # 🔹 Insert user data into the database
        try:
            cursor.execute("INSERT INTO users (username, email, phone, password) VALUES (?, ?, ?, ?)",
                           (username, email, phone, password_hash))
            conn.commit()
            flash("Sign-up successful! Please log in.", "success")
            return redirect(url_for('login'))  # Redirect to login page
        except sqlite3.IntegrityError:
            flash("Username or email already exists! Try a different one.", "danger")
        
        conn.close()

    return render_template('sign_up.html', form=form)

@app.route('/dashboard')
def dashboard():
    return "Welcome to your Dashboard!"

if __name__ == '__main__':
    app.run(debug=True)