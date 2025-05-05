
from flask import Flask, request, render_template
import sqlite3
import bcrypt
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

# CSRF protection
csrf = CSRFProtect(app)

# Insecure SQL Query (Vulnerable to SQL Injection)
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Secure version: Use parameterized queries
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    if user:
        return "Login successful"
    else:
        return "Invalid credentials"

# Secure Password Storage
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    # Hash the password before storing
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
    conn.commit()
    
    return "User registered successfully"

if __name__ == '__main__':
    app.run(debug=True)
