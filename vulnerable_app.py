
from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Simple vulnerable web app for demonstration
VULNERABLE_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Demo App</title>
    <style>
        body { font-family: Arial; margin: 40px; background: #f5f5f5; }
        .container { max-width: 600px; background: white; padding: 30px; border-radius: 10px; }
        input, button { padding: 10px; margin: 5px; }
        .warning { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerable Demo Application</h1>
        <p class="warning">⚠️ This is a demonstration app with intentional vulnerabilities</p>
        
        <h3>SQL Injection Test</h3>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
        <p><small>Try: admin' OR '1'='1</small></p>
        
        <h3>XSS Test</h3>
        <form method="POST" action="/comment">
            <input type="text" name="comment" placeholder="Leave a comment" required><br>
            <button type="submit">Submit</button>
        </form>
        <p><small>Try: &lt;script&gt;alert('XSS')&lt;/script&gt;</small></p>
        
        <h3>File Upload Test</h3>
        <form method="POST" action="/upload" enctype="multipart/form-data">
            <input type="file" name="file" required><br>
            <button type="submit">Upload</button>
        </form>
        
        {% if message %}
        <div style="margin-top: 20px; padding: 10px; background: #e8f4fd; border-radius: 5px;">
            {{ message|safe }}
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(VULNERABLE_HTML)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Vulnerable SQL query (intentional vulnerability)
    try:
        conn = sqlite3.connect(':memory:')
        conn.execute('CREATE TABLE users (id INTEGER, username TEXT, password TEXT)')
        conn.execute("INSERT INTO users VALUES (1, 'admin', 'password123')")
        
        # Vulnerable query - DON'T USE IN PRODUCTION
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        result = conn.execute(query).fetchone()
        
        if result:
            message = f"Login successful! Welcome {result[1]}"
        else:
            message = "Invalid credentials"
        
        conn.close()
        
    except Exception as e:
        message = f"Database error: {str(e)}"
    
    return render_template_string(VULNERABLE_HTML, message=message)

@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form['comment']
    # Vulnerable to XSS - no input sanitization
    message = f"Comment posted: {comment}"
    return render_template_string(VULNERABLE_HTML, message=message)

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        message = "No file uploaded"
    else:
        file = request.files['file']
        # Vulnerable - no file type checking
        message = f"File '{file.filename}' uploaded successfully!"
    
    return render_template_string(VULNERABLE_HTML, message=message)

if __name__ == '__main__':
    print("Starting Vulnerable Demo Application...")
    print("⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("   Only use for educational and testing purposes.")
    app.run(host="0.0.0.0", port=8080, debug=True)
