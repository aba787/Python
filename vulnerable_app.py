
from flask import Flask, request, render_template_string, redirect, url_for, session, jsonify
import sqlite3
import os
import hashlib

# Create vulnerable web application
vulnerable_app = Flask(__name__)
vulnerable_app.secret_key = 'weak_secret_key_123'  # Intentionally weak

# Initialize vulnerable database
def init_vulnerable_db():
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # Users table with weak security
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Sample vulnerable data
    cursor.execute("DELETE FROM users")
    users = [
        ('admin', 'admin123', 'admin@company.com', 'admin'),
        ('user1', 'password', 'user1@company.com', 'user'),
        ('john', '123456', 'john@company.com', 'user'),
        ('test', 'test', 'test@company.com', 'user'),
        ('demo', 'demo', 'demo@company.com', 'user')
    ]
    
    cursor.executemany("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", users)
    
    # Products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    ''')
    
    cursor.execute("DELETE FROM products")
    products = [
        ('Laptop Dell XPS', 1299.99, 'حاسوب محمول عالي الأداء'),
        ('iPhone 15 Pro', 1199.99, 'هاتف ذكي متطور'),
        ('Samsung Galaxy Tab', 699.99, 'جهاز لوحي للعمل والترفيه'),
        ('MacBook Pro', 2499.99, 'حاسوب محمول للمحترفين'),
        ('Sony Headphones', 299.99, 'سماعات لاسلكية عالية الجودة')
    ]
    cursor.executemany("INSERT INTO products (name, price, description) VALUES (?, ?, ?)", products)
    
    conn.commit()
    conn.close()

init_vulnerable_db()

@vulnerable_app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🎯 التطبيق الضعيف للعرض التوضيحي</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { 
                background: linear-gradient(135deg, #ff6b6b 0%, #feca57 100%); 
                min-height: 100vh; 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .main-card { 
                background: rgba(255,255,255,0.95); 
                border-radius: 20px; 
                backdrop-filter: blur(10px); 
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            }
            .vulnerable-badge { 
                background: linear-gradient(45deg, #ff6b6b, #ff8e8e); 
                color: white; 
                padding: 8px 20px; 
                border-radius: 25px; 
                font-weight: bold;
                box-shadow: 0 4px 15px rgba(255,107,107,0.3);
            }
            .demo-card {
                border: none;
                border-radius: 15px;
                transition: transform 0.3s ease;
                box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            }
            .demo-card:hover {
                transform: translateY(-5px);
            }
            .attack-example {
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 10px;
                margin: 10px 0;
                font-family: 'Courier New', monospace;
                font-size: 0.9em;
            }
            .warning-box {
                background: linear-gradient(135deg, #ffeaa7, #fdcb6e);
                border-radius: 10px;
                padding: 20px;
                margin: 20px 0;
                border-left: 5px solid #e17055;
            }
        </style>
    </head>
    <body>
        <div class="container mt-5">
            <div class="row justify-content-center">
                <div class="col-md-11">
                    <div class="main-card p-5">
                        <div class="text-center mb-4">
                            <h1 class="display-4">🎯 التطبيق الضعيف للعرض التوضيحي</h1>
                            <span class="vulnerable-badge">⚠️ يحتوي على ثغرات أمنية مقصودة</span>
                            <p class="mt-3 lead">
                                هذا التطبيق مصمم خصيصاً لاختبار نظام الذكي الاصطناعي لكشف الهجمات السيبرانية
                                <br>
                                <small class="text-muted">يرجى استخدام هذا التطبيق فقط لأغراض تعليمية وتوضيحية</small>
                            </p>
                        </div>
                        
                        <div class="warning-box">
                            <h5>🚨 تحذير مهم</h5>
                            <p class="mb-0">
                                هذا التطبيق يحتوي على ثغرات أمنية مقصودة لأغراض التعليم والعرض التوضيحي فقط.
                                <strong>لا تستخدم هذا الكود في بيئة الإنتاج أبداً!</strong>
                            </p>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-4">
                                <div class="demo-card card h-100">
                                    <div class="card-header bg-danger text-white">
                                        <h5><i class="bi bi-database-slash"></i> 💉 هجوم حقن SQL</h5>
                                    </div>
                                    <div class="card-body">
                                        <form action="/login" method="post">
                                            <div class="mb-3">
                                                <label class="form-label">اسم المستخدم:</label>
                                                <input type="text" name="username" class="form-control" 
                                                       placeholder="أدخل اسم المستخدم" required>
                                            </div>
                                            <div class="mb-3">
                                                <label class="form-label">كلمة المرور:</label>
                                                <input type="password" name="password" class="form-control" 
                                                       placeholder="أدخل كلمة المرور" required>
                                            </div>
                                            <button type="submit" class="btn btn-primary w-100">تسجيل الدخول</button>
                                        </form>
                                        
                                        <hr>
                                        <h6>أمثلة للاختبار:</h6>
                                        <div class="attack-example">admin' OR '1'='1-- </div>
                                        <div class="attack-example">admin'; DROP TABLE users; --</div>
                                        <small class="text-muted">انسخ والصق في حقل اسم المستخدم</small>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-6 mb-4">
                                <div class="demo-card card h-100">
                                    <div class="card-header bg-warning text-dark">
                                        <h5><i class="bi bi-code-slash"></i> 🎯 هجوم XSS</h5>
                                    </div>
                                    <div class="card-body">
                                        <form action="/comment" method="post">
                                            <div class="mb-3">
                                                <label class="form-label">اكتب تعليقك:</label>
                                                <textarea name="comment" class="form-control" rows="4" 
                                                         placeholder="شارك رأيك هنا..." required></textarea>
                                            </div>
                                            <button type="submit" class="btn btn-success w-100">إرسال التعليق</button>
                                        </form>
                                        
                                        <hr>
                                        <h6>أمثلة للاختبار:</h6>
                                        <div class="attack-example">&lt;script&gt;alert('XSS')&lt;/script&gt;</div>
                                        <div class="attack-example">&lt;img src=x onerror=alert('Hacked!')&gt;</div>
                                        <small class="text-muted">انسخ والصق في حقل التعليق</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6 mb-4">
                                <div class="demo-card card h-100">
                                    <div class="card-header bg-info text-white">
                                        <h5><i class="bi bi-search"></i> 🔍 البحث (SQL Injection)</h5>
                                    </div>
                                    <div class="card-body">
                                        <form action="/search" method="get">
                                            <div class="mb-3">
                                                <label class="form-label">ابحث عن منتج:</label>
                                                <input type="text" name="q" class="form-control" 
                                                       placeholder="أدخل اسم المنتج">
                                            </div>
                                            <button type="submit" class="btn btn-outline-primary w-100">بحث</button>
                                        </form>
                                        
                                        <hr>
                                        <h6>أمثلة للاختبار:</h6>
                                        <div class="attack-example">
                                            ' UNION SELECT username,password,email,role FROM users--
                                        </div>
                                        <small class="text-muted">للحصول على بيانات المستخدمين</small>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="col-md-6 mb-4">
                                <div class="demo-card card h-100">
                                    <div class="card-header bg-secondary text-white">
                                        <h5><i class="bi bi-folder2-open"></i> 📁 عرض الملفات</h5>
                                    </div>
                                    <div class="card-body">
                                        <form action="/file" method="get">
                                            <div class="mb-3">
                                                <label class="form-label">اسم الملف:</label>
                                                <input type="text" name="filename" class="form-control" 
                                                       placeholder="أدخل مسار الملف">
                                            </div>
                                            <button type="submit" class="btn btn-outline-secondary w-100">عرض الملف</button>
                                        </form>
                                        
                                        <hr>
                                        <h6>أمثلة للاختبار:</h6>
                                        <div class="attack-example">../../../etc/passwd</div>
                                        <div class="attack-example">..\\..\\..\\windows\\system32\\drivers\\etc\\hosts</div>
                                        <small class="text-muted">Directory Traversal Attack</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="row">
                            <div class="col-12">
                                <div class="demo-card card">
                                    <div class="card-header bg-dark text-white">
                                        <h5>🎮 إرشادات العرض التوضيحي</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="row">
                                            <div class="col-md-4">
                                                <h6>1️⃣ تسجيل الدخول بثغرة SQL:</h6>
                                                <p>استخدم: <code>admin' OR '1'='1-- </code> في حقل اسم المستخدم</p>
                                            </div>
                                            <div class="col-md-4">
                                                <h6>2️⃣ هجوم XSS:</h6>
                                                <p>استخدم: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> في التعليق</p>
                                            </div>
                                            <div class="col-md-4">
                                                <h6>3️⃣ استخراج البيانات:</h6>
                                                <p>استخدم: <code>' UNION SELECT username,password,email,role FROM users--</code> في البحث</p>
                                            </div>
                                        </div>
                                        
                                        <hr>
                                        <div class="alert alert-info">
                                            <h6>💡 نصائح للعرض التوضيحي:</h6>
                                            <ul class="mb-0">
                                                <li>افتح <a href="http://0.0.0.0:5000" target="_blank">لوحة مراقبة الأمان</a> في نافذة منفصلة</li>
                                                <li>جرب الهجمات المختلفة وراقب التنبيهات الفورية</li>
                                                <li>استخدم أزرار السيناريوهات في لوحة التحكم لمحاكاة هجمات متقدمة</li>
                                                <li>اشرح كيف يكشف الذكي الاصطناعي كل نوع من أنواع الهجمات</li>
                                            </ul>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="text-center mt-4">
                            <div class="btn-group" role="group">
                                <a href="/admin" class="btn btn-outline-danger">👨‍💼 لوحة الإدارة</a>
                                <a href="/dashboard" class="btn btn-outline-primary">📊 لوحة المستخدم</a>
                                <a href="http://0.0.0.0:5000" target="_blank" class="btn btn-success">
                                    🛡️ مراقب الأمان AI
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    ''')

# VULNERABLE LOGIN - SQL Injection
@vulnerable_app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE: Direct SQL injection
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # This is intentionally vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        result_html = f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <title>نتيجة تسجيل الدخول</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="card">
                    <div class="card-header bg-{'success' if user else 'danger'} text-white">
                        <h3>{'✅ نجح تسجيل الدخول' if user else '❌ فشل تسجيل الدخول'}</h3>
                    </div>
                    <div class="card-body">
                        <p><strong>الاستعلام المنفذ:</strong></p>
                        <pre class="bg-dark text-light p-3">{query}</pre>
                        
                        {'<div class="alert alert-success"><h5>مرحباً ' + user[1] + '!</h5><p>الدور: ' + user[4] + '</p></div>' if user else '<div class="alert alert-danger">بيانات دخول خاطئة</div>'}
                        
                        <a href="/" class="btn btn-primary">العودة للصفحة الرئيسية</a>
                        <a href="http://0.0.0.0:5000" target="_blank" class="btn btn-warning">مراقبة النظام</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        if user:
            session['user'] = user[1]  # username
            session['role'] = user[4]  # role
            
        return result_html
        
    except Exception as e:
        return f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <title>خطأ في قاعدة البيانات</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="card border-danger">
                    <div class="card-header bg-danger text-white">
                        <h3>💥 خطأ في قاعدة البيانات</h3>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-danger">
                            <strong>الخطأ:</strong> {str(e)}
                        </div>
                        <p><strong>الاستعلام:</strong></p>
                        <pre class="bg-dark text-light p-3">{query}</pre>
                        <a href="/" class="btn btn-primary">العودة</a>
                        <a href="http://0.0.0.0:5000" target="_blank" class="btn btn-warning">مراقبة النظام</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

# VULNERABLE SEARCH - SQL Injection  
@vulnerable_app.route('/search')
def search():
    query = request.args.get('q', '')
    
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    
    # VULNERABLE: SQL injection in search
    sql = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
    
    try:
        cursor.execute(sql)
        results = cursor.fetchall()
        conn.close()
        
        html = f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <title>نتائج البحث</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h3>🔍 نتائج البحث عن: {query}</h3>
                    </div>
                    <div class="card-body">
                        <p><strong>الاستعلام المنفذ:</strong></p>
                        <pre class="bg-dark text-light p-3">{sql}</pre>
                        
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead class="table-dark">
                                    <tr><th>ID</th><th>الاسم</th><th>السعر</th><th>الوصف</th></tr>
                                </thead>
                                <tbody>
        """
        
        for row in results:
            html += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td></tr>"
        
        html += """
                                </tbody>
                            </table>
                        </div>
                        
                        <div class="mt-3">
                            <a href="/" class="btn btn-primary">العودة للصفحة الرئيسية</a>
                            <a href="http://0.0.0.0:5000" target="_blank" class="btn btn-warning">مراقبة النظام</a>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        return html
        
    except Exception as e:
        return f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <title>خطأ في البحث</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="card border-danger">
                    <div class="card-header bg-danger text-white">
                        <h3>💥 خطأ في البحث</h3>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-danger">
                            <strong>الخطأ:</strong> {str(e)}
                        </div>
                        <p><strong>الاستعلام:</strong></p>
                        <pre class="bg-dark text-light p-3">{sql}</pre>
                        <a href="/" class="btn btn-primary">العودة</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

# VULNERABLE COMMENTS - XSS
@vulnerable_app.route('/comment', methods=['POST'])
def comment():
    comment = request.form['comment']
    
    # VULNERABLE: No XSS protection
    html = f"""
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <title>تعليقك</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-success text-white">
                    <h3>💬 تم إرسال تعليقك</h3>
                </div>
                <div class="card-body">
                    <div class="alert alert-warning">
                        <strong>⚠️ تحذير:</strong> هذا التعليق يُعرض بدون أي حماية من XSS
                    </div>
                    
                    <div class="border p-3 mb-3 bg-white">
                        <h5>تعليقك:</h5>
                        {comment}
                    </div>
                    
                    <a href="/" class="btn btn-primary">العودة للصفحة الرئيسية</a>
                    <a href="http://0.0.0.0:5000" target="_blank" class="btn btn-warning">مراقبة النظام</a>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html

# VULNERABLE FILE ACCESS - Directory Traversal
@vulnerable_app.route('/file')
def file_access():
    filename = request.args.get('filename', '')
    
    try:
        # VULNERABLE: No path validation
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <title>عرض الملف</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="card">
                    <div class="card-header bg-info text-white">
                        <h3>📁 محتوى الملف: {filename}</h3>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-warning">
                            <strong>⚠️ تحذير:</strong> هذا التطبيق يسمح بالوصول لأي ملف في النظام!
                        </div>
                        
                        <pre class="bg-dark text-light p-3" style="max-height: 400px; overflow-y: auto;">{content}</pre>
                        
                        <div class="mt-3">
                            <a href="/" class="btn btn-primary">العودة للصفحة الرئيسية</a>
                            <a href="http://0.0.0.0:5000" target="_blank" class="btn btn-warning">مراقبة النظام</a>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
    except Exception as e:
        return f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <title>خطأ في الملف</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="card border-danger">
                    <div class="card-header bg-danger text-white">
                        <h3>💥 خطأ في الوصول للملف</h3>
                    </div>
                    <div class="card-body">
                        <div class="alert alert-danger">
                            <strong>الخطأ:</strong> {str(e)}
                        </div>
                        <p><strong>الملف المطلوب:</strong> {filename}</p>
                        <a href="/" class="btn btn-primary">العودة</a>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """

@vulnerable_app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('home'))
    
    return f"""
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <title>لوحة المستخدم</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-primary text-white">
                    <h3>👤 لوحة المستخدم</h3>
                </div>
                <div class="card-body">
                    <h4>مرحباً، {session['user']}!</h4>
                    <p><strong>الدور:</strong> {session.get('role', 'user')}</p>
                    
                    <div class="mt-3">
                        <a href="/logout" class="btn btn-danger">تسجيل الخروج</a>
                        <a href="/" class="btn btn-primary">الصفحة الرئيسية</a>
                        <a href="http://0.0.0.0:5000" target="_blank" class="btn btn-success">مراقب الأمان</a>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

@vulnerable_app.route('/admin')
def admin():
    # VULNERABLE: No proper authorization check
    return f"""
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <title>لوحة الإدارة</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-danger text-white">
                    <h3>👨‍💼 لوحة الإدارة</h3>
                </div>
                <div class="card-body">
                    <div class="alert alert-warning">
                        <strong>⚠️ ثغرة أمنية:</strong> يمكن لأي شخص الوصول لهذه الصفحة!
                    </div>
                    
                    <h4>مرحباً بك في لوحة الإدارة</h4>
                    <p>هذه الصفحة يجب أن تكون محمية ولكنها متاحة للجميع!</p>
                    
                    <ul class="list-group mb-3">
                        <li class="list-group-item">
                            <a href="/admin/users" class="text-decoration-none">👥 عرض المستخدمين</a>
                        </li>
                        <li class="list-group-item">
                            <a href="/admin/logs" class="text-decoration-none">📋 عرض السجلات</a>
                        </li>
                    </ul>
                    
                    <div class="mt-3">
                        <a href="/" class="btn btn-primary">الصفحة الرئيسية</a>
                        <a href="http://0.0.0.0:5000" target="_blank" class="btn btn-success">مراقب الأمان</a>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

@vulnerable_app.route('/admin/users')
def admin_users():
    conn = sqlite3.connect('vulnerable.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    
    html = """
    <!DOCTYPE html>
    <html dir="rtl" lang="ar">
    <head>
        <meta charset="UTF-8">
        <title>قائمة المستخدمين</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-5">
            <div class="card">
                <div class="card-header bg-warning text-dark">
                    <h3>👥 جميع المستخدمين</h3>
                </div>
                <div class="card-body">
                    <div class="alert alert-danger">
                        <strong>🚨 خطر أمني:</strong> كلمات المرور معروضة بوضوح!
                    </div>
                    
                    <div class="table-responsive">
                        <table class="table table-striped">
                            <thead class="table-dark">
                                <tr>
                                    <th>ID</th><th>اسم المستخدم</th><th>كلمة المرور</th><th>البريد الإلكتروني</th><th>الدور</th>
                                </tr>
                            </thead>
                            <tbody>
    """
    
    for user in users:
        html += f"<tr><td>{user[0]}</td><td>{user[1]}</td><td><code>{user[2]}</code></td><td>{user[3]}</td><td>{user[4]}</td></tr>"
    
    html += """
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="mt-3">
                        <a href="/admin" class="btn btn-secondary">العودة للإدارة</a>
                        <a href="/" class="btn btn-primary">الصفحة الرئيسية</a>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return html

@vulnerable_app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    print("🎯 Starting Vulnerable Web Application for AI Security Demo")
    print("🌐 Available at: http://0.0.0.0:3000")
    print("⚠️  WARNING: This application contains intentional security vulnerabilities!")
    print("📊 Monitor attacks at: http://0.0.0.0:5000")
    vulnerable_app.run(host="0.0.0.0", port=3000, debug=False, use_reloader=False)
