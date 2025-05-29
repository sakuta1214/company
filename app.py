from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # 適宜変更してください

DATABASE = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        department TEXT,
        position TEXT
    )
    ''')
    conn.commit()

    user = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
    if not user:
        password_hash = generate_password_hash('admin123')
        conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', ('admin', password_hash))
        conn.commit()
    conn.close()

init_db()

@app.route('/')
def home_redirect():
    return redirect(url_for('company_home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('employee_list'))
        else:
            flash('ユーザー名かパスワードが間違っています。')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home_redirect'))

@app.route('/employees')
@login_required
def employee_list():
    conn = get_db_connection()
    employees = conn.execute('SELECT * FROM employees').fetchall()
    conn.close()
    return render_template('employees/list.html', employees=employees)

@app.route('/employees/new', methods=['GET', 'POST'])
@login_required
def employee_new():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        department = request.form['department']
        position = request.form['position']
        conn = get_db_connection()
        conn.execute('INSERT INTO employees (name, email, department, position) VALUES (?, ?, ?, ?)',
                     (name, email, department, position))
        conn.commit()
        conn.close()
        flash('社員を登録しました。')
        return redirect(url_for('employee_list'))
    return render_template('employees/new.html')

@app.route('/employees/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def employee_edit(id):
    conn = get_db_connection()
    employee = conn.execute('SELECT * FROM employees WHERE id = ?', (id,)).fetchone()
    if not employee:
        flash('社員が見つかりません。')
        return redirect(url_for('employee_list'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        department = request.form['department']
        position = request.form['position']
        conn.execute('UPDATE employees SET name=?, email=?, department=?, position=? WHERE id=?',
                     (name, email, department, position, id))
        conn.commit()
        conn.close()
        flash('社員情報を更新しました。')
        return redirect(url_for('employee_list'))
    conn.close()
    return render_template('employees/edit.html', employee=employee)

@app.route('/employees/delete/<int:id>', methods=['POST'])
@login_required
def employee_delete(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM employees WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('社員情報を削除しました。')
    return redirect(url_for('employee_list'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_pw = request.form['current_password']
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']

        if new_pw != confirm_pw:
            flash('新しいパスワードと確認用パスワードが一致しません。')
            return redirect(url_for('change_password'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or not check_password_hash(user['password_hash'], current_pw):
            flash('現在のパスワードが正しくありません。')
            conn.close()
            return redirect(url_for('change_password'))

        new_hash = generate_password_hash(new_pw)
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, session['user_id']))
        conn.commit()
        conn.close()
        flash('パスワードを変更しました。')
        return redirect(url_for('employee_list'))
    return render_template('change_password.html')

@app.route('/company')
def company_home():
    return render_template('company/home.html')

@app.route('/company/about')
def company_about():
    return render_template('company/about.html')

@app.route('/company/services')
def company_services():
    return render_template('company/services.html')

@app.route('/company/contact')
def company_contact():
    # GETのみでフォーム表示のみ、POSTはFormspreeが処理するため削除
    return render_template('company/contact.html')

if __name__ == '__main__':
    app.run(debug=True)
