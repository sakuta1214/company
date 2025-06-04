import os
import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# アプリ初期化
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '1214')

# PostgreSQL接続設定（Renderでは DATABASE_URL を環境変数で設定）
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# -------------------------------
# モデル定義
# -------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100))
    position = db.Column(db.String(100))

# -------------------------------
# ログイン必須デコレーター
# -------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# -------------------------------
# 初期化処理（DB作成＆管理者登録）
# -------------------------------

with app.app_context():
    db.create_all()

    admin_username = os.environ.get('ADMIN_USERNAME')
    admin_password = os.environ.get('ADMIN_PASSWORD')
    if admin_username and admin_password:
        existing_admin = User.query.filter_by(username=admin_username).first()
        if not existing_admin:
            hashed_pw = generate_password_hash(admin_password)
            new_admin = User(username=admin_username, password_hash=hashed_pw, is_admin=True)
            db.session.add(new_admin)
            db.session.commit()
            print(f"管理者ユーザー「{admin_username}」を作成しました。")

# -------------------------------
# ルーティング
# -------------------------------

@app.route('/')
def home_redirect():
    return redirect(url_for('company_home'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    now = datetime.datetime.now()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('employee_list'))
        else:
            flash('ユーザー名かパスワードが間違っています。')
    return render_template('login.html', now=now)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home_redirect'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    now = datetime.datetime.now()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing = User.query.filter_by(username=username).first()
        if existing:
            flash('そのユーザー名はすでに登録されています。')
            return render_template('register.html', now=now)
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        flash('登録が完了しました。ログインしてください。')
        return redirect(url_for('login'))
    return render_template('register.html', now=now)

@app.route('/employees')
@login_required
def employee_list():
    now = datetime.datetime.now()
    employees = Employee.query.all()
    return render_template('employees/list.html', employees=employees, now=now)

@app.route('/employees/new', methods=['GET', 'POST'])
@login_required
def employee_new():
    now = datetime.datetime.now()
    if request.method == 'POST':
        employee = Employee(
            name=request.form['name'],
            email=request.form['email'],
            department=request.form['department'],
            position=request.form['position']
        )
        db.session.add(employee)
        db.session.commit()
        flash('社員を登録しました。')
        return redirect(url_for('employee_list'))
    return render_template('employees/new.html', now=now)

@app.route('/employees/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def employee_edit(id):
    now = datetime.datetime.now()
    employee = Employee.query.get_or_404(id)
    if request.method == 'POST':
        employee.name = request.form['name']
        employee.email = request.form['email']
        employee.department = request.form['department']
        employee.position = request.form['position']
        db.session.commit()
        flash('社員情報を更新しました。')
        return redirect(url_for('employee_list'))
    return render_template('employees/edit.html', employee=employee, now=now)

@app.route('/employees/delete/<int:id>', methods=['POST'])
@login_required
def employee_delete(id):
    employee = Employee.query.get_or_404(id)
    db.session.delete(employee)
    db.session.commit()
    flash('社員情報を削除しました。')
    return redirect(url_for('employee_list'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    now = datetime.datetime.now()
    if request.method == 'POST':
        current_pw = request.form['current_password']
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']

        if new_pw != confirm_pw:
            flash('新しいパスワードと確認用パスワードが一致しません。')
            return redirect(url_for('change_password'))

        user = User.query.get(session['user_id'])
        if not user or not check_password_hash(user.password_hash, current_pw):
            flash('現在のパスワードが正しくありません。')
            return redirect(url_for('change_password'))

        user.password_hash = generate_password_hash(new_pw)
        db.session.commit()
        flash('パスワードを変更しました。')
        return redirect(url_for('employee_list'))
    return render_template('change_password.html', now=now)

# -------------------------------
# 会社ページ
# -------------------------------

@app.route('/company')
def company_home():
    return render_template('company/home.html', now=datetime.datetime.now())

@app.route('/company/about')
def company_about():
    return render_template('company/about.html', now=datetime.datetime.now())

@app.route('/company/services')
def company_services():
    return render_template('company/services.html', now=datetime.datetime.now())

@app.route('/company/contact')
def company_contact():
    return render_template('company/contact.html', now=datetime.datetime.now())

@app.route('/company/recruit')
def company_recruit():
    return render_template('company/recruit.html', now=datetime.datetime.now())

# -------------------------------
# 実行
# -------------------------------

if __name__ == '__main__':
    app.run(debug=True)
