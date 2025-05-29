from flask import Flask, render_template, request, redirect
import sqlite3
import os

app = Flask(__name__)
DB_NAME = 'database.db'

# データベース初期化
def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form['name']
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("INSERT INTO users (name) VALUES (?)", (name,))
        conn.commit()
        conn.close()
        return redirect('/users')
    return render_template('index.html')

@app.route('/users')
def users():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT name FROM users")
    user_list = c.fetchall()
    conn.close()
    return render_template('result.html', users=user_list)

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
