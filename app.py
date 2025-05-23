from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Thay bằng key bí mật mạnh hơn trong sản xuất

# Khởi tạo database
def init_db():
    conn = sqlite3.connect('todo.db')
    c = conn.cursor()
    # Bảng users với cột name
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  email TEXT NOT NULL UNIQUE,
                  password TEXT NOT NULL)''')
    # Bảng todos với cột completed_at
    c.execute('''CREATE TABLE IF NOT EXISTS todos
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  task TEXT NOT NULL,
                  completed BOOLEAN NOT NULL,
                  created_at TIMESTAMP,
                  completed_at TIMESTAMP,
                  user_id INTEGER,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    conn.commit()
    conn.close()

init_db()

# Kiểm tra người dùng đã đăng nhập
def login_required(f):
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Vui lòng đăng nhập trước!', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/')
@login_required
def index():
    conn = sqlite3.connect('todo.db')
    c = conn.cursor()
    # Lấy tên người dùng
    c.execute('SELECT name FROM users WHERE id = ?', (session['user_id'],))
    user_name = c.fetchone()[0]
    # Lấy danh sách công việc
    c.execute('SELECT id, task, completed, created_at, completed_at FROM todos WHERE user_id = ? ORDER BY created_at DESC',
              (session['user_id'],))
    todos = c.fetchall()
    conn.close()
    return render_template('index.html', todos=todos, user_name=user_name)

@app.route('/add', methods=['POST'])
@login_required
def add_todo():
    task = request.form.get('task')
    if task:
        conn = sqlite3.connect('todo.db')
        c = conn.cursor()
        c.execute('INSERT INTO todos (task, completed, created_at, user_id) VALUES (?, ?, ?, ?)',
                  (task, False, datetime.now(), session['user_id']))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

@app.route('/complete/<int:id>')
@login_required
def complete_todo(id):
    conn = sqlite3.connect('todo.db')
    c = conn.cursor()
    c.execute('UPDATE todos SET completed = ?, completed_at = ? WHERE id = ? AND user_id = ?',
              (True, datetime.now(), id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['POST'])
@login_required
def edit_todo(id):
    new_task = request.form.get('new_task')
    if new_task:
        conn = sqlite3.connect('todo.db')
        c = conn.cursor()
        c.execute('UPDATE todos SET task = ? WHERE id = ? AND user_id = ?',
                  (new_task, id, session['user_id']))
        conn.commit()
        conn.close()
        flash('Cập nhật công việc thành công!', 'success')
    return redirect(url_for('index'))

@app.route('/delete/<int:id>')
@login_required
def delete_todo(id):
    conn = sqlite3.connect('todo.db')
    c = conn.cursor()
    c.execute('DELETE FROM todos WHERE id = ? AND user_id = ?', (id, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if name and email and password and confirm_password:
            if password != confirm_password:
                flash('Mật khẩu xác nhận không khớp!', 'error')
            else:
                conn = sqlite3.connect('todo.db')
                c = conn.cursor()
                try:
                    c.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                              (name, email, generate_password_hash(password)))
                    conn.commit()
                    flash('Đăng ký thành công! Vui lòng đăng nhập.', 'success')
                    return redirect(url_for('login'))
                except sqlite3.IntegrityError:
                    flash('Email đã tồn tại!', 'error')
                finally:
                    conn.close()
        else:
            flash('Vui lòng nhập đầy đủ thông tin!', 'error')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = sqlite3.connect('todo.db')
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            flash('Đăng nhập thành công!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email hoặc mật khẩu không đúng!', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Đã đăng xuất!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)