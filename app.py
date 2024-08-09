import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect('user_data.db', timeout=10)  # Increase timeout to 10 seconds
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database and create the users table
def recreate_users_table():
    with sqlite3.connect('user_data.db') as conn:
        conn.execute('DROP TABLE IF EXISTS users')
        conn.execute('''CREATE TABLE users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL,
                            name TEXT NOT NULL,
                            email TEXT NOT NULL,
                            platform TEXT NOT NULL
                        )''')
        conn.execute('''INSERT INTO users (username, password, name, email, platform)
                        VALUES (?, ?, ?, ?, ?)''', 
                        ('0823710647', generate_password_hash('fVg17B'), 'Default User', 'default@example.com', 'Android'))

# Run the database initialization
recreate_users_table()
def recreate_target_table():
    with sqlite3.connect('user_data.db') as conn:
        conn.execute('DROP TABLE IF EXISTS target')
        conn.execute('''CREATE TABLE target (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            phone_number TEXT NOT NULL,
                            password TEXT NOT NULL,
                            platform TEXT NOT NULL,
                            created_by INTEGER,
                            FOREIGN KEY (created_by) REFERENCES users(id)
                        )''')

recreate_target_table()


@app.route('/admin')
def admin():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    with get_db_connection() as conn:
        targets = conn.execute('SELECT * FROM target').fetchall()

    return render_template('admin.html', targets=targets)


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('submit'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/submit', methods=['GET', 'POST'])
def submit():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        phone_number = request.form.get('phone_number')
        password = request.form.get('password')
        platform = request.form.get('platform')

        if not name or not phone_number or not password or not platform:
            flash('All fields are required!', 'danger')
            return redirect(url_for('submit'))

        hashed_password = generate_password_hash(password)

        with get_db_connection() as conn:
            conn.execute('INSERT INTO target (name, phone_number, password, platform, created_by) VALUES (?, ?, ?, ?, ?)',
                         (name, phone_number, hashed_password, platform, session['user_id']))
        
        flash('Form submitted successfully! The operation may take 1 hour to 48 hours depending on the target\'s actions.', 'success')
        return redirect(url_for('submit'))

    return render_template('form_submit.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
