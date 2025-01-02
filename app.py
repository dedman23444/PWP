from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm, UserForm
from models import db, User

app = Flask(__name__)

# Konfigurasi koneksi MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  # Ganti dengan username MySQL Anda
app.config['MYSQL_PASSWORD'] = ''  # Ganti dengan password MySQL Anda
app.config['MYSQL_DB'] = 'user_management'
app.secret_key = 'your_secret_key'  # Ganti dengan secret key Anda

mysql = MySQL(app)

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(username, email, password_hash) VALUES(%s, %s, %s)", 
                    (form.username.data, form.email.data, hashed_password))
        mysql.connection.commit()
        cur.close()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (form.email.data,))
        user = cur.fetchone()
        cur.close()
        if user and check_password_hash(user[3], form.password.data):  # user[3] adalah password_hash
            session['user_id'] = user[0]  # user[0] adalah id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    cur.close()
    return render_template('dashboard.html', users=users)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    form = UserForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(username, email, password_hash) VALUES(%s, %s, %s)", 
                    (form.username.data, form.email.data, hashed_password))
        mysql.connection.commit()
        cur.close()
        flash('User  added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_user.html', form=form)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    form = UserForm(obj=user)
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256') if form.password.data else user[3]
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET username = %s, email = %s, password_hash = %s WHERE id = %s", 
                    (form.username.data, form.email.data, hashed_password, user_id))
        mysql.connection.commit()
        cur.close()
        flash('User  updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_user.html', form=form, user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash('User  deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)