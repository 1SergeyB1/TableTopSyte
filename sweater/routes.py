from flask import render_template, request, redirect, flash, url_for
from flask_login import login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from sweater import app, db
from models import User


@app.route('/')
@login_required
def index():
    return 'aboba'


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)

            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            else:
                return redirect(url_for('index'))
        else:
            flash('Login or password is not correct')
    else:
        flash('Please fill login and password fields')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    db.create_all()
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        if not (login and password and password2):
            flash('Please, fill all fields!')
            return redirect(url_for('register'))
        elif password != password2:
            flash('Passwords are not equal!')
            return redirect(url_for('register'))
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User()
            new_user.login = login
            new_user.password = hash_pwd
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login_page'))
    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_page'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?=next=' + request.url)
    return response
