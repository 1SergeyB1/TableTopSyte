from flask import render_template, request, redirect, flash, url_for, g
from flask_login import login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from sweater import app, db
from models import User


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/Users')
def user_table():
    data = User.query.order_by(User.id).all()
    return render_template('Users.html', data=data)


@app.route('/get_admin/<int:user_id>')
def get_admin(user_id):
    user = db.session.get(User, user_id)
    user.role = 'Admin'
    return redirect('user_table')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            if user.role != 'Admin':
                return 'Ожидайте подтверждения учётной записи'
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
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        password2 = request.form.get('password2')

        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        dads_name = request.form.get('dads_name')
        messenger = request.form.get('messenger')
        phone = request.form.get('phone')
        email = request.form.get('email')
        if not (login and password and password2 and first_name and last_name and dads_name and messenger and phone and email):
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

            new_user.first_name = first_name
            new_user.last_name = last_name
            new_user.dads_name = dads_name
            new_user.messenger = messenger
            new_user.phone = phone
            new_user.email = email

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
