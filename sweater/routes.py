from flask import render_template, request, redirect, flash, url_for
from flask_login import login_user, login_required, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from sweater import app, db
from models import User, Games


@app.route('/')
def index():
    db.create_all()
    return render_template('index.html')





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
            return redirect(url_for('user_table'))
    return render_template('register.html')


@app.route('/Users')
def user_table():
    data = User.query.order_by(User.id).all()
    return render_template('Users.html', data=data)


@app.route('/EditUser/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    new_user = db.session.get(User, user_id)
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
        if not (login and first_name and last_name and dads_name and messenger and phone and email):
            flash('Please, fill all fields!')
            return render_template('EditUser.html', user=new_user)
        elif password != password2:
            flash('Passwords are not equal!')
            return render_template('EditUser.html', user=new_user)
        else:
            hash_pwd = generate_password_hash(password)
            new_user.login = login
            if password:
                new_user.password = hash_pwd
            new_user.first_name = first_name
            new_user.last_name = last_name
            new_user.dads_name = dads_name
            new_user.messenger = messenger
            new_user.phone = phone
            new_user.email = email

            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('user_table'))
    return render_template('EditUser.html', user=new_user)


@app.route('/DeleteUser/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    delete = db.session.get(User, user_id)
    db.session.delete(delete)
    db.session.commit()
    return redirect(url_for('user_table'))


@app.route('/Games')
def games_table():
    data = Games.query.order_by(Games.id).all()
    return render_template('Games.html', data=data)


@app.route('/CreateGame', methods=['GET', 'POST'])
def create_game():
    if request.method == 'POST':
        name = request.form.get('name')
        levels = request.form.get('levels')
        if not(name and levels):
            flash('Please, fill all fields!')
            return redirect(url_for('create_game'))
        else:
            new_game = Games()
            new_game.name = name
            new_game.levels = levels
            db.session.add(new_game)
            db.session.commit()
            return redirect(url_for('games_table'))
    return render_template('CreateGame.html')


@app.route('/EditGame/<int:user_id>', methods=['GET', 'POST'])
def edit_game(user_id):
    new_game = db.session.get(Games, user_id)
    if request.method == 'POST':
        name = request.form.get('name')
        levels = request.form.get('levels')
        if not (name and levels):
            flash('Please, fill all fields!')
            return render_template('EditGame.html', user=new_game)
        else:
            new_game.name = name
            new_game.levels = levels
            db.session.add(new_game)
            db.session.commit()
            return redirect(url_for('games_table'))
    return render_template('EditGame.html', game=new_game)


@app.route('/DeleteGame/<int:user_id>', methods=['GET', 'POST'])
def delete_game(user_id):
    delete = db.session.get(Games, user_id)
    db.session.delete(delete)
    db.session.commit()
    return redirect(url_for('games_table'))

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
