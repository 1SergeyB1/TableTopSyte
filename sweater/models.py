from flask_login import UserMixin

from sweater import db, manager


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=True, unique=True)
    password = db.Column(db.String(128), nullable=True, unique=True)
    first_name = db.Column(db.String(128), nullable=True, unique=False)
    last_name = db.Column(db.String(128), nullable=True, unique=False)
    dads_name = db.Column(db.String(128), nullable=False, unique=False)
    messenger = db.Column(db.String(128), nullable=False, unique=True)
    phone = db.Column(db.String(128), nullable=True, unique=True)
    email = db.Column(db.String(128), nullable=True, unique=True)
    role = db.Column(db.String(128), nullable=True, unique=False, default='User')


class Games(db.Model):
    __tablename__ = 'games'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=True, unique=True)
    levels = db.Column(db.Integer, nullable=True)


class Achievements(db.Model):
    __tablename__ = 'achievements'
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey(Games.id))
    name = db.Column(db.String(128), nullable=True, unique=True)
    levels = db.Column(db.Integer, nullable=True)
    points = db.Column(db.Integer, nullable=True)


class Player(db.Model):
    __tablename__ = 'player'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    games = db.Column(db.JSON, default={})
    achievements = db.Column(db.JSON, default={})


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
