from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


"""
Admin
dECWzMz~N9EAlsD
dECWzMz~N9EAlsD
"""
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Data.db'
app.config['SECRET_KEY'] = '%ZK5uE8y}%AtBwN'
# hashes the password and then stores in the database
app.config['SECURITY_PASSWORD_SALT'] = "vG}KjS0Uh#gOyHY"
# allows new registrations to application
app.config['SECURITY_REGISTERABLE'] = True
# to send automatic registration email to user
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
db = SQLAlchemy(app)
manager = LoginManager(app)

import routes
import models