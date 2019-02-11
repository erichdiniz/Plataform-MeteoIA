"""Flask Login Example and instagram fallowing find"""

from flask import Flask, url_for, flash, render_template, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# database de usuários
class User(UserMixin, db.Model):
    """ Create user table"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(80), unique=True)
    name = db.Column(db.String(80))
    password = db.Column(db.String(80))
    authenticated = db.Column(db.Boolean, default=False)

    def __init__(self, username, password, email, name):
        self.username = username
        self.password = password
        self.email = email
        self.name = name

    def __repr__(self):
        return '<User %r>' % self.username


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# form de login de usuários
class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=5, max=20)], render_kw={'autofocus': True})
    password = PasswordField('password', validators=[InputRequired(),Length(min=8, max=80)])
    remember = BooleanField('remember me')


# form de registro de usuários
class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Email invalido, insira um e-mail valido')])
    username = StringField('username', validators=[InputRequired(), Length(min=5, max=20)], render_kw={'autofocus': True})
    password = PasswordField('password', validators=[InputRequired(),Length(min=8, max=80)])
    name = StringField('name', validators=[InputRequired(), Length(min=5, max=20)])


@app.route('/', strict_slashes=False, methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('home'))
        # return '<h1>' + form.username.data + '   ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)


@app.route('/register', strict_slashes=False, methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, name=form.name.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Usuário criado com sucesso!')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.xroute('/dash', strict_slashes=False , methods=['GET', 'POST'])
@login_required
def home():
    """ Session control"""
    if 'username' in session:
        return 'logado'
    else:
        return render_template('index.html', name=current_user.username)


@app.route("/logout", strict_slashes=False)
def logout():
    """Logout Form"""
    session.pop('username', None)
    session['logged_in'] = False
    return redirect(url_for('login'))


if __name__ == '__main__':
    db.create_all()
    app.secret_key = "sandedeska"
    app.run(debug=True)
app.secret_key = 'fn9uhf2983hpnf29ngf29-ngvujoqn3f-29gnf2rion'
