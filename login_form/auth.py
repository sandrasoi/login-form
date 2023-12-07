import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from login_form.db import get_db
from login_form.user import User

bp = Blueprint('auth', __name__, url_prefix='/')

def are_special_chars_included(password):
    if "!" in password or "@" in password or "#" in password or "$" in password or "%" in password or "&" in password:
        return True
    else:
        return False


def is_sufficient_length(password):
    # len(password) > 7 will evaluate to True or False
    return len(password) > 7


def is_valid(password):
    return is_sufficient_length(password) and are_special_chars_included(password)



@bp.route('/')
def index():
    return render_template('index.html')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        error = None

        if len(username) < 5:
            error = 'Username must be at least 5 characters.'
            flash(error)            
            return render_template('register.html', error=error)

        if is_valid(password) == False:
            error = 'Invalid password. Password must be at least 8 characters long and contain at least one special character.'
            flash(error)
            return render_template('register.html', error=error)

        if error is None:
            User.create(username, password)
            return redirect(url_for('auth.login'))

    return render_template('register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        error = None
        user = User.find_with_credentials(username, password)

        if user is None:
            error = 'Incorrect username or password.'

        if error is None:
            session.clear()
            session['user_id'] = user.id
            return redirect(url_for('auth.index'))

        flash(error)

    return render_template('login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = User.find_by_id(user_id)

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view