from flask import Blueprint, render_template, redirect, url_for
from flask_security import login_required, current_user

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Home page"""
    if current_user.is_authenticated:
        return redirect(url_for('main.chat'))
    return render_template('index.html')

@bp.route('/chat')
@login_required
def chat():
    """Chat interface"""
    return render_template('chat.html')

@bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')
