from flask import Blueprint, render_template, request, redirect, url_for
from app.models.todo import Todo
from app.extensions import db

todo_bp = Blueprint('todo', __name__)

@todo_bp.route('/')
def index():
    todos = Todo.query.all()
    return render_template('index.html', todos=todos)

@todo_bp.route('/add', methods=['POST'])
def add_todo():
    todo_title = request.form.get('todo')
    if todo_title:
        new_todo = Todo(title=todo_title)
        db.session.add(new_todo)
        db.session.commit()
    return redirect(url_for('todo.index'))
