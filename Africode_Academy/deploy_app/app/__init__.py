from flask import Flask
from .routes.todo import todo_bp
from .extensions import db

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    db.init_app(app)
    app.register_blueprint(todo_bp)
    return app
