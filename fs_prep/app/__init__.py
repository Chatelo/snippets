from flask import Flask
from app.extensions import db, migrate, security, mail
from config import Config


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    
    # Import models after db initialization
    from app.models.user import User, Role
    
    # Setup Flask-Security
    from flask_security import SQLAlchemyUserDatastore
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security.init_app(app, user_datastore)

    from app.main.views import main_bp
    from app.auth.routes import auth_bp
    from app.api.routes import api_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(api_bp, url_prefix='/api')


    with app.app_context():
        db.create_all()
    print("Creating database tables...")

    return app