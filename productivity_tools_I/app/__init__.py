from flask import Flask, render_template
from flask_security import Security, SQLAlchemyUserDatastore
from flask_restful import Api
from flask_lucide import Lucide
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
import uuid

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_pyfile('config.py')
    
    # Initialize extensions
    from .models import db, User, Role
    
    db.init_app(app)
    
    # Initialize Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security = Security(app, user_datastore)
    
    # Initialize other extensions
    migrate = Migrate(app, db)
    lucide = Lucide(app)
    csrf = CSRFProtect(app)
    
    # Initialize API
    api = Api(app)
    
    # Register API routes
    from .routes.api import ChatResource, ChatHistoryResource
    api.add_resource(ChatResource, '/api/chat')
    api.add_resource(ChatHistoryResource, '/api/chat/history')
    
    # Register web routes
    from .routes import web_routes
    app.register_blueprint(web_routes.bp)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create default roles if they don't exist
        if not user_datastore.find_role('user'):
            user_datastore.create_role(name='user', description='Default user role')
        if not user_datastore.find_role('admin'):
            user_datastore.create_role(name='admin', description='Administrator role')
            
        # Ensure all users have fs_uniquifier
        for user in User.query.all():
            if not user.fs_uniquifier:
                user.fs_uniquifier = str(uuid.uuid4())
        
        db.session.commit()
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('404.html'), 404
        
    @app.errorhandler(500)
    def internal_error(error):
        return render_template('500.html'), 500
    
    return app
