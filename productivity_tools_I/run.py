import os
from app import create_app
from app.models import db
from flask_migrate import Migrate

# Create Flask application
app = create_app()

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Create CLI commands for database management
@app.cli.command()
def create_db():
    """Create database tables."""
    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")

@app.cli.command()
def drop_db():
    """Drop all database tables."""
    with app.app_context():
        db.drop_all()
        print("Database tables dropped successfully!")

@app.cli.command()
def reset_db():
    """Reset database - drop all tables and recreate them."""
    with app.app_context():
        db.drop_all()
        db.create_all()
        print("Database reset successfully!")

if __name__ == '__main__':
    # Set environment variables for development
    os.environ.setdefault('FLASK_ENV', 'development')
    os.environ.setdefault('SECRET_KEY', 'dev-secret-key-change-in-production')
    os.environ.setdefault('SECURITY_PASSWORD_SALT', 'dev-password-salt-change-in-production')
    
    app.run(debug=True, host='0.0.0.0', port=5000)
