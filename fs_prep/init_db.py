#!/usr/bin/env python3
"""
Initialize database with basic roles and a test user.
Run this script after setting up the database.
"""

from app import create_app
from app.extensions import db
from app.models.user import User, Role
from flask_security.utils import hash_password
import uuid

def init_database():
    """Initialize database with basic roles and test user."""
    app = create_app()
    
    with app.app_context():
        # Create tables
        db.create_all()
        
        # Create roles if they don't exist
        roles_to_create = [
            ('Citizen', 'Regular citizen user'),
            ('Department Officer', 'Officer in specific departments'),
            ('County Admin', 'County administrator with full access')
        ]
        
        for role_name, role_desc in roles_to_create:
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                role = Role(name=role_name, description=role_desc)
                db.session.add(role)
                print(f"Created role: {role_name}")
        
        # Create a test user if it doesn't exist
        test_email = 'admin@test.com'
        user = User.query.filter_by(email=test_email).first()
        
        if not user:
            # Get the County Admin role
            admin_role = Role.query.filter_by(name='County Admin').first()
            
            user = User(
                email=test_email,
                password=hash_password('password123'),
                first_name='Test',
                last_name='Admin',
                active=True,
                fs_uniquifier=str(uuid.uuid4())
            )
            
            if admin_role:
                user.roles.append(admin_role)
            
            db.session.add(user)
            print(f"Created test user: {test_email} with password: password123")
        
        # Commit all changes
        db.session.commit()
        print("Database initialization completed!")
        
        # Print summary
        total_users = User.query.count()
        total_roles = Role.query.count()
        print(f"\nDatabase Summary:")
        print(f"- Total Users: {total_users}")
        print(f"- Total Roles: {total_roles}")
        print(f"- Test user credentials: admin@test.com / password123")

if __name__ == '__main__':
    init_database()
