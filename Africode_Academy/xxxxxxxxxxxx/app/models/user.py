from app.extensions import db
from flask_security import UserMixin, RoleMixin
import uuid


# This is an association table for the many-to-many relationship - between users and roles

roles_users = db.Table('roles_users', 
                       db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
                       db.Column('role_id', db.Integer, db.ForeignKey('roles.id'))
                       )

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    # This is basic identity fileds that comes with Flask-Security
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    # Profile information
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    phone = db.Column(db.String(20))

    # Account status fields
    active = db.Column(db.Boolean(), default=True)
    confirmed_at = db.Column(db.DateTime())
    created_at = db.Column(db.DateTime(), default=db.func.current_timestamp())

    #Flask-security reqired field for tokens, session, password management
    fs_uniquifier = db.Column(db.String(64), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))

    # County and department relationships                                     
    county_id = db.Column(db.Integer, db.ForeignKey('counties.id'))           
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id')) 
    
    # Tracking fields
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(45))
    current_login_ip = db.Column(db.String(45))
    login_count = db.Column(db.Integer, default=0)

    # Relationships
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

    def __repr__(self):
        return f'User {self.email} {self.roles}'
    
    def full_name(self):
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.email.split('@')[0] #Fallback if the user dont provide first_name or last_name or both
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)
    
    def get_primary_role(self):
        """Get the user's primary role for display purposes"""
        if self.has_role('super_admin'):
            return 'Super Admin'
        elif self.has_role('staff'):
            return 'Staff'
        elif self.has_role('citizen'):
            return 'Citizen'
        elif self.has_role('guest'):
            return 'Guest'
        else:
            return 'No Role Assigned'
    
    def can_manage_users(self):
        """Check if user can manage other users"""
        return self.has_role('super_admin')
    
    def can_access_county(self, county_id):
        """Check if user can access data for a specific county"""
        if self.has_role('super_admin'):
            return True
        return self.county_id == county_id


class Role(db.Model, RoleMixin):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'Role {self.name}'




