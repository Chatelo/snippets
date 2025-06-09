# Copilot Instructions for County Services Portal Project
# County Services Portal Project
# This document provides guidelines for using Copilot effectively in the County Services Portal project.
# Project Overview
# County Services Portal Project
# This project aims to build a secure multi-role web platform for county services, allowing citizens to apply for permits, department officers to handle approvals, and county admins to manage users and settings. Access and actions are role-scoped per county and tied to workflow stages.

---

## 🏛️ County Services Portal — Project Overview

### 🎯 Objective:

Build a secure multi-role web platform where **citizens apply for permits**, **department officers handle approvals**, and a **county admin manages users and settings**. Access and actions are **role-scoped per county** and tied to **workflow stages**.

---

## 👥 User Roles and Permissions

| Role                   | Description                                                 | Permissions                                          |
| ---------------------- | ----------------------------------------------------------- | ---------------------------------------------------- |
| **County Admin**       | Appointed county system admin                               | Manage users, assign roles, view all permit requests |
| **Department Officer** | Officer in specific departments (e.g. Trade, Lands, Health) | Approve/reject permits for their department          |
| **Citizen**            | Regular user                                                | Apply for permits, view their status                 |

---

## 🛠️ Key Features

### 1. **Authentication & Role Management**

* Use `Flask-Security` for:

  * Registration/login
  * Role assignment (`Citizen`, `County Admin`, etc.)
  * Password reset & email confirmation

### 2. **Permit Application Workflow**

* Citizens can:

  * Submit different permit types (e.g., Business, Construction)
  * Track progress (Submitted → Under Review → Approved/Rejected)
* Officers can:

  * View only permits assigned to their **department**
  * Change status (with comment/history logging)
* County Admin can:

  * View **all permits**
  * Override/reassign officers if needed

### 3. **Role-Scoped Views**

* Officers see **only their department’s applications**
* Admins can **filter by county, department**
* Citizens see **only their own submissions**

### 4. **County-Scoped IAM**

* Each user is tied to a specific **county**
* Officers and admins can only act within their assigned county
* Multi-county support in future (e.g. national dashboard)

---

## ⚙️ Flask Application Factory & Blueprints

### App Factory (app/__init__.py)
```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore
from flask_migrate import Migrate
from flask_mail import Mail
from flask_bootstrap import Bootstrap
from flask_fontawesome import FontAwesome
from flask_moment import Moment
from config import Config

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
security = Security()
bootstrap = Bootstrap()
fontawesome = FontAwesome()
moment = Moment()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)
    bootstrap.init_app(app)
    fontawesome.init_app(app)
    moment.init_app(app)
    
    # Import models
    from app.models.user import User, Role
    from app.models.county import County, Department
    from app.models.permit import PermitApplication, PermitType
    
    # Setup Flask-Security
    user_datastore = SQLAlchemyUserDatastore(db, User, Role)
    security.init_app(app, user_datastore)
    
    # Register Blueprints
    from app.blueprints.main import bp as main_bp
    app.register_blueprint(main_bp)
    
    from app.blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    from app.blueprints.api import bp as api_bp
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    
    return app
```

### Configuration (config.py)
```python
import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'county_services.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Flask-Security settings
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT')
    SECURITY_REGISTERABLE = True
    SECURITY_RECOVERABLE = True
    SECURITY_TRACKABLE = True
    SECURITY_CHANGEABLE = True
    SECURITY_CONFIRMABLE = True
    SECURITY_SEND_REGISTER_EMAIL = False  # Set to True in production
    
    # Email settings
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
```

---

## 🎯 Blueprint Implementation

### 1. Main Blueprint (Frontend) - app/blueprints/main/__init__.py
```python
from flask import Blueprint

bp = Blueprint('main', __name__, template_folder='templates')

from app.blueprints.main import routes
```

### Main Routes (app/blueprints/main/routes.py)
```python
from flask import render_template, request, redirect, url_for, flash, current_app
from flask_security import login_required, roles_required, current_user
from app.blueprints.main import bp
from app.models.user import db, User
from app.models.permit import PermitApplication, PermitType
from app.models.county import County, Department

@bp.route('/')
def index():
    return render_template('main/index.html')

@bp.route('/dashboard')
@login_required
def dashboard():
    """Role-based dashboard"""
    if current_user.has_role('County Admin'):
        # Admin sees all permits in their county
        permits = PermitApplication.query.filter_by(
            county_id=current_user.county_id
        ).order_by(PermitApplication.submitted_at.desc()).all()
        return render_template('main/admin_dashboard.html', permits=permits)
    
    elif current_user.has_role('Department Officer'):
        # Officer sees only their department's permits
        permits = PermitApplication.query.filter_by(
            department_id=current_user.department_id,
            county_id=current_user.county_id
        ).order_by(PermitApplication.submitted_at.desc()).all()
        return render_template('main/officer_dashboard.html', permits=permits)
    
    else:  # Citizen
        # Citizens see only their own applications
        permits = current_user.permit_applications.order_by(
            PermitApplication.submitted_at.desc()
        ).all()
        return render_template('main/citizen_dashboard.html', permits=permits)

@bp.route('/apply', methods=['GET', 'POST'])
@login_required
def apply_permit():
    """Permit application form"""
    if request.method == 'POST':
        # Process permit application
        permit_type_id = request.form.get('permit_type_id')
        business_name = request.form.get('business_name')
        
        permit = PermitApplication(
            user_id=current_user.id,
            permit_type_id=permit_type_id,
            business_name=business_name,
            county_id=current_user.county_id,
            application_number=generate_application_number()
        )
        
        # Set department based on permit type
        permit_type = PermitType.query.get(permit_type_id)
        permit.department_id = permit_type.department_id
        
        db.session.add(permit)
        db.session.commit()
        
        flash('Application submitted successfully!', 'success')
        return redirect(url_for('main.dashboard'))
    
    permit_types = PermitType.query.join(Department).filter_by(
        county_id=current_user.county_id
    ).all()
    return render_template('main/apply.html', permit_types=permit_types)

@bp.route('/permit/<int:permit_id>/review', methods=['POST'])
@login_required
@roles_required('Department Officer', 'County Admin')
def review_permit(permit_id):
    """Officer reviews permit application"""
    permit = PermitApplication.query.get_or_404(permit_id)
    
    # Check authorization
    if current_user.has_role('Department Officer'):
        if permit.department_id != current_user.department_id:
            flash('Unauthorized access', 'error')
            return redirect(url_for('main.dashboard'))
    
    action = request.form.get('action')
    comment = request.form.get('comment')
    
    if action == 'approve':
        permit.add_status_change('Approved', current_user.id, comment)
        permit.approved_at = datetime.utcnow()
    elif action == 'reject':
        permit.add_status_change('Rejected', current_user.id, comment)
    
    db.session.commit()
    flash(f'Permit {action}d successfully', 'success')
    return redirect(url_for('main.dashboard'))

def generate_application_number():
    """Generate unique application number"""
    import random
    import string
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
```

### 2. Auth Blueprint - app/blueprints/auth/__init__.py
```python
from flask import Blueprint

bp = Blueprint('auth', __name__)

from app.blueprints.auth import routes
```

### Auth Routes (app/blueprints/auth/routes.py)
```python
from flask import render_template, request, redirect, url_for, flash
from flask_security import login_required, roles_required, current_user
from app.blueprints.auth import bp
from app.models.user import db, User, Role
from app.models.county import County, Department

@bp.route('/manage-users')
@login_required
@roles_required('County Admin')
def manage_users():
    """County admin manages users in their county"""
    users = User.query.filter_by(county_id=current_user.county_id).all()
    roles = Role.query.all()
    departments = Department.query.filter_by(county_id=current_user.county_id).all()
    return render_template('auth/manage_users.html', 
                         users=users, roles=roles, departments=departments)

@bp.route('/assign-role', methods=['POST'])
@login_required
@roles_required('County Admin')
def assign_role():
    """Assign role to user"""
    user_id = request.form.get('user_id')
    role_name = request.form.get('role_name')
    department_id = request.form.get('department_id')
    
    user = User.query.get(user_id)
    role = Role.query.filter_by(name=role_name).first()
    
    # Verify user is in same county
    if user.county_id != current_user.county_id:
        flash('Cannot manage users from other counties', 'error')
        return redirect(url_for('auth.manage_users'))
    
    # Clear existing roles and assign new one
    user.roles.clear()
    user.roles.append(role)
    
    # Assign department if it's an officer
    if role_name == 'Department Officer' and department_id:
        user.department_id = department_id
    
    db.session.commit()
    flash(f'Role assigned to {user.email}', 'success')
    return redirect(url_for('auth.manage_users'))
```

### 3. API Blueprint (Flask-RESTful) - app/blueprints/api/__init__.py
```python
from flask import Blueprint
from flask_restful import Api

bp = Blueprint('api', __name__)
api = Api(bp)

from app.blueprints.api import routes
```

### API Resources (app/blueprints/api/resources.py)
```python
from flask_restful import Resource, reqparse
from flask_security import auth_required, current_user, roles_required
from flask import jsonify
from app.models.permit import PermitApplication, PermitType
from app.models.county import County, Department
from app.models.user import db

class PermitListAPI(Resource):
    @auth_required('token')
    def get(self):
        """Get permits based on user role"""
        if current_user.has_role('County Admin'):
            permits = PermitApplication.query.filter_by(
                county_id=current_user.county_id
            ).all()
        elif current_user.has_role('Department Officer'):
            permits = PermitApplication.query.filter_by(
                department_id=current_user.department_id,
                county_id=current_user.county_id
            ).all()
        else:  # Citizen
            permits = current_user.permit_applications.all()
        
        return {
            'permits': [{
                'id': p.id,
                'application_number': p.application_number,
                'business_name': p.business_name,
                'status': p.status,
                'submitted_at': p.submitted_at.isoformat(),
                'department': p.department.name if p.department else None
            } for p in permits]
        }
    
    @auth_required('token')
    def post(self):
        """Create new permit application"""
        parser = reqparse.RequestParser()
        parser.add_argument('permit_type_id', type=int, required=True)
        parser.add_argument('business_name', type=str, required=True)
        parser.add_argument('application_data', type=dict)
        args = parser.parse_args()
        
        permit_type = PermitType.query.get(args['permit_type_id'])
        if not permit_type:
            return {'error': 'Invalid permit type'}, 400
        
        permit = PermitApplication(
            user_id=current_user.id,
            permit_type_id=args['permit_type_id'],
            business_name=args['business_name'],
            county_id=current_user.county_id,
            department_id=permit_type.department_id,
            application_data=json.dumps(args.get('application_data', {}))
        )
        
        db.session.add(permit)
        db.session.commit()
        
        return {'message': 'Application created', 'permit_id': permit.id}, 201

class PermitAPI(Resource):
    @auth_required('token')
    def get(self, permit_id):
        """Get specific permit details"""
        permit = PermitApplication.query.get_or_404(permit_id)
        
        # Check access permissions
        if not self._has_access(permit):
            return {'error': 'Unauthorized'}, 403
        
        return {
            'id': permit.id,
            'application_number': permit.application_number,
            'business_name': permit.business_name,
            'status': permit.status,
            'submitted_at': permit.submitted_at.isoformat(),
            'department': permit.department.name,
            'status_history': json.loads(permit.status_history) if permit.status_history else []
        }
    
    @auth_required('token')
    @roles_required('Department Officer', 'County Admin')
    def put(self, permit_id):
        """Update permit status"""
        permit = PermitApplication.query.get_or_404(permit_id)
        
        if not self._has_access(permit):
            return {'error': 'Unauthorized'}, 403
        
        parser = reqparse.RequestParser()
        parser.add_argument('status', type=str, required=True)
        parser.add_argument('comment', type=str)
        args = parser.parse_args()
        
        permit.add_status_change(args['status'], current_user.id, args.get('comment'))
        db.session.commit()
        
        return {'message': 'Status updated', 'new_status': args['status']}
    
    def _has_access(self, permit):
        """Check if current user has access to this permit"""
        if current_user.has_role('County Admin'):
            return permit.county_id == current_user.county_id
        elif current_user.has_role('Department Officer'):
            return (permit.department_id == current_user.department_id and 
                   permit.county_id == current_user.county_id)
        else:  # Citizen
            return permit.user_id == current_user.id
```

### API Routes Registration (app/blueprints/api/routes.py)
```python
from app.blueprints.api import api
from app.blueprints.api.resources import PermitListAPI, PermitAPI

# Register API endpoints
api.add_resource(PermitListAPI, '/permits')
api.add_resource(PermitAPI, '/permits/<int:permit_id>')
```

---

## 📦 Dependencies & Setup

### Required Packages (requirements.txt)
```txt
# Core Flask Framework
Flask==3.1.0
Flask-SQLAlchemy==3.1.1
Flask-Security-Too==5.4.3
Flask-RESTful==0.3.10
Flask-Migrate==4.0.7
Flask-WTF==1.2.1
WTForms==3.1.2
Flask-Mail==0.10.0
Flask-Bootstrap==3.3.7.1
Flask-FontAwesome==0.1.5
Flask-Moment==1.0.6
python-dotenv==1.0.1
bcrypt==4.2.0
Pillow==10.4.0
reportlab==4.2.5
```

### 🔄 Migration Notes for Updated Dependencies

#### Major Version Updates:
- **Flask 2.3.3 → 3.1.0**: 
  - Flask 3.x introduces better async support and improved CLI commands
  - No breaking changes for basic usage, but review any custom CLI commands
  - Improved security headers and CSRF protection

- **Flask-SQLAlchemy 3.0.5 → 3.1.1**:
  - Enhanced type hints and better SQLAlchemy 2.x compatibility
  - Improved session management and query patterns
  - No breaking changes for standard ORM usage

- **Flask-Security-Too 5.3.0 → 5.4.3**:
  - Enhanced security features and better integration with Flask 3.x
  - Improved password hashing defaults and session security
  - Review any custom security configuration for new options

- **Flask-WTF 1.1.1 → 1.2.1**:
  - Better CSRF protection and Flask 3.x compatibility
  - Enhanced file upload validation
  - No breaking changes for standard form usage

- **WTForms 3.0.1 → 3.1.2**:
  - Improved validation messages and field rendering
  - Better internationalization support
  - Enhanced HTML5 field types

- **bcrypt 4.0.1 → 4.2.0**:
  - Security improvements and performance optimizations
  - Better handling of password encoding
  - Backward compatible with existing hashed passwords

- **Pillow 10.0.1 → 10.4.0**:
  - Security fixes and performance improvements
  - Enhanced image format support
  - Review any custom image processing for deprecation warnings

#### Installation Commands:
```bash
# Upgrade all packages
pip install --upgrade -r requirements.txt

# Or install fresh in new virtual environment
pip install -r requirements.txt
```

### Environment Setup (.env)
```env
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///county_services.db
SECURITY_PASSWORD_SALT=your-password-salt
MAIL_SERVER=localhost
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=
MAIL_PASSWORD=
```

---

## 🧱 Core Data Models (SQLAlchemy)

### User & Role Models (app/models/user.py)
```python
from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin

db = SQLAlchemy()

# Association table for many-to-many relationship
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    active = db.Column(db.Boolean, default=True)
    confirmed_at = db.Column(db.DateTime)
    county_id = db.Column(db.Integer, db.ForeignKey('county.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    
    # Relationships
    county = db.relationship('County', backref='users')
    department = db.relationship('Department', backref='officers')
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    permit_applications = db.relationship('PermitApplication', backref='applicant', lazy='dynamic')
```

### County & Department Models (app/models/county.py)
```python
from app.models.user import db

class County(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    code = db.Column(db.String(10), unique=True)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20))
    county_id = db.Column(db.Integer, db.ForeignKey('county.id'))
    active = db.Column(db.Boolean, default=True)
    
    # Relationships
    county = db.relationship('County', backref='departments')
```

### Permit Application Models (app/models/permit.py)
```python
from app.models.user import db
from datetime import datetime
import json

class PermitType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    required_documents = db.Column(db.Text)  # JSON list
    processing_fee = db.Column(db.Decimal(10, 2))
    
    department = db.relationship('Department', backref='permit_types')

class PermitApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_number = db.Column(db.String(50), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    permit_type_id = db.Column(db.Integer, db.ForeignKey('permit_type.id'))
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    county_id = db.Column(db.Integer, db.ForeignKey('county.id'))
    
    # Application details
    business_name = db.Column(db.String(200))
    application_data = db.Column(db.Text)  # JSON for flexible form data
    
    # Status tracking
    status = db.Column(db.String(50), default='Submitted')
    assigned_officer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)
    approved_at = db.Column(db.DateTime)
    
    # Audit trail
    status_history = db.Column(db.Text)  # JSON log of status changes
    comments = db.Column(db.Text)
    
    # Relationships
    permit_type = db.relationship('PermitType', backref='applications')
    department = db.relationship('Department', backref='permit_applications')
    county = db.relationship('County', backref='permit_applications')
    assigned_officer = db.relationship('User', foreign_keys=[assigned_officer_id], backref='assigned_permits')
    
    def add_status_change(self, new_status, user_id, comment=None):
        """Add status change to history"""
        history = json.loads(self.status_history) if self.status_history else []
        history.append({
            'status': new_status,
            'changed_by': user_id,
            'changed_at': datetime.utcnow().isoformat(),
            'comment': comment
        })
        self.status_history = json.dumps(history)
        self.status = new_status
```

---

## 🎨 Template Structure & Examples

### Base Template (app/templates/base.html)
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}County Services Portal{% endblock %}</title>
    
    <!-- Bootstrap CSS -->
    {{ bootstrap.load_css() }}
    
    <!-- FontAwesome Icons -->
    {{ fontawesome.load() }}
    
    <!-- Lucide Icons CDN -->
    <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.js"></script>
    
    <!-- Custom CSS -->
    <link href="{{ url_for('static', filename='css/custom.css') }}" rel="stylesheet">
</head>
<body class="d-flex flex-column min-vh-100">
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm">
        <div class="container">
            <a class="navbar-brand fw-bold" href="{{ url_for('main.index') }}">
                <i class="fas fa-building me-2"></i>
                County Services Portal
            </a>
            
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            
            <div class="collapse navbar-collapse" id="navbarNav">
                <div class="navbar-nav ms-auto">
                    {% if current_user.is_authenticated %}
                        <!-- User dropdown -->
                        <div class="dropdown">
                            <a class="nav-link dropdown-toggle text-white" href="#" role="button" data-bs-toggle="dropdown">
                                <i class="fas fa-user-circle me-1"></i>
                                {{ current_user.first_name or current_user.email.split('@')[0] }}
                                {% if current_user.county %}
                                    <small class="text-light opacity-75">({{ current_user.county.name }})</small>
                                {% endif %}
                            </a>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="{{ url_for('main.dashboard') }}">
                                    <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                                </a></li>
                                <li><a class="dropdown-item" href="{{ url_for('security.change_password') }}">
                                    <i class="fas fa-key me-2"></i>Change Password
                                </a></li>
                                <li><hr class="dropdown-divider"></li>
                                <li><a class="dropdown-item" href="{{ url_for('security.logout') }}">
                                    <i class="fas fa-sign-out-alt me-2"></i>Logout
                                </a></li>
                            </ul>
                        </div>
                        
                        <!-- Role-specific navigation -->
                        {% if current_user.has_role('County Admin') %}
                            <a class="nav-link text-white" href="{{ url_for('auth.manage_users') }}">
                                <i class="fas fa-users me-1"></i>Manage Users
                            </a>
                        {% endif %}
                        
                        {% if current_user.has_role('Citizen') %}
                            <a class="nav-link text-white" href="{{ url_for('main.apply_permit') }}">
                                <i class="fas fa-file-plus me-1"></i>Apply for Permit
                            </a>
                        {% endif %}
                    {% else %}
                        <a class="nav-link text-white" href="{{ url_for('security.login') }}">
                            <i class="fas fa-sign-in-alt me-1"></i>Login
                        </a>
                        <a class="nav-link text-white" href="{{ url_for('security.register') }}">
                            <i class="fas fa-user-plus me-1"></i>Register
                        </a>
                    {% endif %}
                </div>
            </div>
        </div>
    </nav>

    <!-- Breadcrumb -->
    {% block breadcrumb %}{% endblock %}

    <!-- Main Content -->
    <main class="container-fluid py-4 flex-grow-1">
        <!-- Flash Messages with enhanced styling -->
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <div class="row">
                    <div class="col-12">
                        {% for category, message in messages %}
                            <div class="alert alert-{{ 'danger' if category == 'error' else 'success' if category == 'success' else 'warning' if category == 'warning' else 'info' }} alert-dismissible fade show shadow-sm" role="alert">
                                <i class="fas fa-{{ 'exclamation-triangle' if category == 'error' else 'check-circle' if category == 'success' else 'exclamation-circle' if category == 'warning' else 'info-circle' }} me-2"></i>
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        {% endfor %}
                    </div>
                </div>
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </main>

    <!-- Footer -->
    <footer class="bg-light py-3 mt-auto">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <p class="mb-0 text-muted">
                        <i class="fas fa-copyright me-1"></i>
                        {{ moment().format('YYYY') }} County Services Portal
                    </p>
                </div>
                <div class="col-md-6 text-end">
                    <a href="#" class="text-muted me-3">
                        <i class="fas fa-question-circle me-1"></i>Help
                    </a>
                    <a href="#" class="text-muted">
                        <i class="fas fa-phone me-1"></i>Contact
                    </a>
                </div>
            </div>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    {{ bootstrap.load_js() }}
    
    <!-- Initialize Lucide Icons -->
    <script>
        lucide.createIcons();
    </script>
    
    <!-- Custom JavaScript -->
    {% block scripts %}{% endblock %}
</body>
</html>
```

### Admin Dashboard Template (app/blueprints/main/templates/admin_dashboard.html)
```html
{% extends "base.html" %}

{% block title %}Admin Dashboard - County Services{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="bg-light py-2">
    <div class="container">
        <ol class="breadcrumb mb-0">
            <li class="breadcrumb-item"><a href="{{ url_for('main.index') }}">Home</a></li>
            <li class="breadcrumb-item active">Admin Dashboard</li>
        </ol>
    </div>
</nav>
{% endblock %}

{% block content %}
<div class="container-fluid">
    <!-- Header Section -->
    <div class="row mb-4">
        <div class="col-12">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h1 class="h3 mb-1">
                        <i class="fas fa-tachometer-alt text-primary me-2"></i>
                        Admin Dashboard
                    </h1>
                    <p class="text-muted mb-0">
                        <i data-lucide="map-pin" class="me-1"></i>
                        {{ current_user.county.name }} County
                    </p>
                </div>
                <div class="btn-group">
                    <a href="{{ url_for('auth.manage_users') }}" class="btn btn-primary">
                        <i class="fas fa-users me-2"></i>Manage Users
                    </a>
                    <a href="{{ url_for('main.reports') }}" class="btn btn-outline-secondary">
                        <i data-lucide="bar-chart-3" class="me-2"></i>Reports
                    </a>
                    <div class="dropdown">
                        <button class="btn btn-outline-secondary dropdown-toggle" data-bs-toggle="dropdown">
                            <i data-lucide="settings" class="me-2"></i>Settings
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#">
                                <i data-lucide="building" class="me-2"></i>Manage Departments
                            </a></li>
                            <li><a class="dropdown-item" href="#">
                                <i data-lucide="file-text" class="me-2"></i>Permit Types
                            </a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Statistics Cards -->
    <div class="row g-4 mb-4">
        <div class="col-xl-3 col-md-6">
            <div class="card border-0 shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-shrink-0">
                            <div class="bg-warning bg-opacity-10 rounded-3 p-3">
                                <i data-lucide="clock" class="text-warning" style="width: 24px; height: 24px;"></i>
                            </div>
                        </div>
                        <div class="flex-grow-1 ms-3">
                            <h3 class="h4 mb-1">{{ permits|selectattr("status", "equalto", "Submitted")|list|length }}</h3>
                            <p class="text-muted mb-0">Pending Review</p>
                        </div>
                    </div>
                    <div class="progress mt-3" style="height: 4px;">
                        <div class="progress-bar bg-warning" style="width: 65%"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-xl-3 col-md-6">
            <div class="card border-0 shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-shrink-0">
                            <div class="bg-info bg-opacity-10 rounded-3 p-3">
                                <i data-lucide="search" class="text-info" style="width: 24px; height: 24px;"></i>
                            </div>
                        </div>
                        <div class="flex-grow-1 ms-3">
                            <h3 class="h4 mb-1">{{ permits|selectattr("status", "equalto", "Under Review")|list|length }}</h3>
                            <p class="text-muted mb-0">Under Review</p>
                        </div>
                    </div>
                    <div class="progress mt-3" style="height: 4px;">
                        <div class="progress-bar bg-info" style="width: 45%"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-xl-3 col-md-6">
            <div class="card border-0 shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-shrink-0">
                            <div class="bg-success bg-opacity-10 rounded-3 p-3">
                                <i data-lucide="check-circle" class="text-success" style="width: 24px; height: 24px;"></i>
                            </div>
                        </div>
                        <div class="flex-grow-1 ms-3">
                            <h3 class="h4 mb-1">{{ permits|selectattr("status", "equalto", "Approved")|list|length }}</h3>
                            <p class="text-muted mb-0">Approved</p>
                        </div>
                    </div>
                    <div class="progress mt-3" style="height: 4px;">
                        <div class="progress-bar bg-success" style="width: 85%"></div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-xl-3 col-md-6">
            <div class="card border-0 shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-shrink-0">
                            <div class="bg-danger bg-opacity-10 rounded-3 p-3">
                                <i data-lucide="x-circle" class="text-danger" style="width: 24px; height: 24px;"></i>
                            </div>
                        </div>
                        <div class="flex-grow-1 ms-3">
                            <h3 class="h4 mb-1">{{ permits|selectattr("status", "equalto", "Rejected")|list|length }}</h3>
                            <p class="text-muted mb-0">Rejected</p>
                        </div>
                    </div>
                    <div class="progress mt-3" style="height: 4px;">
                        <div class="progress-bar bg-danger" style="width: 25%"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Actions Row -->
    <div class="row g-4 mb-4">
        <div class="col-md-8">
            <!-- Recent Activity Card -->
            <div class="card border-0 shadow-sm h-100">
                <div class="card-header bg-transparent border-bottom-0 py-3">
                    <h5 class="card-title mb-0">
                        <i data-lucide="activity" class="me-2"></i>Recent Activity
                    </h5>
                </div>
                <div class="card-body pt-0">
                    <div class="list-group list-group-flush">
                        {% for permit in permits[:5] %}
                        <div class="list-group-item px-0 py-3 border-0 border-bottom">
                            <div class="d-flex align-items-center">
                                <div class="flex-shrink-0">
                                    <div class="bg-primary bg-opacity-10 rounded-circle p-2">
                                        <i data-lucide="file-text" class="text-primary" style="width: 16px; height: 16px;"></i>
                                    </div>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6 class="mb-1">{{ permit.business_name }}</h6>
                                    <p class="text-muted mb-0 small">
                                        Applied by {{ permit.applicant.first_name }} {{ permit.applicant.last_name }}
                                        • {{ permit.submitted_at.strftime('%b %d, %Y') }}
                                    </p>
                                </div>
                                <span class="badge bg-{{ 'success' if permit.status == 'Approved' else 'warning' if permit.status == 'Under Review' else 'danger' if permit.status == 'Rejected' else 'secondary' }}">
                                    {{ permit.status }}
                                </span>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <!-- Department Overview -->
            <div class="card border-0 shadow-sm h-100">
                <div class="card-header bg-transparent border-bottom-0 py-3">
                    <h5 class="card-title mb-0">
                        <i data-lucide="building" class="me-2"></i>Department Overview
                    </h5>
                </div>
                <div class="card-body pt-0">
                    {% for dept in current_user.county.departments %}
                    <div class="d-flex align-items-center justify-content-between py-2">
                        <div>
                            <h6 class="mb-0">{{ dept.name }}</h6>
                            <small class="text-muted">{{ dept.permit_applications|length }} applications</small>
                        </div>
                        <span class="badge bg-light text-dark">{{ dept.officers|length }} officers</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>

    <!-- Permits Table -->
    <div class="card border-0 shadow-sm">
        <div class="card-header bg-transparent border-bottom py-3">
            <div class="d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0">
                    <i data-lucide="list" class="me-2"></i>All Permit Applications
                </h5>
                <div class="d-flex gap-2">
                    <div class="dropdown">
                        <button class="btn btn-outline-secondary btn-sm dropdown-toggle" data-bs-toggle="dropdown">
                            <i data-lucide="filter" class="me-1"></i>Filter
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="?status=Submitted">Pending Only</a></li>
                            <li><a class="dropdown-item" href="?status=Under Review">Under Review</a></li>
                            <li><a class="dropdown-item" href="?status=Approved">Approved</a></li>
                            <li><a class="dropdown-item" href="?status=Rejected">Rejected</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="?">All Applications</a></li>
                        </ul>
                    </div>
                    <button class="btn btn-outline-secondary btn-sm">
                        <i data-lucide="download" class="me-1"></i>Export
                    </button>
                </div>
            </div>
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead class="table-light">
                        <tr>
                            <th class="border-0 ps-4">Application #</th>
                            <th class="border-0">Applicant</th>
                            <th class="border-0">Business Name</th>
                            <th class="border-0">Department</th>
                            <th class="border-0">Status</th>
                            <th class="border-0">Date</th>
                            <th class="border-0 text-end pe-4">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for permit in permits %}
                        <tr>
                            <td class="ps-4">
                                <code class="text-muted">{{ permit.application_number }}</code>
                            </td>
                            <td>
                                <div class="d-flex align-items-center">
                                    <div class="bg-secondary bg-opacity-10 rounded-circle p-2 me-2">
                                        <i data-lucide="user" style="width: 16px; height: 16px;"></i>
                                    </div>
                                    <div>
                                        <h6 class="mb-0">{{ permit.applicant.first_name }} {{ permit.applicant.last_name }}</h6>
                                        <small class="text-muted">{{ permit.applicant.email }}</small>
                                    </div>
                                </div>
                            </td>
                            <td>
                                <strong>{{ permit.business_name }}</strong>
                            </td>
                            <td>
                                <span class="badge bg-light text-dark">{{ permit.department.name if permit.department else 'N/A' }}</span>
                            </td>
                            <td>
                                <span class="badge bg-{{ 'success' if permit.status == 'Approved' else 'warning' if permit.status == 'Under Review' else 'danger' if permit.status == 'Rejected' else 'secondary' }}">
                                    <i class="fas fa-{{ 'check' if permit.status == 'Approved' else 'clock' if permit.status == 'Under Review' else 'times' if permit.status == 'Rejected' else 'file' }} me-1"></i>
                                    {{ permit.status }}
                                </span>
                            </td>
                            <td>
                                <span class="text-muted">{{ permit.submitted_at.strftime('%b %d, %Y') }}</span>
                                <br>
                                <small class="text-muted">{{ permit.submitted_at.strftime('%I:%M %p') }}</small>
                            </td>
                            <td class="text-end pe-4">
                                <div class="btn-group btn-group-sm">
                                    <a href="{{ url_for('main.permit_detail', permit_id=permit.id) }}" 
                                       class="btn btn-outline-primary" title="View Details">
                                        <i data-lucide="eye"></i>
                                    </a>
                                    <a href="{{ url_for('main.permit_edit', permit_id=permit.id) }}" 
                                       class="btn btn-outline-secondary" title="Edit">
                                        <i data-lucide="edit"></i>
                                    </a>
                                    <button class="btn btn-outline-info" title="History" 
                                            data-bs-toggle="modal" data-bs-target="#historyModal{{ permit.id }}">
                                        <i data-lucide="history"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Pagination -->
        <div class="card-footer bg-transparent border-top-0 py-3">
            <div class="d-flex justify-content-between align-items-center">
                <span class="text-muted small">Showing {{ permits|length }} of {{ permits|length }} applications</span>
                <nav>
                    <ul class="pagination pagination-sm mb-0">
                        <li class="page-item disabled">
                            <span class="page-link">Previous</span>
                        </li>
                        <li class="page-item active">
                            <span class="page-link">1</span>
                        </li>
                        <li class="page-item disabled">
                            <span class="page-link">Next</span>
                        </li>
                    </ul>
                </nav>
            </div>
        </div>
    </div>
</div>

<!-- History Modals -->
{% for permit in permits %}
<div class="modal fade" id="historyModal{{ permit.id }}" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i data-lucide="history" class="me-2"></i>
                    Application History - {{ permit.application_number }}
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="timeline">
                    {% if permit.status_history %}
                        {% for entry in permit.status_history|from_json %}
                        <div class="timeline-item">
                            <div class="timeline-marker bg-primary"></div>
                            <div class="timeline-content">
                                <h6>{{ entry.status }}</h6>
                                <p class="text-muted mb-1">{{ entry.comment or 'No comment provided' }}</p>
                                <small class="text-muted">{{ entry.changed_at }} by User #{{ entry.changed_by }}</small>
                            </div>
                        </div>
                        {% endfor %}
                    {% else %}
                        <p class="text-muted">No history available</p>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
</div>
{% endfor %}
{% endblock %}

{% block scripts %}
<script>
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[title]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
    
    // Auto-refresh dashboard every 30 seconds
    setTimeout(() => {
        location.reload();
    }, 30000);
</script>
{% endblock %}
                <div class="card-body">
                    <div class="d-flex align-items-center">
                        <div class="flex-shrink-0">
                            <div class="bg-danger bg-opacity-10 rounded-3 p-3">
                                <i data-lucide="x-circle" class="text-danger" style="width: 24px; height: 24px;"></i>
                            </div>
                        </div>
                        <div class="flex-grow-1 ms-3">
                            <h3 class="h4 mb-1">{{ permits|selectattr("status", "equalto", "Rejected")|list|length }}</h3>
                            <p class="text-muted mb-0">Rejected</p>
                        </div>
                    </div>
                    <div class="progress mt-3" style="height: 4px;">
                        <div class="progress-bar bg-danger" style="width: 25%"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Actions Row -->
    <div class="row g-4 mb-4">
        <div class="col-md-8">
            <!-- Recent Activity Card -->
            <div class="card border-0 shadow-sm h-100">
                <div class="card-header bg-transparent border-bottom-0 py-3">
                    <h5 class="card-title mb-0">
                        <i data-lucide="activity" class="me-2"></i>Recent Activity
                    </h5>
                </div>
                <div class="card-body pt-0">
                    <div class="list-group list-group-flush">
                        {% for permit in permits[:5] %}
                        <div class="list-group-item px-0 py-3 border-0 border-bottom">
                            <div class="d-flex align-items-center">
                                <div class="flex-shrink-0">
                                    <div class="bg-primary bg-opacity-10 rounded-circle p-2">
                                        <i data-lucide="file-text" class="text-primary" style="width: 16px; height: 16px;"></i>
                                    </div>
                                </div>
                                <div class="flex-grow-1 ms-3">
                                    <h6 class="mb-1">{{ permit.business_name }}</h6>
                                    <p class="text-muted mb-0 small">
                                        Applied by {{ permit.applicant.first_name }} {{ permit.applicant.last_name }}
                                        • {{ permit.submitted_at.strftime('%b %d, %Y') }}
                                    </p>
                                </div>
                                <span class="badge bg-{{ 'success' if permit.status == 'Approved' else 'warning' if permit.status == 'Under Review' else 'danger' if permit.status == 'Rejected' else 'secondary' }}">
                                    {{ permit.status }}
                                </span>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <!-- Department Overview -->
            <div class="card border-0 shadow-sm h-100">
                <div class="card-header bg-transparent border-bottom-0 py-3">
                    <h5 class="card-title mb-0">
                        <i data-lucide="building" class="me-2"></i>Department Overview
                    </h5>
                </div>
                <div class="card-body pt-0">
                    {% for dept in current_user.county.departments %}
                    <div class="d-flex align-items-center justify-content-between py-2">
                        <div>
                            <h6 class="mb-0">{{ dept.name }}</h6>
                            <small class="text-muted">{{ dept.permit_applications|length }} applications</small>
                        </div>
                        <span class="badge bg-light text-dark">{{ dept.officers|length }} officers</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>

    <!-- Permits Table -->
    <div class="card border-0 shadow-sm">
        <div class="card-header bg-transparent border-bottom py-3">
            <div class="d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0">
                    <i data-lucide="list" class="me-2"></i>All Permit Applications
                </h5>
                <div class="d-flex gap-2">
                    <div class="dropdown">
                        <button class="btn btn-outline-secondary btn-sm dropdown-toggle" data-bs-toggle="dropdown">
                            <i data-lucide="filter" class="me-1"></i>Filter
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="?status=Submitted">Pending Only</a></li>
                            <li><a class="dropdown-item" href="?status=Under Review">Under Review</a></li>
                            <li><a class="dropdown-item" href="?status=Approved">Approved</a></li>
                            <li><a class="dropdown-item" href="?status=Rejected">Rejected</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="?">All Applications</a></li>
                        </ul>
                    </div>
                    <button class="btn btn-outline-secondary btn-sm">
                        <i data-lucide="download" class="me-1"></i>Export
                    </button>
                </div>
            </div>
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover mb-0">
                    <thead class="table-light">
                        <tr>
                            <th class="border-0 ps-4">Application #</th>
                            <th class="border-0">Applicant</th>
                            <th class="border-0">Business Name</th>
                            <th class="border-0">Department</th>
                            <th class="border-0">Status</th>
                            <th class="border-0">Date</th>
                            <th class="border-0 text-end pe-4">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for permit in permits %}
                        <tr>
                            <td class="ps-4">
                                <code class="text-muted">{{ permit.application_number }}</code>
                            </td>
                            <td>
                                <div class="d-flex align-items-center">
                                    <div class="bg-secondary bg-opacity-10 rounded-circle p-2 me-2">
                                        <i data-lucide="user" style="width: 16px; height: 16px;"></i>
                                    </div>
                                    <div>
                                        <h6 class="mb-0">{{ permit.applicant.first_name }} {{ permit.applicant.last_name }}</h6>
                                        <small class="text-muted">{{ permit.applicant.email }}</small>
                                    </div>
                                </div>
                            </td>
                            <td>
                                <strong>{{ permit.business_name }}</strong>
                            </td>
                            <td>
                                <span class="badge bg-light text-dark">{{ permit.department.name if permit.department else 'N/A' }}</span>
                            </td>
                            <td>
                                <span class="badge bg-{{ 'success' if permit.status == 'Approved' else 'warning' if permit.status == 'Under Review' else 'danger' if permit.status == 'Rejected' else 'secondary' }}">
                                    <i class="fas fa-{{ 'check' if permit.status == 'Approved' else 'clock' if permit.status == 'Under Review' else 'times' if permit.status == 'Rejected' else 'file' }} me-1"></i>
                                    {{ permit.status }}
                                </span>
                            </td>
                            <td>
                                <span class="text-muted">{{ permit.submitted_at.strftime('%b %d, %Y') }}</span>
                                <br>
                                <small class="text-muted">{{ permit.submitted_at.strftime('%I:%M %p') }}</small>
                            </td>
                            <td class="text-end pe-4">
                                <div class="btn-group btn-group-sm">
                                    <a href="{{ url_for('main.permit_detail', permit_id=permit.id) }}" 
                                       class="btn btn-outline-primary" title="View Details">
                                        <i data-lucide="eye"></i>
                                    </a>
                                    <a href="{{ url_for('main.permit_edit', permit_id=permit.id) }}" 
                                       class="btn btn-outline-secondary" title="Edit">
                                        <i data-lucide="edit"></i>
                                    </a>
                                    <button class="btn btn-outline-info" title="History" 
                                            data-bs-toggle="modal" data-bs-target="#historyModal{{ permit.id }}">
                                        <i data-lucide="history"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Pagination -->
        <div class="card-footer bg-transparent border-top-0 py-3">
            <div class="d-flex justify-content-between align-items-center">
                <span class="text-muted small">Showing {{ permits|length }} of {{ permits|length }} applications</span>
                <nav>
                    <ul class="pagination pagination-sm mb-0">
                        <li class="page-item disabled">
                            <span class="page-link">Previous</span>
                        </li>
                        <li class="page-item active">
                            <span class="page-link">1</span>
                        </li>
                        <li class="page-item disabled">
                            <span class="page-link">Next</span>
                        </li>
                    </ul>
                </nav>
            </div>
        </div>
    </div>
</div>

<!-- History Modals -->
{% for permit in permits %}
<div class="modal fade" id="historyModal{{ permit.id }}" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i data-lucide="history" class="me-2"></i>
                    Application History - {{ permit.application_number }}
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div class="timeline">
                    {% if permit.status_history %}
                        {% for entry in permit.status_history|from_json %}
                        <div class="timeline-item">
                            <div class="timeline-marker bg-primary"></div>
                            <div class="timeline-content">
                                <h6>{{ entry.status }}</h6>
                                <p class="text-muted mb-1">{{ entry.comment or 'No comment provided' }}</p>
                                <small class="text-muted">{{ entry.changed_at }} by User #{{ entry.changed_by }}</small>
                            </div>
                        </div>
                        {% endfor %}
                    {% else %}
                        <p class="text-muted">No history available</p>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
</div>
{% endfor %}
{% endblock %}

{% block scripts %}
<script>
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[title]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
    
    // Auto-refresh dashboard every 30 seconds
    setTimeout(() => {
        location.reload();
    }, 30000);
</script>
{% endblock %}
```

### Permit Application Form (app/blueprints/main/templates/apply.html)
```html
{% extends "base.html" %}

{% block title %}Apply for Permit - County Services{% endblock %}

{% block breadcrumb %}
<nav aria-label="breadcrumb" class="bg-light py-2">
    <div class="container">
        <ol class="breadcrumb mb-0">
            <li class="breadcrumb-item"><a href="{{ url_for('main.index') }}">Home</a></li>
            <li class="breadcrumb-item"><a href="{{ url_for('main.dashboard') }}">Dashboard</a></li>
            <li class="breadcrumb-item active">Apply for Permit</li>
        </ol>
    </div>
</nav>
{% endblock %}

{% block content %}
<div class="container">
    <div class="row justify-content-center">
        <div class="col-lg-8">
            <!-- Header Card -->
            <div class="card border-0 shadow-sm mb-4">
                <div class="card-body text-center py-4">
                    <div class="bg-primary bg-opacity-10 rounded-circle d-inline-flex p-3 mb-3">
                        <i data-lucide="file-plus" class="text-primary" style="width: 32px; height: 32px;"></i>
                    </div>
                    <h2 class="h4 mb-2">Apply for New Permit</h2>
                    <p class="text-muted mb-0">
                        Submit your permit application for {{ current_user.county.name }} County
                    </p>
                </div>
            </div>

            <!-- Application Form -->
            <div class="card border-0 shadow-sm">
                <div class="card-header bg-transparent border-bottom py-3">
                    <h5 class="card-title mb-0">
                        <i data-lucide="clipboard" class="me-2"></i>
                        Application Details
                    </h5>
                </div>
                <div class="card-body p-4">
                    <form method="POST" enctype="multipart/form-data" id="permitForm">
                        {{ csrf_token() }}
                        
                        <!-- Step 1: Permit Type Selection -->
                        <div class="mb-4">
                            <label for="permit_type_id" class="form-label fw-semibold">
                                <i data-lucide="tag" class="me-1"></i>
                                Permit Type <span class="text-danger">*</span>
                            </label>
                            <select class="form-select form-select-lg" id="permit_type_id" name="permit_type_id" required>
                                <option value="">Choose the type of permit you need...</option>
                                {% for permit_type in permit_types %}
                                <option value="{{ permit_type.id }}" 
                                        data-department="{{ permit_type.department.name }}"
                                        data-fee="{{ permit_type.processing_fee or 0 }}"
                                        data-docs="{{ permit_type.required_documents or '[]' }}">
                                    {{ permit_type.name }} - {{ permit_type.department.name }}
                                    {% if permit_type.processing_fee %}
                                        (Fee: ${{ permit_type.processing_fee }})
                                    {% endif %}
                                </option>
                                {% endfor %}
                            </select>
                            <div class="form-text">
                                <i data-lucide="info" class="me-1"></i>
                                Select the permit type that best matches your application needs
                            </div>
                        </div>

                        <!-- Permit Type Info Display -->
                        <div id="permitTypeInfo" class="alert alert-info d-none mb-4">
                            <div class="d-flex align-items-start">
                                <i data-lucide="info-circle" class="me-2 mt-1 flex-shrink-0"></i>
                                <div>
                                    <h6 class="alert-heading mb-2">Permit Information</h6>
                                    <div id="permitDepartment" class="mb-1"></div>
                                    <div id="permitFee" class="mb-1"></div>
                                    <div id="permitDocuments"></div>
                                </div>
                            </div>
                        </div>

                        <!-- Step 2: Business Details -->
                        <div class="row g-3 mb-4">
                            <div class="col-md-6">
                                <label for="business_name" class="form-label fw-semibold">
                                    <i data-lucide="building" class="me-1"></i>
                                    Business/Project Name <span class="text-danger">*</span>
                                </label>
                                <input type="text" class="form-control form-control-lg" 
                                       id="business_name" name="business_name" required
                                       placeholder="Enter business or project name">
                            </div>
                            <div class="col-md-6">
                                <label for="contact_phone" class="form-label fw-semibold">
                                    <i data-lucide="phone" class="me-1"></i>
                                    Contact Phone
                                </label>
                                <input type="tel" class="form-control form-control-lg" 
                                       id="contact_phone" name="contact_phone"
                                       placeholder="Your phone number">
                            </div>
                        </div>

                        <!-- Step 3: Application Description -->
                        <div class="mb-4">
                            <label for="description" class="form-label fw-semibold">
                                <i data-lucide="file-text" class="me-1"></i>
                                Project Description
                            </label>
                            <textarea class="form-control" id="description" name="description" rows="4" 
                                    placeholder="Provide a detailed description of your project or business..."></textarea>
                            <div class="form-text">
                                Include important details about your project, location, scope, and any special considerations
                            </div>
                        </div>

                        <!-- Step 4: Address Information -->
                        <div class="mb-4">
                            <h6 class="fw-semibold mb-3">
                                <i data-lucide="map-pin" class="me-1"></i>
                                Location Information
                            </h6>
                            <div class="row g-3">
                                <div class="col-12">
                                    <label for="address" class="form-label">Street Address</label>
                                    <input type="text" class="form-control" id="address" name="address"
                                           placeholder="Street address where permit applies">
                                </div>
                                <div class="col-md-6">
                                    <label for="city" class="form-label">City</label>
                                    <input type="text" class="form-control" id="city" name="city" 
                                           value="{{ current_user.county.name }}" readonly>
                                </div>
                                <div class="col-md-3">
                                    <label for="state" class="form-label">State</label>
                                    <input type="text" class="form-control" id="state" name="state" 
                                           value="Kenya" readonly>
                                </div>
                                <div class="col-md-3">
                                    <label for="postal_code" class="form-label">Postal Code</label>
                                    <input type="text" class="form-control" id="postal_code" name="postal_code">
                                </div>
                            </div>
                        </div>

                        <!-- Step 5: Supporting Documents -->
                        <div class="mb-4">
                            <label for="documents" class="form-label fw-semibold">
                                <i data-lucide="paperclip" class="me-1"></i>
                                Supporting Documents
                            </label>
                            <div class="border border-2 border-dashed rounded-3 p-4 text-center bg-light">
                                <i data-lucide="upload" class="text-muted mb-2" style="width: 48px; height: 48px;"></i>
                                <h6 class="text-muted mb-2">Drop files here or click to browse</h6>
                                <input type="file" class="form-control d-none" id="documents" name="documents" 
                                       multiple accept=".pdf,.jpg,.jpeg,.png,.doc,.docx">
                                <button type="button" class="btn btn-outline-primary" onclick="document.getElementById('documents').click()">
                                    <i data-lucide="folder" class="me-1"></i>
                                    Choose Files
                                </button>
                                <div class="form-text mt-2">
                                    Accepted formats: PDF, JPG, PNG, DOC, DOCX (Max 10MB per file)
                                </div>
                            </div>
                            <div id="fileList" class="mt-3"></div>
                        </div>

                        <!-- Step 6: Declaration -->
                        <div class="mb-4">
                            <div class="card bg-light border-0">
                                <div class="card-body">
                                    <h6 class="card-title">
                                        <i data-lucide="shield-check" class="me-1"></i>
                                        Declaration
                                    </h6>
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="declaration" name="declaration" required>
                                        <label class="form-check-label" for="declaration">
                                            I declare that the information provided in this application is true and accurate to the best of my knowledge. 
                                            I understand that providing false information may result in the rejection of this application or 
                                            cancellation of any permit issued.
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Action Buttons -->
                        <div class="d-flex gap-3 justify-content-end">
                            <a href="{{ url_for('main.dashboard') }}" class="btn btn-outline-secondary btn-lg">
                                <i data-lucide="arrow-left" class="me-1"></i>
                                Cancel
                            </a>
                            <button type="button" class="btn btn-outline-primary btn-lg" id="previewBtn">
                                <i data-lucide="eye" class="me-1"></i>
                                Preview
                            </button>
                            <button type="submit" class="btn btn-primary btn-lg" id="submitBtn">
                                <i data-lucide="send" class="me-1"></i>
                                Submit Application
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Preview Modal -->
<div class="modal fade" id="previewModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title">
                    <i data-lucide="eye" class="me-2"></i>
                    Application Preview
                </h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body" id="previewContent">
                <!-- Preview content will be populated by JavaScript -->
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">
                    <i data-lucide="edit" class="me-1"></i>
                    Edit Application
                </button>
                <button type="button" class="btn btn-primary" onclick="$('#permitForm').submit()">
                    <i data-lucide="send" class="me-1"></i>
                    Submit Application
                </button>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
document.addEventListener('DOMContentLoaded', function() {
    const permitTypeSelect = document.getElementById('permit_type_id');
    const permitTypeInfo = document.getElementById('permitTypeInfo');
    const documentsInput = document.getElementById('documents');
    const fileList = document.getElementById('fileList');
    const previewBtn = document.getElementById('previewBtn');
    const previewModal = new bootstrap.Modal(document.getElementById('previewModal'));

    // Handle permit type selection
    permitTypeSelect.addEventListener('change', function() {
        const selectedOption = this.options[this.selectedIndex];
        
        if (selectedOption.value) {
            const department = selectedOption.dataset.department;
            const fee = selectedOption.dataset.fee;
            const docs = JSON.parse(selectedOption.dataset.docs || '[]');
            
            document.getElementById('permitDepartment').innerHTML = 
                `<strong>Department:</strong> ${department}`;
            document.getElementById('permitFee').innerHTML = 
                `<strong>Processing Fee:</strong> $${fee || '0.00'}`;
            
            let docsHtml = '<strong>Required Documents:</strong> ';
            if (docs.length > 0) {
                docsHtml += '<ul class="mb-0 mt-1">';
                docs.forEach(doc => {
                    docsHtml += `<li>${doc}</li>`;
                });
                docsHtml += '</ul>';
            } else {
                docsHtml += 'No specific documents required';
            }
            document.getElementById('permitDocuments').innerHTML = docsHtml;
            
            permitTypeInfo.classList.remove('d-none');
        } else {
            permitTypeInfo.classList.add('d-none');
        }
    });

    // Handle file uploads
    documentsInput.addEventListener('change', function() {
        const files = Array.from(this.files);
        let html = '';
        
        files.forEach((file, index) => {
            const size = (file.size / 1024 / 1024).toFixed(2);
            html += `
                <div class="d-flex align-items-center justify-content-between p-2 border rounded mb-2">
                    <div class="d-flex align-items-center">
                        <i data-lucide="file" class="me-2"></i>
                        <div>
                            <div class="fw-medium">${file.name}</div>
                            <small class="text-muted">${size} MB</small>
                        </div>
                    </div>
                    <button type="button" class="btn btn-sm btn-outline-danger" onclick="removeFile(${index})">
                        <i data-lucide="x"></i>
                    </button>
                </div>
            `;
        });
        
        fileList.innerHTML = html;
        lucide.createIcons();
    });

    // Preview functionality
    previewBtn.addEventListener('click', function() {
        const formData = new FormData(document.getElementById('permitForm'));
        let previewHtml = `
            <div class="row g-3">
                <div class="col-md-6">
                    <strong>Permit Type:</strong><br>
                    ${permitTypeSelect.options[permitTypeSelect.selectedIndex].text || 'Not selected'}
                </div>
                <div class="col-md-6">
                    <strong>Business Name:</strong><br>
                    ${formData.get('business_name') || 'Not provided'}
                </div>
                <div class="col-md-6">
                    <strong>Contact Phone:</strong><br>
                    ${formData.get('contact_phone') || 'Not provided'}
                </div>
                <div class="col-md-6">
                    <strong>Address:</strong><br>
                    ${formData.get('address') || 'Not provided'}
                </div>
                <div class="col-12">
                    <strong>Description:</strong><br>
                    ${formData.get('description') || 'Not provided'}
                </div>
                <div class="col-12">
                    <strong>Documents:</strong><br>
                    ${documentsInput.files.length} file(s) selected
                </div>
            </div>
        `;
        
        document.getElementById('previewContent').innerHTML = previewHtml;
        previewModal.show();
    });

    // Form validation
    document.getElementById('permitForm').addEventListener('submit', function(e) {
        const requiredFields = ['permit_type_id', 'business_name', 'declaration'];
        let isValid = true;
        
        requiredFields.forEach(fieldName => {
            const field = document.getElementsByName(fieldName)[0];
            if (!field.value || (field.type === 'checkbox' && !field.checked)) {
                field.classList.add('is-invalid');
                isValid = false;
            } else {
                field.classList.remove('is-invalid');
            }
        });
        
        if (!isValid) {
            e.preventDefault();
            alert('Please fill in all required fields');
        }
    });
});

function removeFile(index) {
    // Implementation to remove specific file
    const input = document.getElementById('documents');
    const dt = new DataTransfer();
    const files = Array.from(input.files);
    
    files.forEach((file, i) => {
        if (i !== index) {
            dt.items.add(file);
        }
    });
    
    input.files = dt.files;
    input.dispatchEvent(new Event('change'));
}
</script>

<style>
.form-control:focus, .form-select:focus {
    border-color: #86b7fe;
    box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.15);
}

.file-drop-area {
    transition: all 0.3s ease;
}

.file-drop-area:hover {
    background-color: #f8f9fa;
    border-color: #6c757d;
}

.timeline-item {
    position: relative;
    padding-left: 2rem;
    padding-bottom: 1rem;
}

.timeline-item:not(:last-child)::before {
    content: '';
    position: absolute;
    left: 0.375rem;
    top: 1.5rem;
    bottom: -1rem;
    width: 2px;
    background-color: #dee2e6;
}

.timeline-marker {
    position: absolute;
    left: 0;
    top: 0.25rem;
    width: 0.75rem;
    height: 0.75rem;
    border-radius: 50%;
}
</style>
{% endblock %}
```

---

## 🔍 Testing & Development Guidelines

### Unit Testing Setup (tests/test_models.py)
```python
import unittest
from app import create_app, db
from app.models.user import User, Role
from app.models.county import County, Department
from app.models.permit import PermitApplication, PermitType

class ModelTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_county_creation(self):
        county = County(name='Test County', code='TC')
        db.session.add(county)
        db.session.commit()
        self.assertEqual(county.name, 'Test County')

    def test_user_role_assignment(self):
        # Create county and role
        county = County(name='Test County', code='TC')
        role = Role(name='Citizen')
        db.session.add_all([county, role])
        db.session.commit()

        # Create user
        user = User(email='test@example.com', county_id=county.id)
        user.roles.append(role)
        db.session.add(user)
        db.session.commit()

        self.assertTrue(user.has_role('Citizen'))
        self.assertEqual(user.county.name, 'Test County')

    def test_permit_workflow(self):
        # Setup test data
        county = County(name='Test County', code='TC')
        department = Department(name='Trade', county_id=county.id)
        permit_type = PermitType(name='Business License', department_id=department.id)
        user = User(email='citizen@example.com', county_id=county.id)
        
        db.session.add_all([county, department, permit_type, user])
        db.session.commit()

        # Create permit application
        permit = PermitApplication(
            user_id=user.id,
            permit_type_id=permit_type.id,
            department_id=department.id,
            county_id=county.id,
            business_name='Test Business'
        )
        db.session.add(permit)
        db.session.commit()

        self.assertEqual(permit.status, 'Submitted')
        self.assertEqual(permit.applicant.email, 'citizen@example.com')

if __name__ == '__main__':
    unittest.main()
```

### API Testing (tests/test_api.py)
```python
import unittest
import json
from app import create_app, db
from app.models.user import User, Role
from app.models.county import County, Department
from app.models.permit import PermitApplication, PermitType

class APITestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        
        # Create test data
        self.setup_test_data()

    def setup_test_data(self):
        # Create county and department
        county = County(name='Test County', code='TC')
        department = Department(name='Trade', county_id=county.id)
        permit_type = PermitType(name='Business License', department_id=department.id)
        
        # Create roles
        citizen_role = Role(name='Citizen')
        officer_role = Role(name='Department Officer')
        
        # Create users
        self.citizen = User(email='citizen@test.com', county_id=county.id)
        self.officer = User(email='officer@test.com', county_id=county.id, department_id=department.id)
        
        self.citizen.roles.append(citizen_role)
        self.officer.roles.append(officer_role)
        
        db.session.add_all([county, department, permit_type, citizen_role, officer_role, self.citizen, self.officer])
        db.session.commit()

    def get_auth_token(self, user):
        # Implementation would depend on your token generation logic
        pass

    def test_get_permits_as_citizen(self):
        # Test implementation for API endpoints
        pass

if __name__ == '__main__':
    unittest.main()
```

---

## 🧠 Concepts You'll Teach

### ✅ RBAC:

* Enforced via decorators (`@roles_required`, `@roles_accepted`)
* Template conditionals (e.g. `{% if 'County Admin' in current_user.roles %}`)

### ✅ Workflow IAM:

* Users can only act on a record if:

  * They're in the correct role
  * The resource is tied to their **county**
  * The resource is **in the right status stage**

### ✅ Scoped Access:

* Citizens → `PermitApplication.user_id == current_user.id`
* Officers → `PermitApplication.department_id == officer.department_id`
* Admins → unrestricted in their county

---

## 🧪 Bonus Features to Add Later

* PDF Generation for permits
* Email/SMS notification on status change
* Activity log / audit trail (for IAM audit teaching)
* Admin panel for creating departments per county

---

## 🔧 Development Setup Commands

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set up environment variables
cp .env.example .env
# Edit .env with your settings

# 4. Initialize database
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

# 5. Create initial data (counties, roles, etc.)
flask shell
>>> from app.models.user import db, Role
>>> from app.models.county import County, Department
>>> 
>>> # Create roles
>>> admin_role = Role(name='County Admin')
>>> officer_role = Role(name='Department Officer') 
>>> citizen_role = Role(name='Citizen')
>>> db.session.add_all([admin_role, officer_role, citizen_role])
>>> 
>>> # Create sample county and departments
>>> county = County(name='Sample County', code='SC')
>>> db.session.add(county)
>>> db.session.commit()
>>> 
>>> departments = [
>>>     Department(name='Trade & Commerce', code='TC', county_id=county.id),
>>>     Department(name='Lands & Housing', code='LH', county_id=county.id),
>>>     Department(name='Health Services', code='HS', county_id=county.id)
>>> ]
>>> db.session.add_all(departments)
>>> db.session.commit()

# 6. Run the application
python run.py
```

---

## Security & Access Control Implementation

### Custom Decorators (app/utils/decorators.py)
```python
from functools import wraps
from flask import abort
from flask_security import current_user

def county_required(f):
    """Ensure user actions are within their county scope"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.county_id:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def department_access_required(f):
    """Ensure officers can only access their department's data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.has_role('Department Officer'):
            if not current_user.department_id:
                abort(403)
        return f(*args, **kwargs)
    return decorated_function

def permit_access_required(f):
    """Check permit access based on user role and county/department"""
    @wraps(f)
    def decorated_function(permit_id, *args, **kwargs):
        from app.models.permit import PermitApplication
        permit = PermitApplication.query.get_or_404(permit_id)
        
        # County Admin: can access all permits in their county
        if current_user.has_role('County Admin'):
            if permit.county_id != current_user.county_id:
                abort(403)
        
        # Department Officer: can access permits in their department
        elif current_user.has_role('Department Officer'):
            if (permit.department_id != current_user.department_id or 
                permit.county_id != current_user.county_id):
                abort(403)
        
        # Citizen: can only access their own permits
        else:
            if permit.user_id != current_user.id:
                abort(403)
        
        return f(permit_id, *args, **kwargs)
    return decorated_function
```

---

### Application Entry Point (run.py)
```python
from app import create_app
from app.models.user import db
import os

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
```


