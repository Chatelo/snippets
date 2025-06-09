# County Services Portal - Flask-Security Integration

This Flask application now includes a fully functional authentication system using Flask-Security.

## 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Initialize database:**
   ```bash
   python init_db.py
   ```

3. **Run the application:**
   ```bash
   python run.py
   ```

4. **Access the application:**
   - Visit: http://127.0.0.1:5000
   - Login at: http://127.0.0.1:5000/login

## 👤 Test Credentials

- **Email:** admin@test.com
- **Password:** password123
- **Role:** County Admin

## 🔐 Authentication Features

### Available Routes

| Route | Description | Authentication Required |
|-------|-------------|------------------------|
| `/` | Home page | No |
| `/login` | User login | No |
| `/register` | User registration | No |
| `/logout` | User logout | Yes |
| `/dashboard` | User dashboard | Yes |
| `/profile` | User profile | Yes |
| `/auth/current-user` | Current user API | Yes |
| `/auth/users` | List users API | Yes |

### User Model Features

- Email-based authentication
- Password hashing with bcrypt
- Role-based access control
- User profiles with first/last name
- Active/inactive user status
- Account creation timestamps

### Role System

Three predefined roles are available:

1. **Citizen** - Regular citizen user
2. **Department Officer** - Officer in specific departments  
3. **County Admin** - County administrator with full access

## 🛠️ Configuration

### Environment Variables

Create a `.env` file (see `.env.example`):

```env
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///county_services.db
SECURITY_PASSWORD_SALT=your-password-salt
```

### Flask-Security Settings

The application is configured with:
- User registration enabled
- Password recovery enabled
- User tracking enabled
- Password changes enabled
- Email confirmation disabled (for development)

## 📁 Project Structure

```
├── app/
│   ├── __init__.py          # App factory with Flask-Security setup
│   ├── extensions.py        # Flask extensions including Security
│   ├── models/
│   │   ├── __init__.py      # Model exports
│   │   └── user.py          # User and Role models
│   ├── main/
│   │   └── views.py         # Main application routes
│   ├── auth/
│   │   └── routes.py        # Authentication-related routes
│   └── api/
│       └── routes.py        # API endpoints
├── config.py                # Application configuration
├── init_db.py              # Database initialization script
├── run.py                  # Application entry point
└── requirements.txt        # Python dependencies
```

## 🔧 Extending the System

### Adding New Roles

```python
from app.models.user import Role
from app.extensions import db

# Create new role
new_role = Role(name='New Role', description='Description here')
db.session.add(new_role)
db.session.commit()
```

### Protected Routes Example

```python
from flask_security import login_required, roles_required

@app.route('/admin-only')
@login_required
@roles_required('County Admin')
def admin_only():
    return "Only county admins can see this"
```

### Creating Users Programmatically

```python
from app.models.user import User, Role
from flask_security.utils import hash_password
import uuid

user = User(
    email='user@example.com',
    password=hash_password('password'),
    first_name='John',
    last_name='Doe',
    fs_uniquifier=str(uuid.uuid4())
)

# Add role
role = Role.query.filter_by(name='Citizen').first()
user.roles.append(role)

db.session.add(user)
db.session.commit()
```

## ✅ Security Features

- CSRF protection on forms
- Password hashing with bcrypt
- Session management
- Role-based access control
- Secure cookie handling
- Protection against unauthorized access

## 🧪 Testing

Run the demo script to verify everything is working:

```bash
python demo_security.py
```

## 📚 Next Steps

1. Customize the User model for your specific needs
2. Add county and department relationships to users
3. Implement permit application workflows
4. Add email confirmation for registration
5. Create admin interface for user management
6. Add API authentication tokens

For more information about Flask-Security, visit: https://flask-security-too.readthedocs.io/
