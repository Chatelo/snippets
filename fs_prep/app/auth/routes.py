from flask import Blueprint
from flask_security import login_required, current_user
from app.models.user import User

auth_bp = Blueprint('auth_bp', __name__, url_prefix='/auth')

@auth_bp.route('/users', methods=['GET'])
@login_required
def list_users():
    """List all users - basic endpoint for testing."""
    users = User.query.all()
    users_data = []
    
    for user in users:
        users_data.append({
            "id": user.id,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "active": user.active,
            "roles": [role.name for role in user.roles]
        })
    
    return {
        "users": users_data,
        "total": len(users_data),
        "status": "success"
    }, 200

@auth_bp.route('/current-user', methods=['GET'])
@login_required
def get_current_user():
    """Get current authenticated user information."""
    return {
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "first_name": current_user.first_name,
            "last_name": current_user.last_name,
            "full_name": current_user.full_name,
            "active": current_user.active,
            "roles": [role.name for role in current_user.roles],
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None
        },
        "status": "success"
    }, 200