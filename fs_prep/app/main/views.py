from flask import Blueprint
from flask_security import login_required, current_user


main_bp = Blueprint('main_bp', __name__)

@main_bp.route('/', methods=['GET'])
def home():
    """Endpoint to handle the home route."""
    return "Welcome to the County Services Portal!", 200

@main_bp.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    """Protected dashboard route that requires authentication."""
    return {
        "message": f"Welcome to your dashboard, {current_user.email}!",
        "user_id": current_user.id,
        "user_roles": [role.name for role in current_user.roles],
        "status": "success"
    }, 200

@main_bp.route('/profile', methods=['GET'])
@login_required
def profile():
    """Get current user profile information."""
    return {
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "first_name": current_user.first_name,
            "last_name": current_user.last_name,
            "full_name": current_user.full_name,
            "active": current_user.active,
            "roles": [role.name for role in current_user.roles]
        },
        "status": "success"
    }, 200