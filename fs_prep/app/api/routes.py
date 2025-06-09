from flask import Blueprint

api_bp = Blueprint('api_bp', __name__, url_prefix='/api')

@api_bp.route('/status', methods=['GET'])
def status():
    """Endpoint to check the API status."""
    return "status:API is running with no issue!", 200