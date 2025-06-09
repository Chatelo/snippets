import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
SQLALCHEMY_DATABASE_URI = 'sqlite:///chatbot.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT', 'your-password-salt-change-in-production')
SECURITY_REGISTERABLE = True
SECURITY_SEND_REGISTER_EMAIL = False
SECURITY_LOGIN_USER_TEMPLATE = 'security/login.html'
SECURITY_REGISTER_USER_TEMPLATE = 'security/register.html'

# CSRF Protection
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = None

# Session Configuration
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
