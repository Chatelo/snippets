# Modern Chatbot

A sleek, modern chatbot application built with Flask, featuring secure authentication, RESTful API, and beautiful UI with Lucide icons.

## 🚀 Features

- **Modern Flask Architecture**: Built with Flask 3.1.1 using the application factory pattern
- **Secure Authentication**: Flask-Security-Too for robust user management
- **RESTful API**: Flask-RESTful for clean API endpoints
- **Beautiful UI**: Tailwind CSS with Lucide icons for modern design
- **Real-time Chat**: Interactive chat interface with message history
- **SQLite Database**: Lightweight database with Flask-SQLAlchemy ORM
- **Security**: CSRF protection, secure sessions, and input validation

## 🛠️ Technology Stack

- **Backend**: Flask 3.1.1, Python 3.13.3
- **Database**: SQLite with Flask-SQLAlchemy
- **Authentication**: Flask-Security-Too
- **API**: Flask-RESTful
- **Frontend**: Tailwind CSS, Lucide Icons
- **Security**: Flask-WTF (CSRF protection)

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd productivity_tools_I
   ```

2. **Activate virtual environment**:
   ```bash
   source .productivity/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Initialize the database**:
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

## 🏃‍♂️ Running the Application

1. **Activate virtual environment**:
   ```bash
   source .productivity/bin/activate
   ```

2. **Run the application**:
   ```bash
   python run.py
   ```

3. **Access the application**:
   Open your browser and navigate to `http://localhost:5000`

## 📚 API Endpoints

### Chat API
- `POST /api/chat` - Send a message to the chatbot
- `GET /api/chat/history` - Get chat history for authenticated user

### Authentication (Flask-Security)
- `GET/POST /login` - User login
- `GET/POST /register` - User registration
- `GET /logout` - User logout

## 🗂️ Project Structure

```
chatbot/
├── app/
│   ├── __init__.py          # Application factory
│   ├── models.py            # Database models
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── api.py           # API routes
│   │   └── web_routes.py    # Web routes
│   ├── templates/           # Jinja2 templates
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── chat.html
│   │   ├── about.html
│   │   ├── 404.html
│   │   ├── 500.html
│   │   └── security/        # Authentication templates
│   │       ├── login.html
│   │       ├── register.html
│   │       ├── _macros.html
│   │       └── _messages.html
│   └── static/
│       ├── css/
│       │   └── style.css    # Custom styles
│       └── js/
│           ├── main.js      # Main JavaScript
│           └── chat.js      # Chat functionality
├── migrations/              # Database migrations
├── instance/
│   └── config.py           # Configuration
├── requirements.txt         # Python dependencies
├── run.py                  # Application entry point
├── .env.example            # Environment variables template
└── README.md              # This file
```

## 🔧 Configuration

The application uses instance-relative configuration. Key settings in `instance/config.py`:

- `SECRET_KEY`: Flask secret key for sessions
- `SECURITY_PASSWORD_SALT`: Salt for password hashing
- `SQLALCHEMY_DATABASE_URI`: Database connection string
- Security and CSRF settings

## 🛡️ Security Features

- **CSRF Protection**: All forms protected against Cross-Site Request Forgery
- **Secure Sessions**: HTTPOnly and Secure cookie flags
- **Password Hashing**: Secure password storage with Flask-Security
- **Input Validation**: Server-side validation for all inputs
- **SQL Injection Prevention**: ORM-based queries

## 🎨 Customization

### Adding New Chat Responses
Edit the `_generate_response` method in `app/routes/api.py` to customize bot responses.

### Styling
- Modify `app/static/css/style.css` for custom styles
- Update templates in `app/templates/` for layout changes
- Tailwind CSS classes can be customized

### Database Models
Add new models in `app/models.py` and create migrations:
```bash
flask db migrate -m "Description of changes"
flask db upgrade
```

## 🚀 Deployment

### Production Setup
1. Set strong `SECRET_KEY` and `SECURITY_PASSWORD_SALT`
2. Use a production database (PostgreSQL recommended)
3. Enable HTTPS
4. Use a WSGI server like Gunicorn
5. Set up reverse proxy with Nginx

### Environment Variables for Production
```bash
export SECRET_KEY="your-production-secret-key"
export SECURITY_PASSWORD_SALT="your-production-salt"
export DATABASE_URL="postgresql://user:pass@localhost/dbname"
export FLASK_ENV="production"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions:
- Check the documentation
- Review the code examples
- Create an issue on GitHub

---

Built with ❤️ using Flask and modern web technologies.
