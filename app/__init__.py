import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager
from flask_migrate import Migrate  # Import Migrate for database migrations

db = SQLAlchemy()
login_manager = LoginManager()  # Initialize LoginManager globally
migrate = Migrate()  # Initialize Migrate globally

def create_app():
    app = Flask(__name__)

    # Hardcoded database path
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/storage_system/instance/storage.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Static secret key for CSRF protection
    app.config['SECRET_KEY'] = '8oT4PMvH6'
    
    # Set a larger maximum content length for file uploads (1GB)
    app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024
    
    # Configuration for handling concurrent requests better
    app.config['UPLOAD_FOLDER'] = 'instance/user_storage'  # Root folder for user uploads
    app.config['THREADS_PER_PAGE'] = 8  # Number of threads per page
    app.config['PREFERRED_URL_SCHEME'] = 'http'  # URL scheme
    app.config['SERVER_NAME'] = None  # Allow dynamic server name

    # Initialize database, Migrate, and CSRF protection
    db.init_app(app)
    migrate.init_app(app, db)  # Link Migrate to the app and database
    csrf = CSRFProtect(app)

    # Initialize LoginManager
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'  # Redirect to 'login' route when not authenticated
    login_manager.login_message = "Please log in to access this page."  # Custom message for unauthenticated users

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User  # Importing User model here to avoid circular imports
        return User.query.get(int(user_id))  # Retrieve the user by their ID

    # Import and register blueprints
    from app.routes import main
    app.register_blueprint(main)

    # Create tables if they don't exist yet
    with app.app_context():
        db.create_all()

    return app