# Secure Storage System - Technical Documentation

This document provides detailed information about the architecture, implementation, and usage of the Secure Storage System.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Database Schema](#database-schema)
3. [Authentication System](#authentication-system)
4. [File Management](#file-management)
5. [Sharing System](#sharing-system)
6. [Admin Functionality](#admin-functionality)
7. [Security Implementations](#security-implementations)
8. [API Reference](#api-reference)
9. [Deployment Guide](#deployment-guide)
10. [Troubleshooting](#troubleshooting)

## Architecture Overview

The Secure Storage System follows a classic MVC (Model-View-Controller) architecture using Flask as the web framework:

- **Models**: Database structure defined with SQLAlchemy ORM
- **Views**: HTML templates with Bootstrap for responsive design
- **Controllers**: Flask routes and business logic

The application is modularized using Flask Blueprints, and utilizes a factory pattern for application initialization.

### Key Components

- **Flask Application Factory**: Centralized app initialization in `app/__init__.py`
- **SQLAlchemy Models**: Database models defined in `app/models.py`
- **Blueprints**: Main blueprint in `app/routes.py`
- **Forms**: WTForms integration in `app/forms.py`
- **Configuration**: Configuration settings in `app/config.py`

## Database Schema

The application uses SQLAlchemy with SQLite and includes the following main models:

### User Model

```python
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_whitelisted = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
```

### File Model

```python
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    folder_name = db.Column(db.String(255), nullable=False)
    original_folder = db.Column(db.String(255), nullable=True)
    upload_time = db.Column(db.DateTime, default=db.func.now())
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    unique_id = db.Column(db.String(36), unique=True, default=str(uuid.uuid4()))
    shared = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)
```

### AuditLog Model

```python
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
```

### Share Model

```python
class Share(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    share_type = db.Column(db.String(20), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('File.id'), nullable=True)
    folder_path = db.Column(db.String(255), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=True)
    recipient_email = db.Column(db.String(120), nullable=True)
    share_key = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    is_public = db.Column(db.Boolean, default=False)
```

## Authentication System

The system uses Flask-Login for user authentication with the following features:

- **Registration**: New users can register with a username, email, and password
- **Login**: Users authenticate with email and password
- **Session Management**: Flask-Login handles user session management
- **Password Security**: Passwords are hashed using Werkzeug's Scrypt algorithm
- **User Roles**: Basic users and admin users with different privileges
- **Whitelisting**: Special permissions for uploading sensitive file types

### Authentication Flow

1. User submits registration form with email, username, and password
2. System validates input and checks for existing users
3. Password is hashed using Scrypt
4. User record is created in the database
5. User can then log in using credentials
6. On login, Flask-Login manages the user session

## File Management

The system provides a comprehensive file management solution with the following features:

### File Operations

- **Upload**: Users can upload files with validation for file types
- **Download**: Files can be downloaded by the owner or via shared links
- **Delete**: Files can be moved to trash before permanent deletion
- **Rename**: File names can be modified
- **Move**: Files can be moved between folders
- **Restore**: Deleted files can be restored from trash

### Folder Operations

- **Create**: Users can create nested folder structures
- **Delete**: Folders can be deleted with all contained files
- **Rename**: Folder names can be changed
- **Navigate**: Users can browse through folder hierarchies

### File Storage

Files are stored in the filesystem with a structured approach:
- Base path: `instance/user_storage/`
- User folders: `instance/user_storage/<user_id>/`
- Nested folders: `instance/user_storage/<user_id>/<folder_path>/`

File metadata is stored in the database for quick searching and listing, while the actual files are stored in the filesystem.

## Sharing System

The system provides flexible file and folder sharing capabilities:

### Sharing Features

- **Public Links**: Generate public links for files and folders
- **User-to-User Sharing**: Share directly with other registered users
- **Access Control**: Control who can access shared content
- **Share Management**: View and manage active shares

### Sharing Implementation

The Share model tracks all sharing relationships with unique share keys. When a file or folder is shared, a new Share record is created with a unique key. This key is used in public URLs for accessing the shared content.

## Admin Functionality

Administrators have access to a dedicated admin panel with the following capabilities:

### Admin Features

- **User Management**: View and manage user accounts
- **Whitelist Control**: Grant special permissions to trusted users
- **Password Reset**: Reset user passwords
- **Audit Logs**: View comprehensive system logs
- **System Statistics**: Monitor storage usage and activity

### Admin Security

Admin functions are protected by role-based authentication. Only users with the `is_admin` flag set to `True` can access these features.

## Security Implementations

The system is designed with security as a priority:

### Security Features

- **CSRF Protection**: All forms are protected against Cross-Site Request Forgery
- **Password Hashing**: Secure password storage using Scrypt
- **Input Validation**: Form validation for all user inputs
- **File Type Validation**: Restrict uploading of potentially harmful file types
- **Audit Logging**: Comprehensive logging of all security-relevant actions
- **Access Control**: Proper authentication and authorization checks
- **Session Security**: Secure session management with Flask-Login

## API Reference

The system provides a set of routes for various operations:

### Authentication Routes

- `GET/POST /register` - User registration
- `GET/POST /login` - User login
- `GET /logout` - User logout

### File Management Routes

- `GET /dashboard` - Main file management interface
- `POST /upload_file` - Upload new files
- `GET /download_file/<file_id>` - Download a file
- `POST /rename_file/<file_id>` - Rename a file
- `POST /delete_file/<file_id>` - Move a file to trash
- `POST /delete_multiple` - Delete multiple files

### Folder Management Routes

- `POST /create_folder` - Create a new folder
- `POST /delete_folder` - Delete a folder
- `POST /rename_folder` - Rename a folder

### Sharing Routes

- `POST /toggle_sharing/<file_id>` - Toggle file sharing
- `GET /public_share/<share_key>` - Access shared file
- `POST /toggle_folder_sharing` - Toggle folder sharing
- `GET /public_folder_share/<share_key>` - Access shared folder

### Trash Management

- `GET /trash` - View trash contents
- `POST /restore_file/<file_id>` - Restore file from trash
- `POST /permanently_delete_file/<file_id>` - Permanently delete file

### Admin Routes

- `GET /admin` - Admin dashboard
- `POST /admin/toggle_whitelist/<user_id>` - Toggle user whitelist status
- `POST /admin/reset_password/<user_id>` - Reset user password
- `GET /admin/logs` - View system logs

## Deployment Guide

### Prerequisites

- Python 3.8 or higher
- Pip package manager
- Virtual environment (recommended)

### Production Deployment Steps

1. **Server Setup**:
   - Set up a server with Python installed
   - Install required system dependencies

2. **Application Deployment**:
   - Clone the repository to your server
   - Create and activate a virtual environment
   - Install dependencies with `pip install -r requirements.txt`

3. **Configuration**:
   - Configure database connection in `app/__init__.py`
   - Set a secure SECRET_KEY
   - Configure file storage paths

4. **Database Initialization**:
   - Run database migrations:
     ```
     flask db upgrade
     ```

5. **Web Server Configuration**:
   - Set up a production WSGI server (Gunicorn, uWSGI)
   - Configure a reverse proxy (Nginx, Apache)

6. **Security Hardening**:
   - Enable HTTPS
   - Set appropriate file permissions
   - Configure firewall rules

## Troubleshooting

### Common Issues

1. **Database Connection Problems**:
   - Check database path in configuration
   - Ensure proper permissions for database files

2. **File Upload Issues**:
   - Verify that upload directories exist and have write permissions
   - Check MAX_CONTENT_LENGTH in configuration

3. **Authentication Problems**:
   - Clear browser cookies
   - Reset user password through admin panel

4. **Performance Issues**:
   - Optimize database queries
   - Consider adding indexes to frequently queried columns
   - Adjust THREADS_PER_PAGE configuration

### Logging

The system includes comprehensive logging:

- **Audit Logs**: Stored in the database for security-relevant events
- **Application Logs**: Printed to stderr and can be captured by your deployment environment
- **Colored Output**: Uses termcolor for better readability in console logs 