# Secure Storage System

A professional, feature-rich and secure file storage and sharing platform built with Flask.

![Storage System Dashboard](static/img/dashboard-preview.png)

## Overview

Secure Storage System is a comprehensive web-based file management solution that allows users to securely upload, organize, and share files. Built with security and usability in mind, it provides a robust platform for personal and team file storage needs.

## Key Features

- **Secure User Authentication**: Registration, login, and password management
- **File Management**: Upload, download, rename, and organize files
- **Folder System**: Create and manage folder hierarchies
- **File Sharing**: Share files and folders with public links or specific users
- **Trash Management**: Deleted files are moved to trash with restore options
- **Admin Panel**: User management, whitelisting, audit logs, and system monitoring
- **Security Features**: CSRF protection, secure password hashing, and audit logging
- **Responsive Design**: Modern UI that works across devices

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy with SQLite
- **Authentication**: Flask-Login
- **Form Handling**: Flask-WTF and WTForms
- **Frontend**: HTML, CSS, JavaScript
- **Security**: Werkzeug security features

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/storage-system.git
   cd storage-system
   ```

2. Set up a virtual environment:
   ```bash
   python -m venv venv
   # On Windows
   venv\Scripts\activate
   # On Unix/MacOS
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Initialize the database:
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

5. Start the server:
   ```bash
   python server.py
   ```

## Development

### Project Structure

```
storage_system/
├── app/                  # Main application package
│   ├── __init__.py       # Application factory
│   ├── config.py         # Configuration settings
│   ├── forms.py          # Form definitions
│   ├── models.py         # Database models
│   ├── routes.py         # Route definitions
│   └── templates/        # HTML templates
├── instance/             # Instance-specific files (database, user uploads)
├── migrations/           # Database migrations
├── scripts/              # Utility scripts
├── static/               # Static files (CSS, JS, images)
├── venv/                 # Virtual environment
├── requirements.txt      # Project dependencies
└── server.py             # Server entry point
```

## Security Features

- Secure password hashing with Scrypt
- CSRF protection on all forms
- Comprehensive audit logging
- File type validation
- User whitelisting for sensitive file types
- Session management

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request 

Disclaimer this project is not intended for production and is no where near finished. 
This website was modified by AI generated code, this means that some of the practises used in this program may not be the fastest, most secure, or pratical. 


I did like 6 updates I forgot to push.
![image](https://github.com/user-attachments/assets/663de135-63fd-4abc-811d-5efc0c3c4a2f)
