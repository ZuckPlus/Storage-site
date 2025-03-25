from app import db
from flask_login import UserMixin
import uuid

class User(db.Model, UserMixin):
    __tablename__ = 'User'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_whitelisted = db.Column(db.Boolean, default=False)  # New field for whitelist status
    is_admin = db.Column(db.Boolean, default=False)  # Admin status flag

    def __repr__(self):
        return f"<User {self.username}>"

class File(db.Model):
    __tablename__ = 'File'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    folder_name = db.Column(db.String(255), nullable=False)  # Current location
    original_folder = db.Column(db.String(255), nullable=True)  # Original location for restoration
    upload_time = db.Column(db.DateTime, default=db.func.now())
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    unique_id = db.Column(db.String(36), unique=True, default=str(uuid.uuid4()))  # Unique identifier
    shared = db.Column(db.Boolean, default=False)
    is_deleted = db.Column(db.Boolean, default=False)  # Indicates if the file is in the trash

    def __repr__(self):
        return f"<File {self.filename}>"

class AuditLog(db.Model):
    __tablename__ = 'AuditLog'
    
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    action = db.Column(db.String(255), nullable=False)  # Type of action (login, upload, delete, etc.)
    details = db.Column(db.Text, nullable=True)  # Additional details about the action
    ip_address = db.Column(db.String(45), nullable=True)  # Store IP address (IPv4 or IPv6)
    
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))
    
    def __repr__(self):
        return f"<AuditLog {self.id}: {self.action}>"

class Share(db.Model):
    __tablename__ = 'Share'
    
    id = db.Column(db.Integer, primary_key=True)
    share_type = db.Column(db.String(20), nullable=False)  # 'file', 'folder'
    file_id = db.Column(db.Integer, db.ForeignKey('File.id'), nullable=True)  # If sharing a file
    folder_path = db.Column(db.String(255), nullable=True)  # If sharing a folder
    owner_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)  # Who shared it
    recipient_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=True)  # Who it's shared with (null for public links)
    recipient_email = db.Column(db.String(120), nullable=True)  # If shared directly with user
    share_key = db.Column(db.String(64), unique=True, nullable=False)  # Unique key for the share
    created_at = db.Column(db.DateTime, default=db.func.now())
    expires_at = db.Column(db.DateTime, nullable=True)  # Optional expiration
    is_active = db.Column(db.Boolean, default=True)
    is_public = db.Column(db.Boolean, default=False)  # Whether this is a public link
    
    # Relationships
    owner = db.relationship('User', foreign_keys=[owner_id], backref=db.backref('shared_items', lazy=True))
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref=db.backref('received_shares', lazy=True))
    file = db.relationship('File', backref=db.backref('shares', lazy=True))
    
    def __repr__(self):
        share_target = f"file:{self.file_id}" if self.file_id else f"folder:{self.folder_path}"
        return f"<Share {self.id}: {share_target} by {self.owner_id}>"
