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

    def __repr__(self):
        return f"<User {self.username}>"

class File(db.Model):
    __tablename__ = 'File'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)
    folder_name = db.Column(db.String(255), nullable=False)
    upload_time = db.Column(db.DateTime, default=db.func.now())
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    unique_id = db.Column(db.String(36), unique=True, default=str(uuid.uuid4))  # Unique identifier
    shared = db.Column(db.Boolean, default=False)  # Sharing toggle
    deleted = db.Column(db.Boolean, default=False)  # Tracks if file is deleted

    def __repr__(self):
        return f"<File {self.filename}>"
