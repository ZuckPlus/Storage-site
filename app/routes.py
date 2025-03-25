from flask import render_template, redirect, url_for, flash, request, send_from_directory, current_app, jsonify
from flask import Blueprint
from flask_login import login_required, logout_user, login_user, current_user
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models import User, File, AuditLog, Share
from app.forms import RegistrationForm, LoginForm, FolderForm, PasswordChangeForm
from app.config import ALLOWED_FILE_TYPES
import mimetypes
import uuid
from concurrent.futures import ThreadPoolExecutor
import shutil
from termcolor import colored
import sys
import hashlib
import secrets
from datetime import datetime

# Initialize the blueprint
main = Blueprint('main', __name__)
executor = ThreadPoolExecutor(max_workers=4)  # Adjust the number of workers based on server resources

# List of allowed file types
ALLOWED_FILE_TYPES = [
    # Document Formats
    'txt', 'doc', 'docx', 'odt', 'rtf', 'pdf', 'tex', 'md', 'epub', 'csv', 'xls', 'xlsx', 'xlsm', 'ods',
    'ppt', 'pptx', 'odp', 'pps', 'ppsx', 'key', 'wpd', 'one', 'pub', 'log',

    # Image Formats
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'tif', 'psd', 'ai', 'eps', 'svg', 'ico', 'webp', 'raw',
    'cr2', 'nef', 'orf', 'raf', 'heif', 'indd', 'sketch', 'xcf', 'dng',

    # Video Formats
    'mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'f4v', 'swf', 'webm', 'vob', 'mpg', 'mpeg', '3gp', 'ogv',
    'm4v', 'mts', 'm2ts', 'ts', 'divx', 'rm', 'rmvb',

    # Audio Formats
    'mp3', 'wav', 'aac', 'flac', 'ogg', 'm4a', 'wma', 'aiff', 'alac', 'opus', 'mid', 'midi',

    # Compressed Formats
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'dmg', 'tgz', 'cab', 'lzma', 'apk', 'jar',

    # Executable & System Files (whitelisted users only)
    'exe', 'msi', 'bat', 'sh', 'bin', 'cmd', 'app', 'deb', 'rpm', 'dll', 'sys', 'drv', 'so', 'pkg', 'out',

    # Database Formats
    'db', 'sql', 'sqlite', 'mdb', 'accdb', 'dbf', 'json', 'xml', 'csv', 'yaml', 'yml',
]

# Utility function to log audit events
def log_audit_event(action, details=None):
    """
    Log an audit event to the database
    
    Args:
        action (str): The action being performed (login, upload, delete, etc.)
        details (str, optional): Additional details about the action
    """
    try:
        if current_user.is_authenticated:
            # Get IP address
            ip_address = request.remote_addr
            
            # Create audit log entry
            audit_log = AuditLog(
                user_id=current_user.id,
                action=action,
                details=details,
                ip_address=ip_address
            )
            
            db.session.add(audit_log)
            db.session.commit()
            
            # Also print to console for server logs
            print(colored(f"AUDIT: {action} by {current_user.username} - {details}", "cyan"), file=sys.stderr)
    except Exception as e:
        print(colored(f"ERROR logging audit event: {str(e)}", "red"), file=sys.stderr)
        db.session.rollback()

@main.route('/')
def home():
    return render_template('home.html')

# Registration
@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return redirect(url_for('main.register'))

        hashed_password = generate_password_hash(password, method='scrypt')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

# Login
@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            # Log login event
            log_audit_event('login', f"User logged in from IP {request.remote_addr}")
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')
    
    return render_template('login.html', form=form)

# Logout
@main.route('/logout')
@login_required
def logout():
    # Log logout event before actually logging out
    log_audit_event('logout', f"User logged out from IP {request.remote_addr}")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.home'))

def search_files(app, user_id, search_query, filter_type, base_path, include_trash=False):
    # Get all files for the user
    query = File.query.filter_by(user_id=user_id)
    
    # Only include trash items if specifically requested
    if not include_trash:
        query = query.filter_by(is_deleted=False)
    
    # Apply file type filter if specified
    if filter_type:
        if filter_type == 'image':
            query = query.filter(File.file_type.like('image/%'))
        elif filter_type == 'pdf':
            query = query.filter(File.file_type == 'application/pdf')
        elif filter_type == 'video':
            query = query.filter(File.file_type.like('video/%'))
        elif filter_type == 'audio':
            query = query.filter(File.file_type.like('audio/%'))
    
    # Apply search query
    if search_query:
        query = query.filter(File.filename.ilike(f'%{search_query}%'))
    
    return query.all()

@main.route('/search_results', methods=['GET'])
@login_required
def search_results():
    search_query = request.args.get('search', '')
    filter_type = request.args.get('filter', '')
    include_trash = request.args.get('include_trash', 'false').lower() == 'true'
    
    base_path = os.path.join(os.getcwd(), 'instance', 'user_storage')
    files = search_files(current_app, current_user.id, search_query, filter_type, base_path, include_trash)
    
    return render_template('search_results.html', 
                         files=files, 
                         search=search_query, 
                         file_filter=filter_type,
                         include_trash=include_trash)

@main.route('/dashboard/async_load', methods=['GET'])
@login_required
def async_load_content():
    parent_folder = request.args.get('parent_folder', '')
    
    # Log the async load attempt with color
    print(colored(f"\n[ASYNC LOAD] Loading content:", 'magenta'), file=sys.stderr)
    print(colored(f"  • Parent Folder: {parent_folder or 'root'}", 'magenta'), file=sys.stderr)
    
    # Build the current path
    user_base_path = os.path.abspath(os.path.join('instance/user_storage', str(current_user.id)))
    current_path = os.path.join(user_base_path, parent_folder)
    print(colored(f"  • Current Path: {current_path}", 'magenta'), file=sys.stderr)
    
    def load_folders():
        try:
            print(colored(f"  • Scanning directory: {current_path}", 'magenta'), file=sys.stderr)
            folders = []
            
            # Create the directory if it doesn't exist
            if not os.path.exists(current_path):
                os.makedirs(current_path)
                print(colored(f"  • Created directory: {current_path}", 'green'), file=sys.stderr)
                
            # List all directories in the current folder
            for item in os.listdir(current_path):
                item_path = os.path.join(current_path, item)
                if os.path.isdir(item_path) and item != 'Trash':
                    folders.append(item)
                    
            print(colored(f"  • [SUCCESS] Found {len(folders)} folders", 'green'), file=sys.stderr)
            for folder in folders:
                print(colored(f"    - {folder}", 'green'), file=sys.stderr)
            return folders
            
        except Exception as e:
            print(colored(f"  • [ERROR] Failed to list directories: {str(e)}", 'red'), file=sys.stderr)
            return []

    def load_files():
        try:
            # Query files in the current folder
            files_query = File.query.filter_by(
                user_id=current_user.id,
                folder_name=parent_folder,
                is_deleted=False
            ).all()
            
            print(colored(f"  • [SUCCESS] Found {len(files_query)} files in database for folder: {parent_folder or 'root'}", 'green'), file=sys.stderr)
            
            # Prepare files for JSON response
            files_data = []
            for file in files_query:
                file_info = {
                    'id': file.id,
                    'filename': file.filename,
                    'file_type': file.file_type,
                    'size': file.file_size,
                    'created_at': file.upload_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'download_url': url_for('main.download_file', file_id=file.id),
                    'shared': file.shared
                }
                files_data.append(file_info)
            return files_data
            
        except Exception as e:
            print(colored(f"  • [ERROR] Failed to load files: {str(e)}", 'red'), file=sys.stderr)
            return []

    # Load folders and files
    folders = load_folders()
    files = load_files()
    
    # Log completion
    print(colored(f"  • [COMPLETE] Async load finished", 'green'), file=sys.stderr)
    print(colored(f"    - Folders: {len(folders)}", 'green'), file=sys.stderr)
    print(colored(f"    - Files: {len(files)}", 'green'), file=sys.stderr)
    
    return jsonify({
        'folders': folders,
        'files': files
    })

@main.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    parent_folder = request.args.get('parent_folder', '')
    search_query = request.args.get('search', '')
    file_filter = request.args.get('filter', '')

    if search_query:
        return redirect(url_for('main.search_results', search=search_query, filter=file_filter))

    user_base_path = os.path.abspath(os.path.join('instance/user_storage', str(current_user.id)))
    
    # Security check: ensure the requested folder is within user's directory
    if parent_folder:
        requested_path = os.path.abspath(os.path.join(user_base_path, parent_folder))
        
        # Check if the path is valid and exists
        if not os.path.exists(requested_path):
            flash('Folder not found.', 'danger')
            return redirect(url_for('main.dashboard'))
            
        # Check if the path is within the user's directory
        if not requested_path.startswith(user_base_path):
            flash('Invalid folder location.', 'danger')
            return redirect(url_for('main.dashboard'))
    
    current_folder_path = os.path.join(user_base_path, parent_folder)

    # Ensure the current folder exists
    os.makedirs(current_folder_path, exist_ok=True)

    # Initialize empty lists - content will be loaded asynchronously
    folders = []
    files = []

    # Initialize the folder creation form
    form = FolderForm()
    return render_template(
        'dashboard.html',
        folders=folders,
        files=files,
        parent_folder=parent_folder,
        form=form,
        search=search_query,
        file_filter=file_filter,
        shared_view=False
    )

# Shared with me view
@main.route('/shared_with_me', methods=['GET'])
@login_required
def shared_with_me():
    # Get all shares where the current user is the recipient
    shares = Share.query.filter_by(recipient_id=current_user.id, is_active=True).all()
    
    # Get all files shared with the current user
    shared_files = []
    for share in shares:
        if share.file_id:
            file = File.query.get(share.file_id)
            if file and not file.is_deleted:
                # Add owner information to the file
                owner = User.query.get(share.owner_id)
                file.owner_name = owner.username if owner else "Unknown"
                file.share_id = share.id
                shared_files.append(file)
    
    # Initialize the folder creation form (for consistency with dashboard template)
    form = FolderForm()
    
    return render_template(
        'dashboard.html',
        folders=[],  # No folders in shared view for now
        files=shared_files,
        parent_folder="",
        form=form,
        search="",
        file_filter="",
        shared_view=True
    )

# Reload user session
@main.route('/reload_user_session')
@login_required
def reload_user_session():
    user = User.query.get(current_user.id)
    login_user(user)
    flash('User session reloaded successfully!', 'success')
    return redirect(url_for('main.dashboard'))

# Folder creation
@main.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    folder_name = request.form.get('folder_name')
    parent_folder = request.form.get('parent_folder', '')

    if not folder_name:
        flash('Folder name cannot be empty.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    # Clean and validate the folder name - Prevent path traversal
    folder_name = secure_filename(folder_name)
    
    # Log folder creation attempt with color
    print(colored(f"\n[FOLDER CREATE] Attempting to create:", 'magenta'), file=sys.stderr)
    print(colored(f"  • Folder Name: {folder_name}", 'magenta'), file=sys.stderr)
    print(colored(f"  • Parent Folder: {parent_folder or 'root'}", 'magenta'), file=sys.stderr)
    
    # Get absolute paths to ensure proper path handling
    user_base_path = os.path.abspath(os.path.join('instance/user_storage', str(current_user.id)))
    
    # Create full paths for parent and new folder
    if parent_folder:
        # Clean and normalize the parent folder path
        parent_folder_path = os.path.abspath(os.path.join(user_base_path, parent_folder))
        
        # Security check: ensure parent path exists and is within user directory
        if not os.path.exists(parent_folder_path):
            print(colored(f"  • [ERROR] Parent folder doesn't exist: {parent_folder_path}", 'red'), file=sys.stderr)
            flash('Parent folder does not exist.', 'danger')
            return redirect(url_for('main.dashboard'))
            
        if not parent_folder_path.startswith(user_base_path):
            print(colored(f"  • [ERROR] Security check failed - Parent path outside user directory", 'red'), file=sys.stderr)
            flash('Invalid folder location.', 'danger')
            return redirect(url_for('main.dashboard'))
            
        # Create the new folder inside the parent folder
        new_folder_path = os.path.join(parent_folder_path, folder_name)
    else:
        # Create folder at root level of user directory
        new_folder_path = os.path.join(user_base_path, folder_name)
    
    print(colored(f"  • Target Path: {new_folder_path}", 'magenta'), file=sys.stderr)

    # Verify the new folder would still be within the user's directory
    if not os.path.abspath(new_folder_path).startswith(user_base_path):
        print(colored(f"  • [ERROR] Security check failed - New folder would be outside user directory", 'red'), file=sys.stderr)
        flash('Invalid folder location.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    try:
        # Check if folder already exists
        if os.path.exists(new_folder_path):
            print(colored(f"  • [ERROR] Folder already exists at: {new_folder_path}", 'red'), file=sys.stderr)
            flash(f'Folder "{folder_name}" already exists.', 'danger')
        else:
            # Create the folder
            os.makedirs(new_folder_path)
            print(colored(f"  • [SUCCESS] Folder created at: {new_folder_path}", 'green'), file=sys.stderr)
            flash(f'Folder "{folder_name}" created successfully!', 'success')
    except Exception as e:
        print(colored(f"  • [ERROR] Failed to create folder: {str(e)}", 'red'), file=sys.stderr)
        flash('Error creating folder. Please try again.', 'danger')

    # Log the redirect destination
    print(colored(f"  • Redirecting to: dashboard with parent_folder={parent_folder}", 'magenta'), file=sys.stderr)
    
    # Redirect back to the current folder
    return redirect(url_for('main.dashboard', parent_folder=parent_folder))

# Folder deletion
@main.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    folder_name = request.form.get('folder_name')
    parent_folder = request.form.get('parent_folder', '')
    
    if not folder_name:
        flash('No folder specified.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))
    
    # Construct the absolute paths
    user_base_path = os.path.abspath(os.path.join('instance/user_storage', str(current_user.id)))
    
    # Build the full path to the folder
    if parent_folder:
        # Get absolute path of parent folder
        parent_folder_path = os.path.abspath(os.path.join(user_base_path, parent_folder))
        
        # Security check: Ensure parent folder is within user directory
        if not parent_folder_path.startswith(user_base_path):
            flash('Invalid folder location.', 'danger')
            return redirect(url_for('main.dashboard'))
            
        # Construct the full path to the folder to delete
        folder_path = os.path.join(parent_folder_path, folder_name)
    else:
        # Delete from root level
        folder_path = os.path.join(user_base_path, folder_name)
    
    # Security check: Ensure target folder is within user directory
    if not os.path.abspath(folder_path).startswith(user_base_path):
        flash('Invalid folder location.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))
    
    # Check if the folder exists
    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        flash(f'Folder "{folder_name}" does not exist.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))
    
    try:
        # Get all files in the folder and its subfolders
        for root, _, files in os.walk(folder_path):
            # Calculate relative path from user's base directory
            rel_path = os.path.relpath(root, user_base_path)
            if rel_path == '.':
                rel_path = ''
                
            # Move files to trash in database
            for file in files:
                file_obj = File.query.filter_by(
                    user_id=current_user.id,
                    filename=file,
                    folder_name=rel_path
                ).first()
                
                if file_obj:
                    # Mark the file as deleted and store original location
                    file_obj.is_deleted = True
                    file_obj.original_folder = file_obj.folder_name
                    file_obj.folder_name = 'Trash'
                    db.session.add(file_obj)
        
        # Commit all changes at once
        db.session.commit()
        
        # Delete the folder from filesystem
        shutil.rmtree(folder_path)
        flash(f'Folder "{folder_name}" has been moved to trash.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting folder: {str(e)}', 'danger')
    
    # Redirect back to parent folder or root
    if parent_folder:
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))
    else:
        return redirect(url_for('main.dashboard'))

def get_unique_filename(base_path, filename):
    """Generate a unique filename by appending a counter if the file exists."""
    name, ext = os.path.splitext(filename)
    counter = 1
    new_filename = filename
    
    while os.path.exists(os.path.join(base_path, new_filename)):
        new_filename = f"{name}_({counter}){ext}"
        counter += 1
        
    return new_filename

@main.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    parent_folder = request.form.get('parent_folder', '')
    print(colored(f"Upload request received - Parent folder: '{parent_folder}'", 'magenta'), file=sys.stderr)
    
    # Check if files are in the request
    if 'files[]' not in request.files:
        flash('No files selected.', 'danger')
        log_audit_event('upload_failure', f"No files selected in upload request")
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))
    
    files = request.files.getlist('files[]')
    if not files or files[0].filename == '':
        flash('No files selected.', 'danger')
        log_audit_event('upload_failure', f"Empty file selection in upload request")
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))
    
    # Get user directory
    user_directory = os.path.join(current_app.config['UPLOAD_FOLDER'], str(current_user.id))
    if not os.path.exists(user_directory):
        os.makedirs(user_directory)
    
    # Determine folder path
    full_folder_path = user_directory
    if parent_folder:
        full_folder_path = os.path.join(user_directory, parent_folder)
    
    # Normalize and validate path
    full_folder_path = os.path.normpath(full_folder_path)
    user_directory = os.path.normpath(user_directory)
    
    # Security check - make sure the target path is within the user's directory
    if os.path.commonpath([full_folder_path, user_directory]) != user_directory:
        print(colored(f"    - [ERROR] Invalid folder path detected: {full_folder_path}", 'red'), file=sys.stderr)
        flash('Invalid folder path.', 'danger')
        log_audit_event('security_violation', f"Attempted to access invalid path: {full_folder_path}")
        return redirect(url_for('main.dashboard'))
    
    # Create the folder if it doesn't exist
    if not os.path.exists(full_folder_path):
        os.makedirs(full_folder_path)
        
    # Process the files
    successful_uploads = 0
    failed_uploads = 0
    error_messages = []
    renamed_files = []
    
    for file in files:
        original_filename = file.filename
        try:
            print(colored(f"Processing file: {original_filename}", 'cyan'), file=sys.stderr)
            
            # Secure the filename
            filename = secure_filename(original_filename)
            if not filename:
                print(colored(f"    - [REJECTED] Invalid filename: {original_filename}", 'red'), file=sys.stderr)
                error_messages.append(f"Invalid filename: {original_filename}")
                failed_uploads += 1
                continue
            
            # Generate a unique filename to prevent overwrites
            unique_filename = get_unique_filename(full_folder_path, filename)
            
            # Check file extension
            file_extension = unique_filename.rsplit('.', 1)[1].lower() if '.' in unique_filename else ''
            
            # Check if file extension is allowed (unless user is whitelisted)
            if not current_user.is_whitelisted and file_extension not in ALLOWED_FILE_TYPES:
                print(colored(f"    - [REJECTED] File type not allowed: .{file_extension}", 'red'), file=sys.stderr)
                error_messages.append(f"File type '.{file_extension}' is not allowed: {unique_filename}")
                failed_uploads += 1
                log_audit_event('upload_blocked', f"Blocked upload of file with disallowed extension: {unique_filename} (.{file_extension})")
                continue
            
            # Save the file
            file_path = os.path.join(full_folder_path, unique_filename)
            file.save(file_path)
            print(colored(f"    - Saved to: {file_path}", 'cyan'), file=sys.stderr)
            
            # Get file info
            file_size = os.path.getsize(file_path)
            file_type = mimetypes.guess_type(unique_filename)[0] or 'application/octet-stream'
            unique_id = str(uuid.uuid4())
            
            # Create database entry
            new_file = File(
                filename=unique_filename,
                user_id=current_user.id,
                folder_name=parent_folder,
                file_size=file_size,
                file_type=file_type,
                unique_id=unique_id
            )
            db.session.add(new_file)
            successful_uploads += 1
            print(colored(f"    - [SUCCESS] File uploaded successfully", 'green'), file=sys.stderr)
            
            # Log successful upload
            log_audit_event('file_upload', f"Uploaded file {unique_filename} ({file_size} bytes) to folder {parent_folder or 'root'}")
            
            # Track renamed files
            if unique_filename != original_filename:
                renamed_files.append(f"{original_filename} → {unique_filename}")
            
        except Exception as e:
            print(colored(f"    - [ERROR] Failed to upload: {str(e)}", 'red'), file=sys.stderr)
            error_messages.append(f"Failed to upload {file.filename}: {str(e)}")
            failed_uploads += 1
            log_audit_event('upload_error', f"Error uploading {original_filename}: {str(e)}")
            continue

    try:
        db.session.commit()
        print(colored(f"  • [DATABASE] Successfully committed {successful_uploads} file records", 'green'), file=sys.stderr)
    except Exception as e:
        db.session.rollback()
        print(colored(f"  • [DATABASE ERROR] {str(e)}", 'red'), file=sys.stderr)
        return jsonify({
            'success': False,
            'message': f'Database error: {str(e)}'
        })

    # Log summary
    print(colored(f"  • [UPLOAD SUMMARY] Success: {successful_uploads}, Failed: {failed_uploads}", 'magenta'), file=sys.stderr)
    
    message = f"Successfully uploaded {successful_uploads} files."
    if renamed_files:
        message += "\nRenamed files:\n" + "\n".join(renamed_files)
    if failed_uploads > 0:
        message += f"\n{failed_uploads} files failed."
        if error_messages:
            message += "\n" + "\n".join(error_messages)

    return jsonify({
        'success': True,
        'message': message
    })

#-------------------------------------------------
#download

@main.route('/download_file/<int:file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    # Locate the file in the database
    file = File.query.get(file_id)
    if not file:
        print(f"Error: File with ID '{file_id}' not found.")
        flash('File not found.', 'danger')
        return redirect(url_for('main.dashboard'))
        
    # Check if the current user is the owner or has a share
    is_owner = file.user_id == current_user.id
    is_shared_with_user = Share.query.filter_by(
        file_id=file_id, 
        recipient_id=current_user.id, 
        is_active=True
    ).first() is not None
    
    # Also check if it's a public share
    public_share = Share.query.filter_by(
        file_id=file_id,
        is_active=True,
        is_public=True
    ).first() is not None
    
    if not (is_owner or is_shared_with_user or public_share):
        print(f"Error: Unauthorized access to file with ID '{file_id}'.")
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Define the full base path for user storage
    base_storage_path = os.path.join(os.getcwd(), 'instance', 'user_storage')

    # Construct the user folder path - using file owner's ID
    user_folder_path = os.path.join(base_storage_path, str(file.user_id), file.folder_name)
    if not os.path.exists(user_folder_path):
        print(f"Error: Folder path '{user_folder_path}' does not exist.")
        flash('File does not exist.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Debug: Print the folder path and file path
    print(f"Serving from directory: {user_folder_path}, file: {file.filename}")

    # Serve the file from the directory
    return send_from_directory(user_folder_path, file.filename, as_attachment=True)

#------------------------------------------------------------------------------
#delete file

import os
from werkzeug.utils import secure_filename

@main.route('/rename_file/<int:file_id>', methods=['POST'])
@login_required
def rename_file(file_id):
    file = File.query.get_or_404(file_id)
    new_filename = request.form.get('new_filename').strip()
    parent_folder = request.form.get('parent_folder', '')  # Preserve current folder

    # Ensure user owns the file
    if file.user_id != current_user.id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    # Validate the new filename
    if not new_filename:
        flash('Filename cannot be empty.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    # Construct the file paths
    user_folder_path = os.path.join('instance/user_storage', str(current_user.id), file.folder_name or '')
    old_file_path = os.path.join(user_folder_path, file.filename)
    new_file_path = os.path.join(user_folder_path, secure_filename(new_filename))

    # Rename the file in the file system
    try:
        os.rename(old_file_path, new_file_path)
    except OSError as e:
        flash(f"Error renaming file on the server: {e}", 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    # Update the filename in the database
    file.filename = secure_filename(new_filename)
    db.session.commit()

    flash('File renamed successfully!', 'success')
    return redirect(url_for('main.dashboard', parent_folder=parent_folder))

@main.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    current_folder = request.form.get('parent_folder', '')

    # Check ownership
    if file.user_id != current_user.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.dashboard', parent_folder=current_folder))

    try:
        # Setup paths
        user_base_path = os.path.join('instance/user_storage', str(current_user.id))
        user_trash_path = os.path.join(user_base_path, 'Trash')
        
        # Create trash directory if it doesn't exist
        os.makedirs(user_trash_path, exist_ok=True)

        # Determine source file path
        source_path = os.path.join(user_base_path, file.folder_name, file.filename) if file.folder_name else os.path.join(user_base_path, file.filename)
        
        # Generate unique name for trash to avoid conflicts
        base_name, extension = os.path.splitext(file.filename)
        trash_filename = f"{base_name}_{str(uuid.uuid4())[:8]}{extension}"
        trash_path = os.path.join(user_trash_path, trash_filename)

        # Move file to trash if it exists
        if os.path.exists(source_path):
            shutil.move(source_path, trash_path)
            
            # Update database
            file.original_folder = file.folder_name
            file.folder_name = 'Trash'
            file.filename = trash_filename
            file.is_deleted = True
            db.session.commit()
            
            flash("File moved to trash.", "success")
        else:
            flash("File not found in the specified location.", "warning")
            
    except Exception as e:
        print(f"Error moving file to trash: {e}")
        flash("Error moving file to trash.", "danger")
        db.session.rollback()

    return redirect(url_for('main.dashboard', parent_folder=current_folder))

@main.route('/delete_multiple', methods=['POST'])
@login_required
def delete_multiple():
    file_ids = request.form.getlist('selected_files[]')
    current_folder = request.form.get('parent_folder', '')
    
    if not file_ids:
        flash("No files selected.", "warning")
        return redirect(url_for('main.dashboard', parent_folder=current_folder))

    success_count = 0
    error_count = 0

    for file_id in file_ids:
        try:
            file = File.query.get(file_id)
            if not file or file.user_id != current_user.id:
                error_count += 1
                continue

            # Setup paths
            user_base_path = os.path.join('instance/user_storage', str(current_user.id))
            user_trash_path = os.path.join(user_base_path, 'Trash')
            os.makedirs(user_trash_path, exist_ok=True)

            # Determine source file path
            source_path = os.path.join(user_base_path, file.folder_name, file.filename) if file.folder_name else os.path.join(user_base_path, file.filename)
            
            # Generate unique name for trash
            base_name, extension = os.path.splitext(file.filename)
            trash_filename = f"{base_name}_{str(uuid.uuid4())[:8]}{extension}"
            trash_path = os.path.join(user_trash_path, trash_filename)

            if os.path.exists(source_path):
                shutil.move(source_path, trash_path)
                file.original_folder = file.folder_name
                file.folder_name = 'Trash'
                file.filename = trash_filename
                file.is_deleted = True
                success_count += 1
            else:
                error_count += 1

        except Exception as e:
            print(f"Error moving file {file_id} to trash: {e}")
            error_count += 1
            continue

    try:
        db.session.commit()
        if success_count > 0:
            flash(f"Successfully moved {success_count} files to trash.", "success")
        if error_count > 0:
            flash(f"Failed to move {error_count} files to trash.", "warning")
    except Exception as e:
        db.session.rollback()
        flash("Error updating database.", "danger")

    return redirect(url_for('main.dashboard', parent_folder=current_folder))

#------------------------------------------------------------------------------
#Toggle sharing mode

from flask import jsonify

@main.route('/toggle_sharing/<int:file_id>', methods=['POST'])
@login_required
def toggle_sharing(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Check if we're creating a public link or sharing with a specific user
    share_type = request.form.get('share_type', 'public')
    recipient_email = request.form.get('recipient_email', None)
    
    # Check if the file is already shared
    existing_share = Share.query.filter_by(file_id=file_id, owner_id=current_user.id).first()
    
    if existing_share:
        # If already shared, deactivate the share
        existing_share.is_active = False
        db.session.commit()
        file.shared = False
        db.session.commit()
        return jsonify({'shared': False, 'url': ''}), 200
    
    # Generate a unique share key
    share_key = secrets.token_urlsafe(32)
    
    # Create a new share record
    new_share = Share(
        share_type='file',
        file_id=file_id,
        owner_id=current_user.id,
        share_key=share_key,
        is_active=True
    )
    
    if share_type == 'public':
        # Public link sharing
        new_share.is_public = True
        shareable_url = f"{request.host_url}public_share/{share_key}"
    else:
        # User-specific sharing
        if recipient_email:
            # Find the recipient user
            recipient = User.query.filter_by(email=recipient_email).first()
            if recipient:
                new_share.recipient_id = recipient.id
                new_share.recipient_email = recipient_email
                shareable_url = f"Shared with {recipient_email}"
            else:
                return jsonify({'error': 'Recipient not found'}), 404
        else:
            return jsonify({'error': 'Recipient email required for user sharing'}), 400
    
    # Update the file's shared status
    file.shared = True
    
    # Save changes
    db.session.add(new_share)
    db.session.commit()
    
    # Log the sharing action
    log_audit_event('share_file', f"File {file.filename} shared by {current_user.username} ({share_type} sharing)")
    
    return jsonify({'shared': True, 'url': shareable_url}), 200

# Public share download route
@main.route('/public_share/<share_key>', methods=['GET'])
def public_share(share_key):
    # Find the share by key
    share = Share.query.filter_by(share_key=share_key, is_active=True, is_public=True).first()
    
    if not share:
        flash('Shared file not found or link has expired.', 'danger')
        return redirect(url_for('main.home'))
    
    # Get the file
    file = File.query.get(share.file_id)
    if not file or file.is_deleted:
        flash('File not found or has been deleted.', 'danger')
        return redirect(url_for('main.home'))
    
    # Get the owner
    owner = User.query.get(share.owner_id)
    
    # Define the full base path for user storage
    base_storage_path = os.path.join(os.getcwd(), 'instance', 'user_storage')
    
    # Construct the user folder path
    user_folder_path = os.path.join(base_storage_path, str(owner.id), file.folder_name)
    if not os.path.exists(user_folder_path):
        flash('File does not exist.', 'danger')
        return redirect(url_for('main.home'))
    
    # Log the download
    log_audit_event('public_download', f"File {file.filename} downloaded via public link by IP {request.remote_addr}")
    
    # Serve the file from the directory
    return send_from_directory(user_folder_path, file.filename, as_attachment=True)

#-----------------------------------------
#rename

@main.route('/rename_folder', methods=['POST'])
@login_required
def rename_folder():
    old_folder_name = request.form.get('old_folder_name')
    new_folder_name = request.form.get('new_folder_name')
    parent_folder = request.form.get('parent_folder', '')  # Preserve current folder
    
    # Log rename attempt with color
    print(colored(f"\n[FOLDER RENAME] Attempting to rename:", 'magenta'), file=sys.stderr)
    print(colored(f"  • Old Folder Name: {old_folder_name}", 'magenta'), file=sys.stderr)
    print(colored(f"  • New Folder Name: {new_folder_name}", 'magenta'), file=sys.stderr)
    print(colored(f"  • Parent Folder: {parent_folder or 'root'}", 'magenta'), file=sys.stderr)

    if not old_folder_name or not new_folder_name:
        print(colored(f"  • [ERROR] Missing folder name parameters", 'red'), file=sys.stderr)
        flash('Both old and new folder names are required.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))
        
    # Clean and validate the new folder name
    new_folder_name = secure_filename(new_folder_name)
    
    # Build the absolute paths
    user_base_path = os.path.abspath(os.path.join('instance/user_storage', str(current_user.id)))
    
    # Construct paths for parent folder, old folder and new folder
    if parent_folder:
        # Get absolute path of parent folder
        parent_folder_path = os.path.abspath(os.path.join(user_base_path, parent_folder))
        
        # Security check: Ensure parent folder is within user directory
        if not parent_folder_path.startswith(user_base_path):
            print(colored(f"  • [ERROR] Security check failed - Parent path outside user directory", 'red'), file=sys.stderr)
            flash('Invalid folder location.', 'danger')
            return redirect(url_for('main.dashboard'))
            
        if not os.path.exists(parent_folder_path):
            print(colored(f"  • [ERROR] Parent folder doesn't exist: {parent_folder_path}", 'red'), file=sys.stderr)
            flash('Parent folder does not exist.', 'danger')
            return redirect(url_for('main.dashboard'))
            
        # Build paths for the old and new folders
        old_folder_path = os.path.join(parent_folder_path, old_folder_name)
        new_folder_path = os.path.join(parent_folder_path, new_folder_name)
    else:
        # Rename folder at root level
        old_folder_path = os.path.join(user_base_path, old_folder_name)
        new_folder_path = os.path.join(user_base_path, new_folder_name)
    
    print(colored(f"  • Old Folder Path: {old_folder_path}", 'magenta'), file=sys.stderr)
    print(colored(f"  • New Folder Path: {new_folder_path}", 'magenta'), file=sys.stderr)
    
    # Security check: Verify both paths are within user directory
    if not os.path.abspath(old_folder_path).startswith(user_base_path) or not os.path.abspath(new_folder_path).startswith(user_base_path):
        print(colored(f"  • [ERROR] Security check failed - Path is outside user directory", 'red'), file=sys.stderr)
        flash('Invalid folder location.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    try:
        # Check if old folder exists and new folder doesn't
        if not os.path.exists(old_folder_path):
            print(colored(f"  • [ERROR] Original folder not found: {old_folder_path}", 'red'), file=sys.stderr)
            flash('Folder not found.', 'danger')
        elif os.path.exists(new_folder_path):
            print(colored(f"  • [ERROR] Destination folder already exists: {new_folder_path}", 'red'), file=sys.stderr)
            flash(f'A folder named "{new_folder_name}" already exists.', 'danger')
        else:
            # Rename the folder
            os.rename(old_folder_path, new_folder_path)
            print(colored(f"  • [SUCCESS] Folder renamed: {old_folder_path} → {new_folder_path}", 'green'), file=sys.stderr)
            flash('Folder renamed successfully!', 'success')
            
            # Update file paths in the database
            old_rel_path = os.path.relpath(old_folder_path, user_base_path)
            new_rel_path = os.path.relpath(new_folder_path, user_base_path)
            
            # Update files directly in this folder
            files_to_update = File.query.filter_by(
                user_id=current_user.id,
                folder_name=old_rel_path if old_rel_path != '.' else ''
            ).all()
            
            for file in files_to_update:
                file.folder_name = new_rel_path if new_rel_path != '.' else ''
                db.session.add(file)
            
            # Update files in subfolders
            subfolder_files = File.query.filter(
                File.user_id == current_user.id,
                File.folder_name.like(f"{old_rel_path}/%") if old_rel_path != '.' else File.folder_name.like("%")
            ).all()
            
            for file in subfolder_files:
                file.folder_name = file.folder_name.replace(old_rel_path, new_rel_path, 1)
                db.session.add(file)
                
            db.session.commit()
            
    except Exception as e:
        print(colored(f"  • [ERROR] Failed to rename folder: {str(e)}", 'red'), file=sys.stderr)
        flash(f'Error renaming folder: {str(e)}', 'danger')
        db.session.rollback()

    return redirect(url_for('main.dashboard', parent_folder=parent_folder))

#--------------------------------------------------
#Delete folder

@main.route('/trash', methods=['GET'])
@login_required
def trash():
    user_trash_path = os.path.join('instance/user_storage', str(current_user.id), 'Trash')

    # Ensure the trash folder exists
    os.makedirs(user_trash_path, exist_ok=True)

    # Fetch files marked as deleted
    deleted_files = File.query.filter_by(user_id=current_user.id, is_deleted=True).all()
    
    # Filter out files that no longer exist on the hard drive
    existing_files = [
        file for file in deleted_files
        if os.path.exists(os.path.join(user_trash_path, file.filename))
    ]

    # Pass the form to the template
    form = FolderForm()

    return render_template('trash.html', files=existing_files, form=form)

@main.route('/restore_file/<int:file_id>', methods=['POST'])
@login_required
def restore_file(file_id):
    file = File.query.get_or_404(file_id)

    if file.user_id != current_user.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.trash'))

    # Paths for trash and original location
    trash_path = os.path.join('instance/user_storage', str(current_user.id), 'Trash', file.filename)
    original_path = os.path.join('instance/user_storage', str(current_user.id), file.original_folder, file.filename)

    try:
        os.rename(trash_path, original_path)  # Move file back to original folder
        file.folder_name = file.original_folder  # Restore original folder name
        file.original_folder = None             # Clear original folder
        file.is_deleted = False                 # Mark as not deleted
        db.session.commit()
        flash("File restored successfully.", "success")
    except OSError as e:
        flash(f"Error restoring file: {e}", "danger")

    return redirect(url_for('main.trash'))

@main.route('/permanently_delete_file/<int:file_id>', methods=['POST'])
@login_required
def permanently_delete_file(file_id):
    file = File.query.get_or_404(file_id)

    # Check ownership and ensure the file is marked as deleted
    if file.user_id != current_user.id or not file.is_deleted:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.trash'))

    # Delete file from the Trash folder
    trash_path = os.path.join('instance/user_storage', str(current_user.id), 'Trash', file.filename)
    try:
        if os.path.exists(trash_path):
            os.remove(trash_path)
    except FileNotFoundError:
        pass  # File might already be missing

    # Remove file from the database
    db.session.delete(file)
    db.session.commit()

    flash("File permanently deleted.", "success")
    return redirect(url_for('main.trash'))

# Admin routes
@main.route('/admin', methods=['GET'])
@login_required
def admin_panel():
    # Check if user is admin
    if not current_user.is_admin:  # Using is_admin field instead of user ID
        flash('You do not have permission to access the admin panel.', 'danger')
        return redirect(url_for('main.dashboard'))
        
    # Get all users
    users = User.query.all()
    
    # Pass allowed file types to the template
    return render_template('admin.html', users=users, allowed_file_types=ALLOWED_FILE_TYPES)

@main.route('/admin/toggle_whitelist/<int:user_id>', methods=['POST'])
@login_required
def toggle_whitelist(user_id):
    # Check if user is admin
    if not current_user.is_admin:  # Using is_admin field instead of user ID
        flash('You do not have permission to perform this action.', 'danger')
        log_audit_event('access_denied', f"Non-admin user attempted to toggle whitelist for user ID {user_id}")
        return redirect(url_for('main.dashboard'))
    
    # Find the user
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        log_audit_event('error', f"Attempted to toggle whitelist for non-existent user ID {user_id}")
        return redirect(url_for('main.admin_panel'))
    
    # Get current status for logging
    current_status = "whitelisted" if user.is_whitelisted else "not whitelisted"
    
    try:
        # Toggle whitelist status
        user.is_whitelisted = not user.is_whitelisted
        db.session.commit()
        
        # New status for logging
        new_status = "whitelisted" if user.is_whitelisted else "not whitelisted"
        
        # Log action
        log_audit_event('toggle_whitelist', 
                        f"Changed user {user.username} (ID: {user.id}) whitelist status from {current_status} to {new_status}")
        
        status = 'enabled' if user.is_whitelisted else 'disabled'
        flash(f'Whitelist status for {user.username} {status}.', 'success')
    except Exception as e:
        db.session.rollback()
        print(colored(f"ERROR in toggle_whitelist: {str(e)}", "red"), file=sys.stderr)
        log_audit_event('error', f"Failed to toggle whitelist: {str(e)}")
        flash(f'Error updating whitelist status: {str(e)}', 'danger')
    
    return redirect(url_for('main.admin_panel'))

@main.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password(user_id):
    # Check if user is admin
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    # Find the user
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('main.admin_panel'))
    
    # Set temporary password
    temp_password = "Temp123!"
    user.password = generate_password_hash(temp_password)
    db.session.commit()
    
    flash(f'Password for {user.username} has been reset to "{temp_password}".', 'success')
    return redirect(url_for('main.admin_panel'))

@main.route('/admin/logs', methods=['GET'])
@login_required
def admin_logs():
    # Check if user is admin
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        log_audit_event('access_denied', f"Non-admin user attempted to access audit logs")
        return redirect(url_for('main.dashboard'))
    
    # Get page number for pagination
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Number of logs per page
    
    # Get filter parameters
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user_id', '', type=str)
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Build query
    query = AuditLog.query.order_by(AuditLog.timestamp.desc())
    
    # Apply filters if provided
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)
    
    if user_filter:
        query = query.filter(AuditLog.user_id == user_filter)
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(AuditLog.timestamp >= date_from_obj)
        except ValueError:
            flash('Invalid date format for From Date', 'warning')
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            # Add one day to include the entire end date
            date_to_obj = date_to_obj.replace(hour=23, minute=59, second=59)
            query = query.filter(AuditLog.timestamp <= date_to_obj)
        except ValueError:
            flash('Invalid date format for To Date', 'warning')
    
    # Get unique actions for filter dropdown
    all_actions = db.session.query(AuditLog.action).distinct().all()
    actions = [action[0] for action in all_actions]
    
    # Get all users for filter dropdown
    all_users = User.query.all()
    
    # Execute the paginated query
    logs = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Log that the logs were viewed
    log_audit_event('view_logs', f"Admin viewed audit logs page {page}")
    
    return render_template('admin_logs.html', 
                          logs=logs, 
                          actions=actions,
                          users=all_users,
                          current_action=action_filter,
                          current_user_filter=user_filter,
                          date_from=date_from,
                          date_to=date_to)

@main.route('/toggle_folder_sharing', methods=['POST'])
@login_required
def toggle_folder_sharing():
    """Toggle sharing status for a folder"""
    folder_path = request.form.get('folder_path')
    parent_folder = request.form.get('parent_folder', '')
    
    # Build the folder full path
    if parent_folder:
        full_folder_path = os.path.join(parent_folder, folder_path)
    else:
        full_folder_path = folder_path
    
    # Security check: Ensure path is within user's directory
    user_base_path = os.path.abspath(os.path.join('instance/user_storage', str(current_user.id)))
    target_folder_path = os.path.join(user_base_path, full_folder_path)
    
    if not os.path.exists(target_folder_path) or not os.path.abspath(target_folder_path).startswith(user_base_path):
        return jsonify({'error': 'Invalid folder location'}), 403
    
    # Check if the folder is already shared
    existing_share = Share.query.filter_by(
        share_type='folder',
        folder_path=full_folder_path, 
        owner_id=current_user.id,
        is_active=True
    ).first()
    
    # Check if we're creating a public link or sharing with a specific user
    share_type = request.form.get('share_type', 'public')
    recipient_email = request.form.get('recipient_email', None)
    
    if existing_share:
        # If already shared, deactivate the share
        existing_share.is_active = False
        db.session.commit()
        return jsonify({'shared': False, 'url': ''}), 200
    
    # Generate a unique share key
    share_key = secrets.token_urlsafe(32)
    
    # Create a new share record
    new_share = Share(
        share_type='folder',
        folder_path=full_folder_path,
        owner_id=current_user.id,
        share_key=share_key,
        is_active=True
    )
    
    if share_type == 'public':
        # Public link sharing
        new_share.is_public = True
        shareable_url = f"{request.host_url}public_folder_share/{share_key}"
    else:
        # User-specific sharing
        if recipient_email:
            # Find the recipient user
            recipient = User.query.filter_by(email=recipient_email).first()
            if recipient:
                new_share.recipient_id = recipient.id
                new_share.recipient_email = recipient_email
                shareable_url = f"Shared with {recipient_email}"
            else:
                return jsonify({'error': 'Recipient not found'}), 404
        else:
            return jsonify({'error': 'Recipient email required for user sharing'}), 400
    
    # Save changes
    db.session.add(new_share)
    db.session.commit()
    
    # Log the sharing action
    log_audit_event('share_folder', f"Folder {full_folder_path} shared by {current_user.username} ({share_type} sharing)")
    
    return jsonify({'shared': True, 'url': shareable_url}), 200

# Public folder share route
@main.route('/public_folder_share/<share_key>', methods=['GET'])
def public_folder_share(share_key):
    # Find the share by key
    share = Share.query.filter_by(
        share_key=share_key, 
        is_active=True, 
        is_public=True, 
        share_type='folder'
    ).first()
    
    if not share:
        flash('Shared folder not found or link has expired.', 'danger')
        return redirect(url_for('main.home'))
    
    # Get the owner
    owner = User.query.get(share.owner_id)
    
    # Define the full base path for user storage
    base_storage_path = os.path.join(os.getcwd(), 'instance', 'user_storage')
    
    # Construct the folder path
    user_folder_path = os.path.join(base_storage_path, str(owner.id), share.folder_path)
    if not os.path.exists(user_folder_path) or not os.path.isdir(user_folder_path):
        flash('Folder does not exist or has been deleted.', 'danger')
        return redirect(url_for('main.home'))
    
    # Get all files in the folder
    files = []
    for item in os.listdir(user_folder_path):
        item_path = os.path.join(user_folder_path, item)
        if os.path.isfile(item_path):
            # Get file information
            file_size = os.path.getsize(item_path)
            file_type = mimetypes.guess_type(item)[0] or 'application/octet-stream'
            files.append({
                'name': item,
                'size': file_size,
                'type': file_type,
                'path': os.path.join(share.folder_path, item),
                'download_url': url_for('main.public_file_download', share_key=share_key, filename=item)
            })
    
    # Log the access
    log_audit_event('public_folder_access', f"Folder {share.folder_path} accessed via public link by IP {request.remote_addr}")
    
    return render_template('public_folder.html', 
                          folder_name=os.path.basename(share.folder_path),
                          files=files, 
                          owner=owner.username,
                          share=share)

@main.route('/public_file_download/<share_key>/<path:filename>', methods=['GET'])
def public_file_download(share_key, filename):
    # Find the share by key
    share = Share.query.filter_by(
        share_key=share_key, 
        is_active=True, 
        is_public=True, 
        share_type='folder'
    ).first()
    
    if not share:
        flash('Shared folder not found or link has expired.', 'danger')
        return redirect(url_for('main.home'))
    
    # Get the owner
    owner = User.query.get(share.owner_id)
    
    # Define the full base path for user storage
    base_storage_path = os.path.join(os.getcwd(), 'instance', 'user_storage')
    
    # Construct the folder path
    user_folder_path = os.path.join(base_storage_path, str(owner.id), share.folder_path)
    if not os.path.exists(user_folder_path) or not os.path.isdir(user_folder_path):
        flash('Folder does not exist or has been deleted.', 'danger')
        return redirect(url_for('main.home'))
    
    # Security check to prevent path traversal
    file_path = os.path.join(user_folder_path, filename)
    if not os.path.exists(file_path) or not os.path.isfile(file_path) or not os.path.abspath(file_path).startswith(user_folder_path):
        flash('File not found or access denied.', 'danger')
        return redirect(url_for('main.home'))
    
    # Log the download
    log_audit_event('public_file_download', f"File {filename} from folder {share.folder_path} downloaded via public link by IP {request.remote_addr}")
    
    # Serve the file
    return send_from_directory(user_folder_path, filename, as_attachment=True)

@main.route('/account')
@login_required
def account():
    # Get user statistics
    total_files = File.query.filter_by(user_id=current_user.id, is_deleted=False).count()
    total_shares = Share.query.filter_by(owner_id=current_user.id, is_active=True).count()
    
    # Calculate storage used
    files = File.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    total_size = sum(file.file_size for file in files)
    
    # Convert to appropriate unit
    if total_size < 1024:
        storage_used = f"{total_size} B"
    elif total_size < 1024 * 1024:
        storage_used = f"{total_size/1024:.1f} KB"
    elif total_size < 1024 * 1024 * 1024:
        storage_used = f"{total_size/(1024*1024):.1f} MB"
    else:
        storage_used = f"{total_size/(1024*1024*1024):.1f} GB"
    
    form = PasswordChangeForm()
    return render_template('account.html', 
                         form=form,
                         total_files=total_files,
                         total_shares=total_shares,
                         storage_used=storage_used)

@main.route('/change_password', methods=['POST'])
@login_required
def change_password():
    form = PasswordChangeForm()
    if form.validate_on_submit():
        if not check_password_hash(current_user.password, form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('main.account'))
        
        # Update password
        current_user.password = generate_password_hash(form.new_password.data)
        db.session.commit()
        
        # Log the password change
        log_audit_event('password_change', f'User {current_user.username} changed their password')
        
        flash('Password successfully updated!', 'success')
        return redirect(url_for('main.account'))
    
    # If form validation failed, flash the errors
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'{error}', 'danger')
    
    return redirect(url_for('main.account'))

