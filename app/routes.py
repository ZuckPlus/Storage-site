from flask import render_template, redirect, url_for, flash, request, send_from_directory, current_app
from flask import Blueprint
from flask_login import login_required, logout_user, login_user, current_user
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models import User, File
from app.forms import RegistrationForm, LoginForm, FolderForm
from app.config import ALLOWED_FILE_TYPES
import mimetypes
import uuid
from concurrent.futures import ThreadPoolExecutor
import shutil

# Initialize the blueprint
main = Blueprint('main', __name__)
executor = ThreadPoolExecutor(max_workers=4)  # Adjust the number of workers based on server resources

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
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

# Logout
@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('main.home'))


@main.route('/search_results', methods=['GET'])
@login_required
def search_results():
    search_query = request.args.get('search', '')
    file_filter = request.args.get('filter', '')

    user_base_path = os.path.join('instance/user_storage', str(current_user.id))
    files = search_files(current_app, current_user.id, search_query, file_filter, user_base_path)

    return render_template(
        'search_results.html',
        files=files,
        search=search_query,
        file_filter=file_filter
    )


# Search logic for asynchronous execution
def search_files(app, user_id, search_query, filter_type, base_path):
    with app.app_context():
        files_query = File.query.filter_by(user_id=user_id)

        if search_query:
            files_query = files_query.filter(File.filename.ilike(f"%{search_query}%"))
        if filter_type:
            if filter_type == 'image':
                files_query = files_query.filter(File.file_type.like('image/%'))
            elif filter_type == 'pdf':
                files_query = files_query.filter(File.file_type == 'application/pdf')
            elif filter_type == 'video':
                files_query = files_query.filter(File.file_type.like('video/%'))
            elif filter_type == 'audio':
                files_query = files_query.filter(File.file_type.like('audio/%'))

        # Get all files from the database
        all_files = files_query.all()

        # Verify files exist on the disk
        verified_files = []
        for file in all_files:
            folder_path = os.path.join(base_path, file.folder_name or '')
            file_path = os.path.join(folder_path, file.filename)
            if os.path.exists(file_path):
                verified_files.append(file)

        return verified_files



@main.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    parent_folder = request.args.get('parent_folder', '')  # Root if none specified
    search_query = request.args.get('search', '')
    file_filter = request.args.get('filter', '')

    if search_query:
        return redirect(url_for('main.search_results', search=search_query, filter=file_filter))

    user_base_path = os.path.join('instance/user_storage', str(current_user.id))
    current_folder_path = os.path.join(user_base_path, parent_folder)

    # Ensure the current folder exists
    os.makedirs(current_folder_path, exist_ok=True)

    # List folders and files in the current directory
    folders = [f for f in os.listdir(current_folder_path) if os.path.isdir(os.path.join(current_folder_path, f))]
    files_query = File.query.filter_by(user_id=current_user.id, folder_name=parent_folder)
    files = files_query.all()

    # Initialize the folder creation form
    form = FolderForm()
    return render_template(
        'dashboard.html',
        folders=folders,
        files=files,
        parent_folder=parent_folder,
        form=form,
        search=search_query,
        file_filter=file_filter
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

    user_base_path = os.path.join('instance/user_storage', str(current_user.id))
    new_folder_path = os.path.join(user_base_path, parent_folder, folder_name)

    if not os.path.exists(new_folder_path):
        os.makedirs(new_folder_path)
        flash(f'Folder "{folder_name}" created successfully!', 'success')
    else:
        flash(f'Folder "{folder_name}" already exists.', 'danger')

    return redirect(url_for('main.dashboard', parent_folder=parent_folder))

# Folder deletion
@main.route('/delete_folder', methods=['POST'])
@login_required
def delete_folder():
    folder_name = request.form.get('folder_name')
    parent_folder = request.args.get('parent_folder', '')  # Get the current parent folder
    print(f"Folder to delete: {folder_name}, Parent folder: {parent_folder}")

    if not folder_name:
        flash('Folder name is required.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    # Construct the full folder path
    user_base_path = os.path.join('instance/user_storage', str(current_user.id))
    folder_path = os.path.join(user_base_path, parent_folder, folder_name)

    print(f"Attempting to delete folder at path: {folder_path}")

    try:
        if os.path.exists(folder_path):
            # Delete all files and subdirectories within the folder
            for root, dirs, files in os.walk(folder_path, topdown=False):
                # Remove all files
                for file in files:
                    file_path = os.path.join(root, file)
                    print(f"Deleting file: {file_path}")
                    os.remove(file_path)
                # Remove all subdirectories
                for directory in dirs:
                    dir_path = os.path.join(root, directory)
                    print(f"Deleting directory: {dir_path}")
                    os.rmdir(dir_path)

            # Finally, delete the parent folder itself
            print(f"Deleting parent folder: {folder_path}")
            os.rmdir(folder_path)

            flash(f'Folder "{folder_name}" and all its contents deleted successfully!', 'success')
        else:
            flash(f'Folder "{folder_name}" does not exist.', 'danger')
    except Exception as e:
        print(f"Error deleting folder: {e}")
        flash('Error deleting folder. Please try again.', 'danger')

    return redirect(url_for('main.dashboard', parent_folder=parent_folder))

# File upload
@main.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part in the request.', 'danger')
        return redirect(url_for('main.dashboard'))
    
    file = request.files['file']
    parent_folder = request.form.get('parent_folder', '')

    if file.filename == '':
        flash('No selected file.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    if not current_user.is_whitelisted and file_extension not in ALLOWED_FILE_TYPES:
        flash(f'File type ".{file_extension}" is not allowed.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    user_base_path = os.path.join('instance/user_storage', str(current_user.id))
    full_folder_path = os.path.join(user_base_path, parent_folder)

    if not os.path.exists(full_folder_path):
        flash('Folder does not exist.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(full_folder_path, filename)
    file.save(file_path)

    file_size = os.path.getsize(file_path)
    file_type = mimetypes.guess_type(file.filename)[0] or 'Unknown'

    unique_id = str(uuid.uuid4())

    new_file = File(
        filename=filename,
        user_id=current_user.id,
        folder_name=parent_folder,
        file_size=file_size,
        file_type=file_type,
        unique_id=unique_id
    )
    db.session.add(new_file)
    db.session.commit()

    flash('File uploaded successfully!', 'success')
    return redirect(url_for('main.dashboard', parent_folder=parent_folder))

#-------------------------------------------------
#download


@main.route('/download_file/<int:file_id>', methods=['GET'])
@login_required
def download_file(file_id):
    # Locate the file in the database
    file = File.query.get(file_id)
    if not file or file.user_id != current_user.id:
        print(f"Error: Unauthorized access or file with ID '{file_id}' not found.")
        flash('File not found or unauthorized access.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Define the full base path for user storage
    base_storage_path = os.path.join(os.getcwd(), 'instance', 'user_storage')

    # Construct the user folder path
    user_folder_path = os.path.join(base_storage_path, str(current_user.id), file.folder_name)
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

    # Check ownership
    if file.user_id != current_user.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.dashboard'))

    # Move file to user's trash folder
    user_trash_path = os.path.join('instance/user_storage', str(current_user.id), 'Trash')
    os.makedirs(user_trash_path, exist_ok=True)

    original_path = os.path.join('instance/user_storage', str(current_user.id), file.folder_name, file.filename)
    trash_path = os.path.join(user_trash_path, file.filename)

    try:
        os.rename(original_path, trash_path)  # Move file to trash
        file.folder_name = 'Trash'  # Update database to reflect trash folder
        file.deleted = True         # Mark as deleted
        db.session.commit()
        flash("File moved to trash.", "success")
    except OSError as e:
        flash(f"Error deleting file: {e}", "danger")

    return redirect(url_for('main.dashboard'))


#------------------------------------------------------------------------------
#Toggle sharing mode



from flask import jsonify

@main.route('/toggle_sharing/<int:file_id>', methods=['POST'])
@login_required
def toggle_sharing(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Toggle sharing status
    file.shared = not file.shared
    db.session.commit()

    # Generate shareable URL
    if file.shared:
        shareable_url = f"{request.host_url}download_file/{file.id}"
        return jsonify({'shared': True, 'url': shareable_url}), 200
    else:
        return jsonify({'shared': False, 'url': ''}), 200


#------------------------------------------------------------------------------
#downloading file from unique id set to it 


@main.route('/download_file/<unique_id>=<filename>', methods=['GET'])
def public_download(unique_id, filename):
    # Locate the file in the database
    file = File.query.filter_by(unique_id=unique_id, filename=filename, shared=True).first()

    if not file:
        print(f"Error: File with unique_id '{unique_id}' and filename '{filename}' not found or not shared.")
        flash('File not found or sharing disabled.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Define the full base path for user storage
    base_storage_path = os.path.join(os.getcwd(), 'instance', 'user_storage')

    # Construct the user folder path
    user_folder_path = os.path.join(base_storage_path, str(file.user_id), file.folder_name)
    if not os.path.exists(user_folder_path):
        print(f"Error: Folder path '{user_folder_path}' does not exist.")
        flash('File does not exist.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Debug: Print the folder path and file path
    print(f"Serving from directory: {user_folder_path}, file: {file.filename}")

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

    if not old_folder_name or not new_folder_name:
        flash('Both old and new folder names are required.', 'danger')
        return redirect(url_for('main.dashboard', parent_folder=parent_folder))

    base_storage_path = os.path.join('instance/user_storage', str(current_user.id))
    old_folder_path = os.path.join(base_storage_path, parent_folder, old_folder_name)
    new_folder_path = os.path.join(base_storage_path, parent_folder, secure_filename(new_folder_name))

    try:
        if os.path.exists(old_folder_path):
            os.rename(old_folder_path, new_folder_path)
            flash('Folder renamed successfully!', 'success')
        else:
            flash('Folder not found.', 'danger')
    except OSError as e:
        print(f"Error renaming folder: {e}")
        flash('Error renaming folder.', 'danger')

    return redirect(url_for('main.dashboard', parent_folder=parent_folder))

#--------------------------------------------------
#Delete folder


#-----------------------------------------------------


@main.route('/trash', methods=['GET'])
@login_required
def trash():
    user_trash_path = os.path.join('instance/user_storage', str(current_user.id), 'Trash')

    # Ensure the trash folder exists
    os.makedirs(user_trash_path, exist_ok=True)

    # Fetch deleted files for the user
    deleted_files = File.query.filter_by(user_id=current_user.id, deleted=True).all()

    # Filter out files that no longer exist on the hard drive
    existing_files = [
        file for file in deleted_files
        if os.path.exists(os.path.join(user_trash_path, file.filename))
    ]

    return render_template('trash.html', files=existing_files)


#-----------------------------------------------------


@main.route('/restore_file/<int:file_id>', methods=['POST'])
@login_required
def restore_file(file_id):
    file = File.query.get_or_404(file_id)

    # Check ownership and ensure the file is deleted
    if file.user_id != current_user.id or not file.deleted:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.trash'))

    # Move file back to the original folder
    trash_path = os.path.join('instance/user_storage', str(current_user.id), 'Trash', file.filename)
    original_path = os.path.join('instance/user_storage', str(current_user.id), file.folder_name, file.filename)

    try:
        os.rename(trash_path, original_path)
    except OSError as e:
        flash(f"Error restoring file: {e}", "danger")
        return redirect(url_for('main.trash'))

    # Update database
    file.deleted = False
    db.session.commit()

    flash("File restored successfully.", "success")
    return redirect(url_for('main.trash'))

#-----------------------------------------------------

@main.route('/permanently_delete_file/<int:file_id>', methods=['POST'])
@login_required
def permanently_delete_file(file_id):
    file = File.query.get_or_404(file_id)

    # Check ownership and ensure the file is deleted
    if file.user_id != current_user.id or not file.deleted:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('main.trash'))

    # Delete file from the Trash folder
    trash_path = os.path.join('instance/user_storage', str(current_user.id), 'Trash', file.filename)
    try:
        os.remove(trash_path)
    except FileNotFoundError:
        pass  # File might already be missing

    # Remove file from the database
    db.session.delete(file)
    db.session.commit()

    flash("File permanently deleted.", "success")
    return redirect(url_for('main.trash'))

