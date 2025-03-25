"""
Script to set initial admin user after database migration
Run this after the database migration to set user with ID 1 as admin
"""

import sys
import os

# Add the parent directory to sys.path to allow importing the app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models import User

app = create_app()

def set_admin():
    """Set user with ID 1 as admin"""
    with app.app_context():
        # Get user with ID 1
        admin_user = User.query.get(1)
        
        if not admin_user:
            print("Error: User with ID 1 not found")
            return False
        
        # Set as admin
        admin_user.is_admin = True
        db.session.commit()
        
        print(f"User '{admin_user.username}' (ID: 1) has been set as admin")
        return True

if __name__ == "__main__":
    set_admin() 