from app import app, db
from models import User, Event, Ticket, AccessRestriction, SiteNotice, WikiUser
import tomllib
from datetime import datetime, timedelta
import random
import string

# Load configuration
with open('config.toml', 'rb') as f:
    config = tomllib.load(f)
    SUPERADMIN_USERNAME = config['SUPERADMIN_USERNAME']

def init_db():
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create super admin user if it doesn't exist
        super_admin = User.query.filter_by(username=SUPERADMIN_USERNAME).first()
        if not super_admin:
            super_admin = User(
                username=SUPERADMIN_USERNAME,
                is_admin=True,
                is_super_admin=True,
                is_active=True
            )
            db.session.add(super_admin)
            db.session.commit()
            print(f"Super admin user created with username: {SUPERADMIN_USERNAME}")
        
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db() 