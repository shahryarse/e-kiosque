from app import app, db
from models import User
import tomllib

# Load configuration
with open('config.toml', 'rb') as f:
    config = tomllib.load(f)
    SUPERADMIN_USERNAME = config['SUPERADMIN_USERNAME']

def init_super_admin():
    with app.app_context():
        # Check if super admin already exists
        super_admin = User.query.filter_by(username=SUPERADMIN_USERNAME).first()
        
        if not super_admin:
            # Create super admin user
            super_admin = User(
                username=SUPERADMIN_USERNAME,
                is_admin=True,
                is_super_admin=True,
                is_active=True
            )
            db.session.add(super_admin)
            db.session.commit()
            print(f"Super admin user created with username: {SUPERADMIN_USERNAME}")
        else:
            print(f"Super admin user already exists with username: {SUPERADMIN_USERNAME}")

if __name__ == '__main__':
    init_super_admin() 