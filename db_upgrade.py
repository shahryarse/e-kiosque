from app import app
from extensions import db
from models import SiteNotice

def upgrade_db():
    with app.app_context():
        # Create the SiteNotice table
        db.create_all()
        print("Database upgraded successfully!")

if __name__ == '__main__':
    upgrade_db() 