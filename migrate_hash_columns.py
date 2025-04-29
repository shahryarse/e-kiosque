from app import app, db
from models import Ticket

def migrate_hash_columns():
    """Migrate the hash columns to support longer Argon2 hashes"""
    with app.app_context():
        # Get all tickets
        tickets = Ticket.query.all()
        
        # Update each ticket's hash values
        for ticket in tickets:
            # Rehash the values with the new method
            from app import hash_identifier
            ticket.hashed_ip = hash_identifier(ticket.hashed_ip)
            ticket.hashed_session = hash_identifier(ticket.hashed_session)
            ticket.hashed_cookie = hash_identifier(ticket.hashed_cookie)
        
        # Commit the changes
        db.session.commit()
        print("Migration completed successfully!")

if __name__ == '__main__':
    migrate_hash_columns() 