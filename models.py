from extensions import db
from datetime import datetime
import hashlib
import random
import string
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)  # Required by Flask-Login
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def get_id(self):
        return str(self.id)

class Event(db.Model):
    __tablename__ = 'event'  # Changed from 'seminar' to 'event'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    time = db.Column(db.String(50), nullable=False)
    timezone = db.Column(db.String(50), nullable=False, default='UTC')
    location = db.Column(db.String(200), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    available_tickets = db.Column(db.Integer, nullable=False)
    registration_start = db.Column(db.DateTime, nullable=False)
    registration_end = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_private = db.Column(db.Boolean, default=False)
    private_link = db.Column(db.String(64), unique=True, nullable=True)  # Increased length to 64 characters
    image_url = db.Column(db.String(500), nullable=True)  # New column for image URL
    
    # Attendee information collection settings
    collect_name = db.Column(db.Boolean, default=False)
    name_optional = db.Column(db.Boolean, default=False)
    collect_email = db.Column(db.Boolean, default=False)
    email_optional = db.Column(db.Boolean, default=False)
    collect_username = db.Column(db.Boolean, default=False)
    username_optional = db.Column(db.Boolean, default=False)
    collect_phone = db.Column(db.Boolean, default=False)
    phone_optional = db.Column(db.Boolean, default=False)
    
    tickets = db.relationship('Ticket', backref='event', lazy=True)
    wiki_creator_id = db.Column(db.Integer, db.ForeignKey('wiki_user.id'), nullable=True)
    creator = db.Column(db.String(50), nullable=False)  # Username of the event creator

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    ticket_code = db.Column(db.String(50), unique=True, nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    name = db.Column(db.String(100), nullable=True)  # Optional name field
    email = db.Column(db.String(120), nullable=True)  # Optional email field
    username = db.Column(db.String(100), nullable=True)  # Optional username field
    phone = db.Column(db.String(20), nullable=True)  # Optional phone number field
    hashed_ip = db.Column(db.String(200), nullable=False)  # Increased length for Argon2 hash
    hashed_session = db.Column(db.String(200), nullable=False)  # Increased length for Argon2 hash
    hashed_cookie = db.Column(db.String(200), nullable=False)  # Increased length for Argon2 hash
    is_used = db.Column(db.Boolean, default=False)
    expiry_time = db.Column(db.DateTime, nullable=False)  # Expires when event ends

class AccessRestriction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hashed_ip = db.Column(db.String(64), nullable=False)
    session_id = db.Column(db.String(64), nullable=False)
    hashed_cookie = db.Column(db.String(64), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    reservation_time = db.Column(db.DateTime, default=datetime.utcnow)
    expiry_time = db.Column(db.DateTime, nullable=False)
    
    # Define relationship to event
    event = db.relationship('Event', foreign_keys=[event_id])

class SiteNotice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    background_color = db.Column(db.String(20), nullable=False, default='#FFF3CD')  # Default is a light yellow
    text_color = db.Column(db.String(20), nullable=False, default='#212529')  # Default is dark
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Define relationship to get user who created the notice
    creator = db.relationship('User', backref='site_notices', foreign_keys=[created_by])

class WikiUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, default=datetime.utcnow)
    access_token = db.Column(db.String(255), nullable=True)
    access_secret = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    
    # Relationship to events created by this user
    events = db.relationship('Event', backref='wiki_creator', lazy=True, foreign_keys='Event.wiki_creator_id') 