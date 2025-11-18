"""
Main application file for e-kiosque
Refactored to use Flask Blueprints for better code organization
"""

from flask import Flask, render_template, session, send_file
from datetime import datetime, timedelta
import os
import random
import string
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
import hashlib
import tomllib
from models import User, Event, Ticket, SiteNotice, WikiUser
from extensions import db, login_manager, csrf, babel, limiter
from flask_babel import gettext as _
from argon2 import PasswordHasher
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, BooleanField
from wtforms.validators import DataRequired, Optional, Email

# Create Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tickets.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_SUPPORTED_LOCALES'] = ['en', 'fa']
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

# Load OAuth configuration
if not os.path.exists('config.toml'):
    raise FileNotFoundError(
        "config.toml not found! Please create this file with required settings:\n"
        "- SECRET_KEY\n"
        "- CONSUMER_KEY and CONSUMER_SECRET (OAuth credentials)\n"
        "- SUPERADMIN_USERNAME\n"
        "- SALT and PEPPER (for security hashing)\n"
        "See config.toml.example for reference."
    )

with open('config.toml', 'rb') as f:
    config = tomllib.load(f)
    app.config.update(config)
    
    # Validate required configuration
    required_keys = ['SUPERADMIN_USERNAME', 'SALT', 'PEPPER', 'SECRET_KEY', 'CONSUMER_KEY', 'CONSUMER_SECRET']
    missing_keys = [key for key in required_keys if not config.get(key) or config.get(key).startswith('CHANGE_THIS') or config.get(key) == '']
    
    if missing_keys:
        raise ValueError(
            f"Missing or invalid configuration in config.toml: {', '.join(missing_keys)}\n"
            "Please update config.toml with valid values for all required fields."
        )
    
    # Set global variables from config
    SUPERADMIN_USERNAME = app.config['SUPERADMIN_USERNAME']
    SALT = app.config['SALT']
    PEPPER = app.config['PEPPER']

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'auth.wiki_login'
csrf.init_app(app)
limiter.init_app(app)


# Locale selector for Babel
def get_locale():
    """Get the current locale from session"""
    if 'language' in session:
        return session['language']
    return 'en'


# Make get_locale available to templates
app.jinja_env.globals['get_locale'] = get_locale

# Initialize Babel
babel.init_app(app, locale_selector=get_locale)


# Context processors
@app.context_processor
def inject_now():
    """Inject current datetime into templates"""
    return {'now': datetime.now()}


@app.context_processor
def inject_site_notice():
    """Inject active site notice into templates"""
    active_notice = SiteNotice.query.filter_by(is_active=True).order_by(SiteNotice.updated_at.desc()).first()
    return {'site_notice': active_notice}


@app.context_processor
def inject_wiki_user():
    """Make wiki_username and current_user available to all templates"""
    context = {}
    if 'wiki_username' in session:
        context['wiki_username'] = session['wiki_username']
        context['current_user'] = User.query.filter_by(username=session['wiki_username']).first()
    else:
        context['wiki_username'] = None
        context['current_user'] = None
    return context


# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    """Load user by ID for Flask-Login"""
    # Try to load a regular user first
    user = db.session.get(User, int(user_id))
    if user:
        return user
    
    # If not found, try to load a wiki user
    wiki_user = db.session.get(WikiUser, int(user_id))
    if wiki_user:
        # Create a temporary User object for the wiki user
        user = User()
        user.id = wiki_user.id
        user.username = wiki_user.username
        user.is_admin = wiki_user.is_admin
        user.is_super_admin = wiki_user.is_super_admin
        user.is_active = True  # Required by Flask-Login
        return user
    
    return None


# Helper functions (used by blueprints)
def generate_ticket_code():
    """Generate a random ticket code"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))


def hash_identifier(identifier):
    """Hash an identifier (IP, session ID, etc.) for privacy using SHA-256 and Argon2"""
    if not identifier:
        return None
    
    # First step: Hash with SHA-256 and salt
    sha256_hash = hashlib.sha256((SALT + identifier).encode()).hexdigest()
    
    # Second step: Hash with Argon2 and pepper
    ph = PasswordHasher()
    final_hash = ph.hash(sha256_hash + PEPPER)
    
    return final_hash


def verify_identifier(identifier, stored_hash):
    """Verify an identifier against a stored hash"""
    if not identifier or not stored_hash:
        return False
    
    try:
        # First step: Hash with SHA-256 and salt
        sha256_hash = hashlib.sha256((SALT + identifier).encode()).hexdigest()
        
        # Second step: Verify with Argon2 and pepper
        ph = PasswordHasher()
        return ph.verify(stored_hash, sha256_hash + PEPPER)
    except Exception:
        return False


# CAPTCHA configuration
CAPTCHA_LENGTH = 6
CAPTCHA_WIDTH = 200
CAPTCHA_HEIGHT = 80


def generate_captcha():
    """Generate CAPTCHA image"""
    # Generate random text
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=CAPTCHA_LENGTH))
    
    # Create image
    image = Image.new('RGB', (CAPTCHA_WIDTH, CAPTCHA_HEIGHT), color='white')
    draw = ImageDraw.Draw(image)
    
    # Add noise
    for _ in range(100):
        x = random.randint(0, CAPTCHA_WIDTH)
        y = random.randint(0, CAPTCHA_HEIGHT)
        draw.point((x, y), fill='gray')
    
    # Add text
    try:
        font_path = os.path.join(os.path.dirname(__file__), 'static', 'fonts', 'DejaVuSans.ttf')
        font = ImageFont.truetype(font_path, 36)
    except Exception as e:
        print(f"Error loading font: {e}")
        font = ImageFont.load_default()
    
    # Draw text with random position and rotation
    for i, char in enumerate(captcha_text):
        x = 20 + i * 30 + random.randint(-5, 5)
        y = 20 + random.randint(-5, 5)
        angle = random.randint(-10, 10)
        draw.text((x, y), char, font=font, fill='black', angle=angle)
    
    # Save to bytes
    img_byte_arr = BytesIO()
    image.save(img_byte_arr, format='PNG')
    img_byte_arr.seek(0)
    
    # Store captcha text in session
    session['captcha'] = captcha_text
    
    return img_byte_arr


# Forms (used by templates)
class TicketForm(FlaskForm):
    """Form for ticket reservation"""
    name = StringField('Name', validators=[Optional()])
    email = StringField('Email', validators=[Optional(), Email()])
    captcha = StringField('CAPTCHA', validators=[DataRequired()])


class EventDisplayForm(FlaskForm):
    """Form for event display with timezone selector"""
    timezone = SelectField('Timezone', choices=[
        ('+00:00', '(GMT) Western Europe Time, London, Lisbon, Casablanca'),
        ('+01:00', '(GMT +1:00) Brussels, Copenhagen, Madrid, Paris'),
        ('+02:00', '(GMT +2:00) Kaliningrad, South Africa'),
        ('+03:00', '(GMT +3:00) Baghdad, Riyadh, Moscow, St. Petersburg'),
        ('+03:30', '(GMT +3:30) Tehran'),
        ('+04:00', '(GMT +4:00) Abu Dhabi, Muscat, Baku, Tbilisi'),
        ('+04:30', '(GMT +4:30) Kabul'),
        ('+05:00', '(GMT +5:00) Ekaterinburg, Islamabad, Karachi, Tashkent'),
        ('+05:30', '(GMT +5:30) Bombay, Calcutta, Madras, New Delhi'),
        ('+05:45', '(GMT +5:45) Kathmandu, Pokhara'),
        ('+06:00', '(GMT +6:00) Almaty, Dhaka, Colombo'),
        ('+06:30', '(GMT +6:30) Yangon, Mandalay'),
        ('+07:00', '(GMT +7:00) Bangkok, Hanoi, Jakarta'),
        ('+08:00', '(GMT +8:00) Beijing, Perth, Singapore, Hong Kong'),
        ('+08:45', '(GMT +8:45) Eucla'),
        ('+09:00', '(GMT +9:00) Tokyo, Seoul, Osaka, Sapporo, Yakutsk'),
        ('+09:30', '(GMT +9:30) Adelaide, Darwin'),
        ('+10:00', '(GMT +10:00) Eastern Australia, Guam, Vladivostok'),
        ('+10:30', '(GMT +10:30) Lord Howe Island'),
        ('+11:00', '(GMT +11:00) Magadan, Solomon Islands, New Caledonia'),
        ('+11:30', '(GMT +11:30) Norfolk Island'),
        ('+12:00', '(GMT +12:00) Auckland, Wellington, Fiji, Kamchatka'),
        ('+12:45', '(GMT +12:45) Chatham Islands'),
        ('+13:00', '(GMT +13:00) Apia, Nukualofa'),
        ('+14:00', '(GMT +14:00) Line Islands, Tokelau'),
        ('-12:00', '(GMT -12:00) Eniwetok, Kwajalein'),
        ('-11:00', '(GMT -11:00) Midway Island, Samoa'),
        ('-10:00', '(GMT -10:00) Hawaii'),
        ('-09:30', '(GMT -9:30) Taiohae'),
        ('-09:00', '(GMT -9:00) Alaska'),
        ('-08:00', '(GMT -8:00) Pacific Time (US & Canada)'),
        ('-07:00', '(GMT -7:00) Mountain Time (US & Canada)'),
        ('-06:00', '(GMT -6:00) Central Time (US & Canada), Mexico City'),
        ('-05:00', '(GMT -5:00) Eastern Time (US & Canada), Bogota, Lima'),
        ('-04:30', '(GMT -4:30) Caracas'),
        ('-04:00', '(GMT -4:00) Atlantic Time (Canada), Caracas, La Paz'),
        ('-03:30', '(GMT -3:30) Newfoundland'),
        ('-03:00', '(GMT -3:00) Brazil, Buenos Aires, Georgetown'),
        ('-02:00', '(GMT -2:00) Mid-Atlantic'),
        ('-01:00', '(GMT -1:00) Azores, Cape Verde Islands')
    ])


# Error handlers
@app.errorhandler(403)
def forbidden(e):
    """Handle 403 Forbidden errors"""
    return render_template('403.html'), 403


@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 Not Found errors"""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 Internal Server Error"""
    return render_template('500.html'), 500


# Make helper functions available to blueprints
app.generate_ticket_code = generate_ticket_code
app.hash_identifier = hash_identifier
app.verify_identifier = verify_identifier
app.generate_captcha = generate_captcha
app.TicketForm = TicketForm
app.EventDisplayForm = EventDisplayForm

# Register Blueprints
from routes.main import main_bp
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.wiki import wiki_bp

app.register_blueprint(main_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(wiki_bp)


# Run application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

