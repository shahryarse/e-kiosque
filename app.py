from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, abort
from datetime import datetime, timezone, timedelta
import os
import random
import string
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO
import hashlib
from sqlalchemy import func
import time
import uuid
import pytz
import qrcode
import base64
import mwoauth
import tomllib
from models import User, Event, Ticket, AccessRestriction, SiteNotice, WikiUser
from extensions import db, login_manager, csrf, babel
from flask_login import login_user, logout_user, current_user, login_required
from flask_babel import gettext as _
import xlsxwriter
from event_forms import EventForm, generate_private_link, handle_event_creation, handle_event_update, populate_form_from_event, populate_form_from_request
import requests
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, BooleanField
from wtforms.validators import DataRequired, Optional, Email
from argon2 import PasswordHasher
import re
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tickets.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Set session lifetime to 1 hour
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_SUPPORTED_LOCALES'] = ['en', 'fa']
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

# Load OAuth configuration if available
if os.path.exists('config.toml'):
    with open('config.toml', 'rb') as f:
        app.config.update(tomllib.load(f))
        SUPERADMIN_USERNAME = app.config['SUPERADMIN_USERNAME']

# Initialize extensions
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'wiki_login'
csrf.init_app(app)

# Add SALT and PEPPER constants at the top of the file
SALT = "RANDOM_SALT"
PEPPER = "RANDOM_PEPPER"

# Add rate limiting functionality
# Store IP addresses and their request counts
rate_limit_data = {}

def rate_limited(max_per_minute):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            current_time = int(time.time())
            minute_window = current_time - (current_time % 60)
            
            if ip not in rate_limit_data:
                rate_limit_data[ip] = {'count': 0, 'window': minute_window}
            
            # Reset count if in a new time window
            if rate_limit_data[ip]['window'] < minute_window:
                rate_limit_data[ip] = {'count': 0, 'window': minute_window}
            
            # Increment the request count
            rate_limit_data[ip]['count'] += 1
            
            # Check if rate limit is exceeded
            if rate_limit_data[ip]['count'] > max_per_minute:
                app.logger.warning(f"Rate limit exceeded for IP: {ip}")
                return render_template('429.html'), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_locale():
    # Check if language is set in session
    if 'language' in session:
        return session['language']
    # Default to English
    return 'en'

# Make get_locale available to templates
app.jinja_env.globals['get_locale'] = get_locale

# Initialize Babel with the locale selector function
babel.init_app(app, locale_selector=get_locale)

# Add context processor for current year
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.context_processor
def inject_site_notice():
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

@app.route('/set_language/<lang>')
def set_language(lang):
    if lang in app.config['BABEL_SUPPORTED_LOCALES']:
        session['language'] = lang
    return redirect(request.referrer or url_for('index'))

@login_manager.user_loader
def load_user(user_id):
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

# Helper functions
def generate_ticket_code():
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

@app.route('/captcha')
def captcha():
    img_byte_arr = generate_captcha()
    return send_file(img_byte_arr, mimetype='image/png')

# Main routes
@app.route('/')
def index():
    # Update status of all events first
    events = Event.query.all()
    for event in events:
        update_event_status(event)
    db.session.commit()
    
    # Get page number from query parameters, default to 1
    page = request.args.get('page', 1, type=int)
    
    # Get paginated events, excluding private events
    events = Event.query.filter_by(is_private=False).order_by(Event.date.asc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    return render_template('index.html', events=events)

class TicketForm(FlaskForm):
    name = StringField('Name', validators=[Optional()])
    email = StringField('Email', validators=[Optional(), Email()])
    captcha = StringField('CAPTCHA', validators=[DataRequired()])

class EventDisplayForm(FlaskForm):
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

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if event is private
    if event.is_private:
        flash(_('This is a private event. Please use the private link to access it.'), 'error')
        return redirect(url_for('index'))
    
    # Get current identifiers
    current_ip = request.remote_addr
    current_session_id = session.get('_id', str(uuid.uuid4()))
    current_cookie = request.cookies.get('session', str(uuid.uuid4()))
    
    # Get username if user is logged in
    current_username = None
    if current_user and current_user.is_authenticated:
        current_username = current_user.username
    elif session.get('wiki_username'):
        current_username = session.get('wiki_username')
    
    # Check if the user already has a ticket for this event
    user_ticket = None
    
    # First check by username if the user is logged in
    if current_username:
        user_ticket = Ticket.query.filter_by(
            event_id=event_id,
            username=current_username
        ).first()
    
    # If no ticket found by username, check by identifiers
    if not user_ticket:
        # Get all tickets for this event
        event_tickets = Ticket.query.filter_by(event_id=event_id).all()
        
        # Check if any existing ticket matches any of our identifiers
        for ticket in event_tickets:
            if (verify_identifier(current_ip, ticket.hashed_ip) or
                verify_identifier(current_session_id, ticket.hashed_session) or
                verify_identifier(current_cookie, ticket.hashed_cookie)):
                user_ticket = ticket
                break
    
    # Generate a secure token for viewing the ticket (if user has one)
    ticket_token = None
    if user_ticket:
        # Generate a secure random token with timestamp to prevent guessing
        token_data = f"{user_ticket.id}:{uuid.uuid4()}:{int(time.time())}"
        ticket_token = hashlib.sha256(token_data.encode()).hexdigest()
        
        # Store the token in session with the ticket id and expiration time (24 hours)
        session[f'ticket_token_{ticket_token}'] = {
            'ticket_id': user_ticket.id,
            'expires_at': int(time.time()) + 86400  # 24 hours in seconds
        }
    
    ticket_form = TicketForm()
    display_form = EventDisplayForm()
    return render_template('event.html', 
                          event=event, 
                          form=ticket_form, 
                          display_form=display_form, 
                          pytz=pytz, 
                          datetime=datetime,
                          user_ticket=user_ticket,
                          ticket_token=ticket_token)

@app.route('/reserve/<int:event_id>', methods=['POST'])
def reserve_ticket(event_id):
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if registration is open
    # Handle offset-based timezone (e.g., "+03:30")
    offset = event.timezone
    hours, minutes = int(offset[1:3]), int(offset[4:6])
    sign = 1 if offset[0] == '+' else -1
    offset_seconds = sign * (hours * 3600 + minutes * 60)
    
    # Create timezone with the offset
    tz = timezone(timedelta(seconds=offset_seconds))
    now = datetime.now(tz)
    
    # Make sure registration dates are timezone-aware
    if not event.registration_start.tzinfo:
        registration_start = event.registration_start.replace(tzinfo=tz)
    else:
        registration_start = event.registration_start
    
    if not event.registration_end.tzinfo:
        registration_end = event.registration_end.replace(tzinfo=tz)
    else:
        registration_end = event.registration_end
    
    if not (registration_start <= now <= registration_end):
        flash(_('Registration is not open for this event.'), 'error')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Verify CAPTCHA
    captcha_input = request.form.get('captcha', '').upper()
    stored_captcha = session.get('captcha', '')
    if captcha_input != stored_captcha:
        flash(_('Invalid CAPTCHA. Please try again.'), 'error')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Get current identifiers
    current_ip = request.remote_addr
    current_session_id = session.get('_id', str(uuid.uuid4()))
    current_cookie = request.cookies.get('session', str(uuid.uuid4()))
    
    # Get username if user is logged in
    current_username = None
    if current_user and current_user.is_authenticated:
        current_username = current_user.username
    elif session.get('wiki_username'):
        current_username = session.get('wiki_username')
    
    # Check for existing tickets by username first (more efficient)
    if current_username:
        username_ticket = Ticket.query.filter_by(
            event_id=event_id,
            username=current_username
        ).first()
        
        if username_ticket:
            flash(_('You have already reserved a ticket for this event.'), 'error')
            return redirect(url_for('event_detail', event_id=event_id))
    
    # Get all tickets for this event to check IP and cookies
    existing_tickets = Ticket.query.filter_by(event_id=event_id).all()
    
    # Check if any existing ticket matches any of our identifiers
    for ticket in existing_tickets:
        if verify_identifier(current_ip, ticket.hashed_ip) or verify_identifier(current_session_id, ticket.hashed_session) or verify_identifier(current_cookie, ticket.hashed_cookie):
            flash(_('You have already reserved a ticket for this event.'), 'error')
            return redirect(url_for('event_detail', event_id=event_id))
    
    # Create new ticket with hashed identifiers
    ticket_code = generate_ticket_code()
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(ticket_code)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code to base64
    buffered = BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    # Hash the identifiers for storage
    hashed_ip = hash_identifier(current_ip)
    hashed_session = hash_identifier(current_session_id)
    hashed_cookie = hash_identifier(current_cookie)
    
    # Set username directly if the user is logged in
    username = None
    if current_username:
        username = current_username
    elif event.collect_username:
        username = request.form.get('username')
    
    ticket = Ticket(
        event_id=event_id,
        ticket_code=ticket_code,
        name=request.form.get('name') if event.collect_name else None,
        email=request.form.get('email') if event.collect_email else None,
        username=username,
        phone=request.form.get('phone') if event.collect_phone else None,
        hashed_ip=hashed_ip,
        hashed_session=hashed_session,
        hashed_cookie=hashed_cookie,
        expiry_time=event.date
    )
    
    # Update event available tickets
    event.available_tickets -= 1
    
    try:
        db.session.add(ticket)
        db.session.commit()
        return render_template('ticket.html', ticket=ticket, qr_base64=qr_base64)
    except Exception as e:
        db.session.rollback()
        flash(f'{_("Error reserving ticket:")} {str(e)}', 'error')
        return redirect(url_for('event_detail', event_id=event_id))

# Admin routes
@app.route('/admin')
@login_required
def admin_dashboard():
    # Check if the user is an admin
    if not current_user.is_admin and not current_user.is_super_admin:
        flash(_('Access denied. You must be an admin to access this page.'), 'error')
        return redirect(url_for('index'))
    
    total_events = Event.query.count()
    active_events = Event.query.filter_by(is_active=True).count()
    total_tickets = Ticket.query.count()
    used_tickets = Ticket.query.filter_by(is_used=True).count()
    
    # Get ticket distribution by event (top 10 by ticket count)
    event_stats = db.session.query(
        Event.title,
        func.count(Ticket.id).label('count')
    ).outerjoin(Ticket).group_by(Event.id).order_by(func.count(Ticket.id).desc()).limit(10).all()
    
    # Get recent tickets
    recent_tickets = Ticket.query.order_by(Ticket.issue_date.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html',
                         total_events=total_events,
                         active_events=active_events,
                         total_tickets=total_tickets,
                         used_tickets=used_tickets,
                         event_stats=event_stats,
                         recent_tickets=recent_tickets)

@app.route('/admin/manage-admins')
@login_required
def manage_admins():
    # Check if the user is a super admin
    if not current_user.is_super_admin:
        flash(_('Access denied. Only super admin can manage admins.'), 'error')
        return redirect(url_for('admin_dashboard'))
    
    admins = User.query.filter(User.is_admin == True).all()
    return render_template('admin/manage_admins.html', admins=admins)

@app.route('/admin/add-admin', methods=['GET', 'POST'])
@login_required
def add_admin():
    # Check if the user is a super admin
    if not current_user.is_super_admin:
        flash(_('Access denied. Only super admin can add admins.'), 'error')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            
            if not username:
                flash(_('Username is required.'), 'error')
                return redirect(url_for('add_admin'))
            
            if User.query.filter_by(username=username).first():
                flash(_('Username already exists.'), 'error')
                return redirect(url_for('add_admin'))
            
            new_admin = User(
                username=username,
                is_admin=True
            )
            
            db.session.add(new_admin)
            db.session.commit()
            
            flash(_('Admin added successfully.'), 'success')
            return redirect(url_for('manage_admins'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'{_("Error adding admin:")} {str(e)}', 'error')
            return redirect(url_for('add_admin'))
    
    return render_template('admin/add_admin.html')

@app.route('/admin/delete-admin/<int:admin_id>', methods=['POST'])
@login_required
def delete_admin(admin_id):
    # Check if the user is a super admin
    if not current_user.is_super_admin:
        flash(_('Access denied. Only super admin can delete admins.'), 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        admin = db.session.get(User, admin_id)
        
        if admin.is_super_admin:
            flash(_('Cannot delete super admin.'), 'error')
            return redirect(url_for('manage_admins'))
        
        db.session.delete(admin)
        db.session.commit()
        flash(_('Admin deleted successfully.'), 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'{_("Error deleting admin:")} {str(e)}', 'error')
    
    return redirect(url_for('manage_admins'))

@app.route('/admin/run-cleanup', methods=['POST'])
@login_required
def admin_run_cleanup():
    if not current_user.is_super_admin:
        flash(_('Unauthorized'), 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Run the cleanup
    now = datetime.now(timezone.utc)
    past_events = Event.query.filter(Event.date < now).all()
    tickets_deleted = 0
    
    for event in past_events:
        result = Ticket.query.filter_by(event_id=event.id).delete()
        tickets_deleted += result
    
    db.session.commit()
    flash(_('Cleanup complete. {} tickets from past events were deleted.').format(tickets_deleted), 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/cleanup', methods=['POST'])
def cleanup_old_data():
    """Clean up old ticket data after events end"""
    now = datetime.now(timezone.utc)
    
    past_events = Event.query.filter(Event.date < now).all()
    for event in past_events:
        Ticket.query.filter_by(event_id=event.id).delete()
    
    db.session.commit()
    return jsonify({'status': 'success'})

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/admin/events/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_event(event_id):
    if not current_user.is_super_admin:
        return redirect(url_for('index'))
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    form = EventForm()
    
    if request.method == 'POST':
        # Get form data using the shared function
        form_data = populate_form_from_request(form)
        form_data['form'] = form
        
        # Use the shared function to handle event update
        result = handle_event_update(event, form_data, is_wiki=False)
        if result is True:
            return redirect(url_for('admin_events'))
        else:
            return result
    else:
        # Pre-populate form with event data
        populate_form_from_event(form, event)
    
    return render_template('admin/edit_event.html', form=form, event=event)

@app.route('/admin/events/<int:event_id>/tickets')
@login_required
def manage_event_tickets(event_id):
    if not current_user.is_super_admin:
        return redirect(url_for('index'))
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    tickets = Ticket.query.filter_by(event_id=event_id).order_by(Ticket.issue_date.desc()).all()
    return render_template('admin/manage_tickets.html', event=event, tickets=tickets)

@app.route('/admin/events/<int:event_id>/ticket-details', methods=['POST'])
@login_required
def admin_get_ticket_details(event_id):
    """Get details of a ticket for admin users."""
    if not current_user.is_admin and not current_user.is_super_admin:
        return jsonify({'success': False, 'message': _('Authentication required')})
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    data = request.get_json()
    if not data or 'ticket_id' not in data:
        return jsonify({'success': False, 'message': _('Invalid request')})
    
    ticket_id = data['ticket_id']
    
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if ticket and ticket.event_id == event_id:
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(ticket.ticket_code)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffered = BytesIO()
            img.save(buffered)
            qr_base64 = base64.b64encode(buffered.getvalue()).decode()
            
            # Render ticket details template
            html = render_template('partials/ticket_details.html', 
                                  ticket=ticket, 
                                  event=event, 
                                  qr_base64=qr_base64)
            
            return jsonify({'success': True, 'html': html})
        else:
            return jsonify({'success': False, 'message': _('Ticket not found')})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/tickets/bulk-delete', methods=['POST'])
@login_required
def bulk_delete_tickets():
    if not current_user.is_super_admin:
        return jsonify({'success': False, 'message': _('Unauthorized')})
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': _('Invalid request data')})
        
        ticket_ids = data.get('ticket_ids', [])
        if not ticket_ids:
            return jsonify({'success': False, 'message': _('No tickets selected')})
        
        tickets = Ticket.query.filter(Ticket.id.in_(ticket_ids)).all()
        for ticket in tickets:
            event = ticket.event
            event.available_tickets += 1
            db.session.delete(ticket)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/tickets/export')
@login_required
def export_tickets():
    if not current_user.is_super_admin:
        return redirect(url_for('index'))
    
    event_id = request.args.get('event_id', type=int)
    
    if event_id:
        # Export tickets for a specific event
        event = db.session.get(Event, event_id)
        if event is None:
            abort(404)
        tickets = Ticket.query.filter_by(event_id=event_id).all()
        filename = f'tickets_{event.title}_{datetime.now().strftime("%Y%m%d")}.xlsx'
    else:
        # Export all tickets
        tickets = Ticket.query.all()
        filename = f'all_tickets_{datetime.now().strftime("%Y%m%d")}.xlsx'
    
    # Create Excel file
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()
    
    # Add headers
    headers = ['Ticket Code', 'Event', 'Name', 'Email', 'Username', 'Phone Number', 'Issue Date', 'Status']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header)
    
    # Add data
    for row, ticket in enumerate(tickets, start=1):
        worksheet.write(row, 0, ticket.ticket_code)
        worksheet.write(row, 1, ticket.event.title)
        worksheet.write(row, 2, ticket.name or '-')
        worksheet.write(row, 3, ticket.email or '-')
        worksheet.write(row, 4, ticket.username or '-')
        worksheet.write(row, 5, ticket.phone or '-')
        worksheet.write(row, 6, ticket.issue_date.strftime('%Y-%m-%d %H:%M'))
        worksheet.write(row, 7, _('Used') if ticket.is_used else _('Not Used'))
    
    workbook.close()
    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

@app.route('/admin/tickets/bulk-mark-used', methods=['POST'])
@login_required
def bulk_mark_used():
    if not current_user.is_super_admin:
        return jsonify({'success': False, 'message': _('Unauthorized')})
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': _('Invalid request data')})
        
        ticket_ids = data.get('ticket_ids', [])
        if not ticket_ids:
            return jsonify({'success': False, 'message': _('No tickets selected')})
        
        tickets = Ticket.query.filter(Ticket.id.in_(ticket_ids)).all()
        for ticket in tickets:
            ticket.is_used = True
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/tickets/bulk-mark-unused', methods=['POST'])
@login_required
def bulk_mark_unused():
    if not current_user.is_super_admin:
        return jsonify({'success': False, 'message': _('Unauthorized')})
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': _('Invalid request data')})
        
        ticket_ids = data.get('ticket_ids', [])
        if not ticket_ids:
            return jsonify({'success': False, 'message': _('No tickets selected')})
        
        tickets = Ticket.query.filter(Ticket.id.in_(ticket_ids)).all()
        for ticket in tickets:
            ticket.is_used = False
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/analytics')
@login_required
def analytics():
    total_events = Event.query.count()
    active_events = Event.query.filter_by(is_active=True).count()
    total_tickets = Ticket.query.count()
    used_tickets = Ticket.query.filter_by(is_used=True).count()
    
    # Get ticket distribution by event
    event_stats = db.session.query(
        Event.title,
        func.count(Ticket.id).label('count')
    ).outerjoin(Ticket).group_by(Event.id).all()
    
    # Get recent tickets
    recent_tickets = Ticket.query.order_by(Ticket.issue_date.desc()).limit(10).all()
    
    return render_template('admin/analytics.html',
                         total_events=total_events,
                         active_events=active_events,
                         total_tickets=total_tickets,
                         used_tickets=used_tickets,
                         event_stats=event_stats,
                         recent_tickets=recent_tickets)

@app.route('/validate_image', methods=['POST'])
def validate_image():
    # Allow both logged-in users and wiki users to validate images
    # Check if it's a form submission or JSON request
    if request.is_json:
        data = request.json
        original_filename = data.get('filename', '').strip()
    else:
        original_filename = request.form.get('filename', '').strip()
    
    print(f"[Debug] Received filename: {original_filename}")
    if not original_filename:
        return jsonify({'exists': False, 'message': _('Please enter a filename')})

    # Ensure filename starts with "File:" for the API query
    if not original_filename.lower().startswith('file:'):
        query_title = f"File:{original_filename}"
    else:
        query_title = original_filename

    # Wikimedia Commons API endpoint
    api_url = "https://commons.wikimedia.org/w/api.php"

    params = {
        "action": "query",
        "titles": query_title,
        "prop": "imageinfo",
        "iiprop": "url|size", # Request URL and size
        "format": "json"
    }

    headers = {
        'User-Agent': 'FlaskTicketApp/1.0 (https://yourdomain.com; your@email.com) PythonRequests'
        # Replace with your actual app info if possible, otherwise this generic one is fine
    }

    try:
        print(f"[Debug] Querying API: {api_url} with params {params}")
        response = requests.get(api_url, params=params, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        
        data = response.json()
        print(f"[Debug] API Response: {data}")

        # Navigate the API response structure
        query_result = data.get('query', {})
        pages = query_result.get('pages', {})
        
        # Check if the page exists (key is not '-1') and has imageinfo
        page_id = next(iter(pages), '-1') # Get the first page ID or '-1'
        
        if page_id != '-1' and 'imageinfo' in pages[page_id]:
            image_info = pages[page_id]['imageinfo'][0]
            image_url = image_info.get('url')
            
            if image_url:
                print(f"[Debug] Image found: {image_url}")
                return jsonify({
                    'exists': True,
                    'url': image_url
                })
            else:
                 print("[Debug] 'url' key missing in imageinfo")
                 return jsonify({'exists': False, 'message': _('Image URL not found in API response')})
        else:
            print(f"[Debug] Page not found or missing imageinfo (Page ID: {page_id})")
            return jsonify({'exists': False, 'message': _('Image not found on Wikimedia Commons')})

    except requests.exceptions.RequestException as e:
        print(f"[Debug] API Request Exception: {str(e)}")
        return jsonify({'exists': False, 'message': f"Error querying Wikimedia API: {str(e)}"})
    except Exception as e:
        print(f"[Debug] General Exception: {str(e)}")
        return jsonify({'exists': False, 'message': str(e)})

class SiteNoticeForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    background_color = StringField('Background Color', validators=[DataRequired()], default='#FFF3CD')
    text_color = StringField('Text Color', validators=[DataRequired()], default='#212529')
    is_active = BooleanField('Active')

@app.route('/admin/site-notice', methods=['GET', 'POST'])
@login_required
def manage_site_notice():
    if not current_user.is_admin:
        flash(_('Unauthorized'), 'error')
        return redirect(url_for('admin_dashboard'))
    
    form = SiteNoticeForm()
    
    # Get the latest notice to edit if it exists
    notice = SiteNotice.query.order_by(SiteNotice.updated_at.desc()).first()
    
    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                if notice:
                    # Update existing notice
                    notice.title = form.title.data
                    notice.content = form.content.data
                    notice.background_color = form.background_color.data
                    notice.text_color = form.text_color.data
                    notice.is_active = form.is_active.data
                    notice.updated_at = datetime.utcnow()
                else:
                    # Create new notice
                    notice = SiteNotice(
                        title=form.title.data,
                        content=form.content.data,
                        background_color=form.background_color.data,
                        text_color=form.text_color.data,
                        is_active=form.is_active.data,
                        created_by=current_user.id
                    )
                    db.session.add(notice)
                
                db.session.commit()
                flash(_('Site notice updated successfully'), 'success')
                return redirect(url_for('manage_site_notice'))
            except Exception as e:
                db.session.rollback()
                flash(f'{_("Error updating site notice:")} {str(e)}', 'error')
    
    elif notice:
        # Populate form with existing notice data
        form.title.data = notice.title
        form.content.data = notice.content
        form.background_color.data = notice.background_color
        form.text_color.data = notice.text_color
        form.is_active.data = notice.is_active
    
    return render_template('admin/site_notice.html', form=form, notice=notice)

# Wikimedia OAuth routes
@app.route('/wiki-login')
def wiki_login():
    """Initiate an OAuth login.
    
    Call the MediaWiki server to get request secrets and then redirect the
    user to the MediaWiki server to sign the request.
    """
    consumer_token = mwoauth.ConsumerToken(
        app.config['CONSUMER_KEY'], app.config['CONSUMER_SECRET'])
    try:
        redirect_url, request_token = mwoauth.initiate(
            app.config['OAUTH_MWURI'], consumer_token)
    except Exception as e:
        app.logger.exception('mwoauth.initiate failed')
        flash(f'OAuth initialization failed: {str(e)}', 'error')
        return redirect(url_for('index'))
    else:
        session['oauth_request_token'] = dict(zip(
            request_token._fields, request_token))
        return redirect(redirect_url)

@app.route('/oauth-callback')
def oauth_callback():
    """OAuth handshake callback."""
    if 'oauth_request_token' not in session:
        flash(_('OAuth callback failed. Are cookies disabled?'), 'error')
        return redirect(url_for('index'))
    
    consumer_token = mwoauth.ConsumerToken(
        app.config['CONSUMER_KEY'], app.config['CONSUMER_SECRET'])
    
    try:
        access_token = mwoauth.complete(
            app.config['OAUTH_MWURI'],
            consumer_token,
            mwoauth.RequestToken(**session['oauth_request_token']),
            request.query_string)
        
        identity = mwoauth.identify(
            app.config['OAUTH_MWURI'], consumer_token, access_token)
    except Exception as e:
        app.logger.exception('OAuth authentication failed')
        flash(f'OAuth authentication failed: {str(e)}', 'error')
    else:
        # Store access token and username in session
        session['oauth_access_token'] = dict(zip(
            access_token._fields, access_token))
        session['wiki_username'] = identity['username']
        
        # Store or update WikiUser in database
        wiki_user = WikiUser.query.filter_by(username=identity['username']).first()
        if not wiki_user:
            # Check if this is the super admin user
            is_super_admin = identity['username'] == SUPERADMIN_USERNAME
            wiki_user = WikiUser(
                username=identity['username'],
                access_token=access_token.key,
                access_secret=access_token.secret,
                is_admin=is_super_admin,  # Super admin is also an admin
                is_super_admin=is_super_admin
            )
            db.session.add(wiki_user)
        else:
            # Update admin status for super admin if needed
            if identity['username'] == SUPERADMIN_USERNAME and not wiki_user.is_super_admin:
                wiki_user.is_admin = True
                wiki_user.is_super_admin = True
            wiki_user.last_login = datetime.utcnow()
            wiki_user.access_token = access_token.key
            wiki_user.access_secret = access_token.secret
        
        db.session.commit()
        
        # Create a temporary User object for login
        user = User()
        user.id = wiki_user.id
        user.username = wiki_user.username
        user.is_admin = wiki_user.is_admin
        user.is_super_admin = wiki_user.is_super_admin
        user.is_active = True  # Required by Flask-Login
        
        # Log the user in
        login_user(user, remember=True)
        
        # Regenerate session for security
        session_data = dict(session)
        session.clear()
        session.update(session_data)
        session.modified = True
        
        flash(_('You have been successfully logged in with your Wikimedia account.'), 'success')
    
    return redirect(url_for('wiki_dashboard'))

@app.route('/wiki-logout')
def wiki_logout():
    """Log the user out by clearing their session."""
    # Save any non-auth related session data we want to keep
    language = session.get('language')
    
    # Clear the entire session for security
    session.clear()
    
    # Restore non-auth data
    if language:
        session['language'] = language
    
    # Log out the user from Flask-Login
    logout_user()
    
    flash(_('You have been logged out from your Wikimedia account.'), 'success')
    return redirect(url_for('index'))

@app.route('/wiki-dashboard')
def wiki_dashboard():
    """Dashboard for Wikimedia users to manage their events."""
    if 'wiki_username' not in session:
        flash(_('Please login with your Wikimedia account.'), 'warning')
        return redirect(url_for('index'))
    
    # Get the WikiUser
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('wiki_login'))
    
    # Get events created by this user
    user_events = Event.query.filter_by(wiki_creator_id=wiki_user.id).all()
    
    # Update event status for all events
    for event in user_events:
        update_event_status(event)
    
    # Filter active and past events
    active_events = [event for event in user_events if event.is_active]
    past_events = [event for event in user_events if not event.is_active]
    
    # Calculate statistics
    total_tickets = sum(len(event.tickets) for event in user_events)
    tickets_used = sum(sum(1 for ticket in event.tickets if ticket.is_used) for event in user_events)
    
    return render_template('wiki/dashboard.html', 
                          events=user_events, 
                          active_events=active_events,
                          past_events=past_events,
                          total_tickets=total_tickets,
                          tickets_used=tickets_used,
                          username=session['wiki_username'])

@app.route('/wiki/events/new', methods=['GET', 'POST'])
def wiki_new_event():
    """Create a new event as a Wikimedia user."""
    if 'wiki_username' not in session:
        flash(_('Please login with your Wikimedia account.'), 'warning')
        return redirect(url_for('index'))
    
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('wiki_login'))
    
    form = EventForm()
    if request.method == 'POST':
        # Get form data using the shared function
        form_data = populate_form_from_request(form)
        form_data['form'] = form
        
        # Use the shared function to handle event creation
        result = handle_event_creation(form_data, wiki_user, is_wiki=True)
        if result is True:
            return redirect(url_for('wiki_dashboard'))
        else:
            return result
    
    return render_template('wiki/new_event.html', form=form)

@app.route('/wiki/events/<int:event_id>/edit', methods=['GET', 'POST'])
def wiki_edit_event(event_id):
    """Edit an event as a Wikimedia user."""
    if 'wiki_username' not in session:
        flash(_('Please login with your Wikimedia account.'), 'warning')
        return redirect(url_for('index'))
    
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('wiki_login'))
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        flash(_('You do not have permission to edit this event.'), 'error')
        return redirect(url_for('wiki_dashboard'))
    
    form = EventForm()
    
    if request.method == 'POST':
        # Get form data using the shared function
        form_data = populate_form_from_request(form)
        form_data['form'] = form
        
        # Use the shared function to handle event update
        result = handle_event_update(event, form_data, is_wiki=True)
        if result is True:
            return redirect(url_for('wiki_dashboard'))
        else:
            return result
    else:
        # Pre-populate form with event data
        populate_form_from_event(form, event)
    
    return render_template('wiki/edit_event.html', form=form, event=event)

@app.route('/wiki/events/<int:event_id>/tickets')
def wiki_manage_tickets(event_id):
    """Manage tickets for an event as a Wikimedia user."""
    if 'wiki_username' not in session:
        flash(_('Please login with your Wikimedia account.'), 'warning')
        return redirect(url_for('index'))
    
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('wiki_login'))
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        flash(_('You do not have permission to manage tickets for this event.'), 'error')
        return redirect(url_for('wiki_dashboard'))
    
    tickets = Ticket.query.filter_by(event_id=event_id).order_by(Ticket.issue_date.desc()).all()
    return render_template('wiki/manage_tickets.html', event=event, tickets=tickets)

@app.route('/wiki/events/<int:event_id>/bulk-ticket-action', methods=['POST'])
def wiki_bulk_ticket_action(event_id):
    """Perform bulk actions on tickets for an event."""
    if 'wiki_username' not in session:
        return jsonify({'success': False, 'message': _('Authentication required')})
    
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        return jsonify({'success': False, 'message': _('User account not found')})
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        return jsonify({'success': False, 'message': _('Permission denied')})
    
    data = request.get_json()
    if not data or 'ticket_ids' not in data or 'action' not in data:
        return jsonify({'success': False, 'message': _('Invalid request')})
    
    ticket_ids = data['ticket_ids']
    action = data['action']
    
    try:
        if action == 'delete':
            # Delete tickets
            for ticket_id in ticket_ids:
                ticket = db.session.get(Ticket, ticket_id)
                if ticket and ticket.event_id == event_id:
                    db.session.delete(ticket)
            
            # Update available tickets
            event.available_tickets = event.capacity - Ticket.query.filter_by(event_id=event_id).count()
            db.session.commit()
            return jsonify({'success': True, 'message': _('Tickets deleted successfully')})
            
        elif action == 'mark_used':
            # Mark tickets as used
            for ticket_id in ticket_ids:
                ticket = db.session.get(Ticket, ticket_id)
                if ticket and ticket.event_id == event_id:
                    ticket.is_used = True
            db.session.commit()
            return jsonify({'success': True, 'message': _('Tickets marked as used')})
            
        elif action == 'mark_unused':
            # Mark tickets as unused
            for ticket_id in ticket_ids:
                ticket = db.session.get(Ticket, ticket_id)
                if ticket and ticket.event_id == event_id:
                    ticket.is_used = False
            db.session.commit()
            return jsonify({'success': True, 'message': _('Tickets marked as unused')})
            
        else:
            return jsonify({'success': False, 'message': _('Invalid action')})
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/wiki/events/<int:event_id>/toggle-ticket', methods=['POST'])
def wiki_toggle_ticket_status(event_id):
    """Toggle the status of a ticket."""
    if 'wiki_username' not in session:
        return jsonify({'success': False, 'message': _('Authentication required')})
    
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        return jsonify({'success': False, 'message': _('User account not found')})
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        return jsonify({'success': False, 'message': _('Permission denied')})
    
    data = request.get_json()
    if not data or 'ticket_id' not in data or 'is_used' not in data:
        return jsonify({'success': False, 'message': _('Invalid request')})
    
    ticket_id = data['ticket_id']
    is_used = data['is_used']
    
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if ticket and ticket.event_id == event_id:
            ticket.is_used = is_used
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': _('Ticket not found')})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/wiki/events/<int:event_id>/delete-ticket', methods=['POST'])
def wiki_delete_ticket(event_id):
    """Delete a ticket."""
    if 'wiki_username' not in session:
        return jsonify({'success': False, 'message': _('Authentication required')})
    
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        return jsonify({'success': False, 'message': _('User account not found')})
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        return jsonify({'success': False, 'message': _('Permission denied')})
    
    data = request.get_json()
    if not data or 'ticket_id' not in data:
        return jsonify({'success': False, 'message': _('Invalid request')})
    
    ticket_id = data['ticket_id']
    
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if ticket and ticket.event_id == event_id:
            db.session.delete(ticket)
            # Update available tickets
            event.available_tickets = event.capacity - Ticket.query.filter_by(event_id=event_id).count()
            db.session.commit()
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': _('Ticket not found')})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/wiki/events/<int:event_id>/ticket-details', methods=['POST'])
def wiki_get_ticket_details(event_id):
    """Get details of a ticket."""
    if 'wiki_username' not in session:
        return jsonify({'success': False, 'message': _('Authentication required')})
    
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        return jsonify({'success': False, 'message': _('User account not found')})
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        return jsonify({'success': False, 'message': _('Permission denied')})
    
    data = request.get_json()
    if not data or 'ticket_id' not in data:
        return jsonify({'success': False, 'message': _('Invalid request')})
    
    ticket_id = data['ticket_id']
    
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if ticket and ticket.event_id == event_id:
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(ticket.ticket_code)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffered = BytesIO()
            img.save(buffered)
            qr_base64 = base64.b64encode(buffered.getvalue()).decode()
            
            # Render ticket details template
            html = render_template('partials/ticket_details.html', 
                                  ticket=ticket, 
                                  event=event, 
                                  qr_base64=qr_base64)
            
            return jsonify({'success': True, 'html': html})
        else:
            return jsonify({'success': False, 'message': _('Ticket not found')})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/wiki/events/<int:event_id>/export-tickets')
def wiki_export_tickets(event_id):
    """Export tickets for an event as an Excel file."""
    if 'wiki_username' not in session:
        flash(_('Please login with your Wikimedia account.'), 'warning')
        return redirect(url_for('index'))
    
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('wiki_login'))
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        flash(_('You do not have permission to export tickets for this event.'), 'error')
        return redirect(url_for('wiki_dashboard'))
    
    tickets = Ticket.query.filter_by(event_id=event_id).all()
    
    # Create a workbook and add a worksheet
    output = BytesIO()
    workbook = xlsxwriter.Workbook(output)
    worksheet = workbook.add_worksheet()
    
    # Add a bold format
    bold = workbook.add_format({'bold': True})
    
    # Write headers
    headers = [_('Ticket Code'), _('Name'), _('Email'), _('Username'), _('Phone Number'), _('Registration Date'), _('Status')]
    for col, header in enumerate(headers):
        worksheet.write(0, col, header, bold)
    
    # Write data rows
    for row, ticket in enumerate(tickets, 1):
        worksheet.write(row, 0, ticket.ticket_code)
        worksheet.write(row, 1, ticket.name if ticket.name else '')
        worksheet.write(row, 2, ticket.email if ticket.email else '')
        worksheet.write(row, 3, ticket.username if ticket.username else '')
        worksheet.write(row, 4, ticket.phone if ticket.phone else '')
        worksheet.write(row, 5, ticket.issue_date.strftime('%Y-%m-%d %H:%M:%S'))
        worksheet.write(row, 6, _('Used') if ticket.is_used else _('Unused'))
    
    # Close the workbook
    workbook.close()
    
    # Set to the beginning of the stream
    output.seek(0)
    
    # Create a safe filename
    safe_event_name = "".join([c for c in event.title if c.isalpha() or c.isdigit() or c==' ']).rstrip()
    filename = f"{safe_event_name}_tickets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

@app.route('/wiki/events/<int:event_id>/delete', methods=['POST'])
def wiki_delete_event(event_id):
    """Delete an event as a Wikimedia user."""
    if 'wiki_username' not in session:
        return jsonify({'success': False, 'message': _('Authentication required')}), 401
    
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        return jsonify({'success': False, 'message': _('User account not found')}), 404
    
    try:
        # Get the event
        event = db.session.get(Event, event_id)
        
        # Check if event exists
        if not event:
            return jsonify({'success': False, 'message': _('Event not found')}), 404
        
        # Check if the wiki user is the event creator
        if event.wiki_creator_id != wiki_user.id:
            return jsonify({'success': False, 'message': _('You can only delete events you created')}), 403
        
        # Check for unused tickets
        unused_tickets_count = Ticket.query.filter_by(
            event_id=event_id, 
            is_used=False
        ).count()
        
        if unused_tickets_count > 0:
            return jsonify({
                'success': False, 
                'message': _('Cannot delete event with unused tickets. Please mark all tickets as used first.')
            }), 400
        
        # Delete all tickets associated with the event
        Ticket.query.filter_by(event_id=event_id).delete()
        
        # Delete the event
        db.session.delete(event)
        db.session.commit()
        
        return jsonify({'success': True, 'message': _('Event deleted successfully')})
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting event: {str(e)}")
        return jsonify({'success': False, 'message': _('An error occurred while deleting the event')}), 500

@app.route('/private/<string:private_link>')
def private_event(private_link):
    """Route for accessing private events"""
    event = Event.query.filter_by(private_link=private_link, is_private=True).first()
    if event is None:
        abort(404)
        
    if not event.is_active:
        flash(_('This event is not active.'), 'error')
        return redirect(url_for('index'))
    
    ticket_form = TicketForm()
    display_form = EventDisplayForm()
    return render_template('event.html', event=event, form=ticket_form, display_form=display_form, pytz=pytz, datetime=datetime)

def update_event_status(event):
    """Update event status based on current date"""
    # Get the event's timezone
    offset = event.timezone
    hours, minutes = int(offset[1:3]), int(offset[4:6])
    sign = 1 if offset[0] == '+' else -1
    offset_seconds = sign * (hours * 3600 + minutes * 60)
    tz = timezone(timedelta(seconds=offset_seconds))
    
    # Make event date timezone-aware if it isn't already
    if not event.date.tzinfo:
        event.date = event.date.replace(tzinfo=tz)
    
    # Get current time in the same timezone
    now = datetime.now(tz)
    
    if event.date < now:
        event.is_active = False
        return True
    return False

@app.route('/admin/events')
@login_required
def admin_events():
    if not current_user.is_admin and not current_user.is_super_admin:
        flash(_('Access denied. You must be an admin to access this page.'), 'error')
        return redirect(url_for('index'))
    
    events = Event.query.order_by(Event.date.desc()).all()
    return render_template('admin/events.html', events=events)

@app.route('/admin/tickets')
@login_required
def admin_tickets():
    if not current_user.is_admin and not current_user.is_super_admin:
        flash(_('Access denied. You must be an admin to access this page.'), 'error')
        return redirect(url_for('index'))
    
    tickets = Ticket.query.order_by(Ticket.issue_date.desc()).all()
    return render_template('admin/tickets.html', tickets=tickets)

@app.route('/admin/tickets/<int:ticket_id>/details', methods=['POST'])
@login_required
def admin_ticket_details(ticket_id):
    """Get details of a ticket for admin users."""
    if not current_user.is_admin and not current_user.is_super_admin:
        return jsonify({'success': False, 'message': _('Authentication required')})
    
    # We don't need to get the ticket_id from the request body since it's in the URL
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if ticket is None:
            return jsonify({'success': False, 'message': _('Ticket not found')}), 404
            
        event = ticket.event
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(ticket.ticket_code)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = BytesIO()
        img.save(buffered)
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        # Render ticket details template
        html = render_template('partials/ticket_details.html', 
                              ticket=ticket, 
                              event=event, 
                              qr_base64=qr_base64)
        
        return jsonify({'success': True, 'html': html})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/events/<int:event_id>/delete', methods=['POST'])
@login_required
def admin_delete_event(event_id):
    """Delete an event as an admin."""
    if not current_user.is_super_admin:
        return jsonify({'success': False, 'message': _('Unauthorized. Only super admin can delete events.')}), 401
    
    try:
        # Get the event
        event = db.session.get(Event, event_id)
        
        # Check if event exists
        if not event:
            return jsonify({'success': False, 'message': _('Event not found')}), 404
        
        # Check for unused tickets
        unused_tickets_count = Ticket.query.filter_by(
            event_id=event_id, 
            is_used=False
        ).count()
        
        if unused_tickets_count > 0:
            return jsonify({
                'success': False, 
                'message': _('Cannot delete event with unused tickets. Please mark all tickets as used first.')
            }), 400
        
        # Delete all tickets associated with the event
        Ticket.query.filter_by(event_id=event_id).delete()
        
        # Delete the event
        db.session.delete(event)
        db.session.commit()
        
        return jsonify({'success': True, 'message': _('Event deleted successfully')})
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting event: {str(e)}")
        return jsonify({'success': False, 'message': _('An error occurred while deleting the event')}), 500

@app.route('/admin/tickets/<int:ticket_id>/toggle-status', methods=['POST'])
@login_required
def admin_toggle_ticket_status(ticket_id):
    """Toggle the status of a ticket."""
    if not current_user.is_admin and not current_user.is_super_admin:
        return jsonify({'success': False, 'message': _('Unauthorized')}), 403
    
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if ticket is None:
            abort(404)
            
        ticket.is_used = not ticket.is_used
        db.session.commit()
        return jsonify({'success': True, 'is_used': ticket.is_used})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/tickets/<int:ticket_id>/delete-ticket', methods=['POST'])
@login_required
def admin_delete_ticket(ticket_id):
    """Delete a ticket."""
    if not current_user.is_admin and not current_user.is_super_admin:
        return jsonify({'success': False, 'message': _('Unauthorized')}), 403
    
    try:
        ticket = db.session.get(Ticket, ticket_id)
        if ticket is None:
            abort(404)
            
        event = ticket.event
        event.available_tickets += 1
        db.session.delete(ticket)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/view-ticket/<string:token>')
@csrf.exempt  # Exempt this route from CSRF as we're using the token itself for security
@rate_limited(10)  # Limit to 10 requests per minute
def view_ticket_by_token(token):
    # Verify token format to prevent injection attacks
    if not re.match(r'^[a-f0-9]{64}$', token):
        flash(_('Invalid ticket link format.'), 'error')
        return redirect(url_for('index'))
        
    # Check if the token exists in the session
    session_key = f'ticket_token_{token}'
    if session_key not in session:
        flash(_('Invalid or expired ticket link.'), 'error')
        return redirect(url_for('index'))
    
    # Get the token data from the session
    token_data = session[session_key]
    
    # Check if the token has expired
    current_time = int(time.time())
    if current_time > token_data['expires_at']:
        # Token has expired, remove it from session
        session.pop(session_key, None)
        flash(_('Ticket link has expired. Please view the event page to get a new link.'), 'error')
        return redirect(url_for('index'))
    
    # Get the ticket ID
    ticket_id = token_data['ticket_id']
    
    # Get the ticket
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        # If ticket not found, remove the session key and redirect
        session.pop(session_key, None)
        flash(_('Ticket not found.'), 'error')
        return redirect(url_for('index'))
    
    # Verify the user has access to this ticket 
    current_ip = request.remote_addr
    current_session_id = session.get('_id', str(uuid.uuid4()))
    current_cookie = request.cookies.get('session', str(uuid.uuid4()))
    current_username = None
    
    if current_user and current_user.is_authenticated:
        current_username = current_user.username
    elif session.get('wiki_username'):
        current_username = session.get('wiki_username')
    
    # Check if the user is associated with this ticket
    has_access = False
    
    # Check by username first
    if current_username and ticket.username == current_username:
        has_access = True
    
    # Then check by identifiers
    if not has_access:
        if (verify_identifier(current_ip, ticket.hashed_ip) or
            verify_identifier(current_session_id, ticket.hashed_session) or
            verify_identifier(current_cookie, ticket.hashed_cookie)):
            has_access = True
    
    if not has_access:
        flash(_('You do not have permission to view this ticket.'), 'error')
        return redirect(url_for('index'))
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(ticket.ticket_code)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert QR code to base64
    buffered = BytesIO()
    qr_img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    # Regenerate the token each time it's used for better security
    new_token_data = f"{ticket.id}:{uuid.uuid4()}:{int(time.time())}"
    new_token = hashlib.sha256(new_token_data.encode()).hexdigest()
    
    # Store the new token and remove the old one
    session[f'ticket_token_{new_token}'] = {
        'ticket_id': ticket.id,
        'expires_at': int(time.time()) + 86400  # 24 hours in seconds
    }
    session.pop(session_key, None)
    
    # Add the new token to the template context
    return render_template('ticket.html', ticket=ticket, qr_base64=qr_base64, ticket_token=new_token)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 