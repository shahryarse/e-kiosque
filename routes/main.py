"""
Main routes for public pages (homepage, event details, ticket reservation)
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file, abort
from flask_babel import gettext as _
from models import Event, Ticket, WaitingList
from extensions import db, limiter
from datetime import datetime, timezone, timedelta
import uuid
import hashlib
import time
import base64
import qrcode
from io import BytesIO
import re
import pytz
from services.waiting_list_service import WaitingListService

main_bp = Blueprint('main', __name__)


def recalculate_available_tickets(event):
    """Recalculate and update available_tickets for an event based on actual ticket count"""
    total_issued_tickets = Ticket.query.filter_by(event_id=event.id).count()
    event.available_tickets = max(0, event.capacity - total_issued_tickets)
    return event.available_tickets

@main_bp.route('/')
def index():
    """Homepage with list of public events"""
    # Get page number from query parameters, default to 1
    page = request.args.get('page', 1, type=int)
    
    # Get paginated events, excluding private events
    # No longer updating status on every page load for performance
    events = Event.query.filter_by(is_private=False).order_by(Event.date.asc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    # Recalculate available_tickets for each event to ensure accuracy
    for event in events.items:
        recalculate_available_tickets(event)
    
    return render_template('index.html', events=events)


@main_bp.route('/event/<int:event_id>')
def event_detail(event_id):
    """Display event details and reservation form"""
    from app import verify_identifier, TicketForm, EventDisplayForm
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if event is private
    if event.is_private:
        flash(_('This is a private event. Please use the private link to access it.'), 'error')
        return redirect(url_for('main.index'))
    
    # Get current identifiers
    current_ip = request.remote_addr
    current_session_id = session.get('_id', str(uuid.uuid4()))
    current_cookie = request.cookies.get('session', str(uuid.uuid4()))
    
    # Get username if user is logged in
    from flask_login import current_user
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
    
    # Check if user is in waiting list
    user_waiting = None
    if current_username:
        # Check by username first
        user_waiting = WaitingList.query.filter_by(
            event_id=event_id,
            username=current_username,
            converted_to_ticket=False
        ).first()
    
    # If not found by username, check by identifiers
    if not user_waiting:
        from app import verify_identifier
        waiting_entries = WaitingList.query.filter_by(
            event_id=event_id,
            converted_to_ticket=False
        ).all()
        
        for entry in waiting_entries:
            if (verify_identifier(current_ip, entry.hashed_ip) or
                verify_identifier(current_session_id, entry.hashed_session) or
                verify_identifier(current_cookie, entry.hashed_cookie)):
                user_waiting = entry
                break
    
    # Recalculate available_tickets to ensure accuracy
    recalculate_available_tickets(event)
    
    ticket_form = TicketForm()
    display_form = EventDisplayForm()
    return render_template('event.html', 
                          event=event, 
                          form=ticket_form, 
                          display_form=display_form, 
                          pytz=pytz, 
                          datetime=datetime,
                          user_ticket=user_ticket,
                          ticket_token=ticket_token,
                          user_waiting=user_waiting)


@main_bp.route('/reserve/<int:event_id>', methods=['POST'])
def reserve_ticket(event_id):
    """Handle ticket reservation"""
    from app import hash_identifier, TicketForm, generate_ticket_code
    from flask_login import current_user
    
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
        return redirect(url_for('main.event_detail', event_id=event_id))
    
    # Verify CAPTCHA
    captcha_input = request.form.get('captcha', '').upper()
    stored_captcha = session.get('captcha', '')
    if captcha_input != stored_captcha:
        flash(_('Invalid CAPTCHA. Please try again.'), 'error')
        return redirect(url_for('main.event_detail', event_id=event_id))
    
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
            return redirect(url_for('main.event_detail', event_id=event_id))
    
    # Get all tickets for this event to check IP and cookies
    from app import verify_identifier
    existing_tickets = Ticket.query.filter_by(event_id=event_id).all()
    
    # Check if any existing ticket matches any of our identifiers
    for ticket in existing_tickets:
        if verify_identifier(current_ip, ticket.hashed_ip) or verify_identifier(current_session_id, ticket.hashed_session) or verify_identifier(current_cookie, ticket.hashed_cookie):
            flash(_('You have already reserved a ticket for this event.'), 'error')
            return redirect(url_for('main.event_detail', event_id=event_id))
    
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
        return redirect(url_for('main.event_detail', event_id=event_id))


@main_bp.route('/private/<string:private_link>')
def private_event(private_link):
    """Route for accessing private events"""
    from app import TicketForm, EventDisplayForm
    
    event = Event.query.filter_by(private_link=private_link, is_private=True).first()
    if event is None:
        abort(404)
        
    if not event.is_active:
        flash(_('This event is not active.'), 'error')
        return redirect(url_for('main.index'))
    
    ticket_form = TicketForm()
    display_form = EventDisplayForm()
    return render_template('event.html', event=event, form=ticket_form, display_form=display_form, pytz=pytz, datetime=datetime)


@main_bp.route('/view-ticket/<string:token>')
@limiter.limit("10 per minute")
def view_ticket_by_token(token):
    """View ticket by secure token"""
    from app import verify_identifier
    from flask_login import current_user
    from extensions import csrf
    
    # Verify token format to prevent injection attacks
    if not re.match(r'^[a-f0-9]{64}$', token):
        flash(_('Invalid ticket link format.'), 'error')
        return redirect(url_for('main.index'))
        
    # Check if the token exists in the session
    session_key = f'ticket_token_{token}'
    if session_key not in session:
        flash(_('Invalid or expired ticket link.'), 'error')
        return redirect(url_for('main.index'))
    
    # Get the token data from the session
    token_data = session[session_key]
    
    # Check if the token has expired
    current_time = int(time.time())
    if current_time > token_data['expires_at']:
        # Token has expired, remove it from session
        session.pop(session_key, None)
        flash(_('Ticket link has expired. Please view the event page to get a new link.'), 'error')
        return redirect(url_for('main.index'))
    
    # Get the ticket ID
    ticket_id = token_data['ticket_id']
    
    # Get the ticket
    ticket = db.session.get(Ticket, ticket_id)
    if not ticket:
        # If ticket not found, remove the session key and redirect
        session.pop(session_key, None)
        flash(_('Ticket not found.'), 'error')
        return redirect(url_for('main.index'))
    
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
        return redirect(url_for('main.index'))
    
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


@main_bp.route('/set_language/<lang>')
def set_language(lang):
    """Change application language"""
    from flask import current_app
    if lang in current_app.config['BABEL_SUPPORTED_LOCALES']:
        session['language'] = lang
    return redirect(request.referrer or url_for('main.index'))


@main_bp.route('/captcha')
def captcha():
    """Generate and serve CAPTCHA image"""
    from app import generate_captcha
    img_byte_arr = generate_captcha()
    return send_file(img_byte_arr, mimetype='image/png')


@main_bp.route('/event/<int:event_id>/join-waiting-list', methods=['POST'])
def join_waiting_list(event_id):
    """Add user to waiting list for a fully booked event"""
    from app import hash_identifier, TicketForm
    from flask_login import current_user
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if waiting list is enabled
    if not event.enable_waiting_list:
        flash(_('Waiting list is not available for this event.'), 'error')
        return redirect(url_for('main.event_detail', event_id=event_id))
    
    # Check if tickets are still available
    if event.available_tickets > 0:
        flash(_('Tickets are still available! Please reserve directly.'), 'info')
        return redirect(url_for('main.event_detail', event_id=event_id))
    
    # Verify CAPTCHA
    captcha_input = request.form.get('captcha', '').upper()
    stored_captcha = session.get('captcha', '')
    if captcha_input != stored_captcha:
        flash(_('Invalid CAPTCHA. Please try again.'), 'error')
        return redirect(url_for('main.event_detail', event_id=event_id))
    
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
    
    # Get form data
    name = request.form.get('name') if event.collect_name else None
    email = request.form.get('email') if event.collect_email else None
    phone = request.form.get('phone') if event.collect_phone else None
    
    # Validate email is provided
    if event.collect_email and not email:
        flash(_('Email is required to join the waiting list.'), 'error')
        return redirect(url_for('main.event_detail', event_id=event_id))
    
    # Set username
    username = None
    if current_username:
        username = current_username
    elif event.collect_username:
        username = request.form.get('username')
    
    # Hash identifiers
    hashed_ip = hash_identifier(current_ip)
    hashed_session = hash_identifier(current_session_id)
    hashed_cookie = hash_identifier(current_cookie)
    
    # Add to waiting list
    success, result, position = WaitingListService.add_to_waiting_list(
        event_id=event_id,
        name=name,
        email=email,
        username=username,
        phone=phone,
        hashed_ip=hashed_ip,
        hashed_session=hashed_session,
        hashed_cookie=hashed_cookie
    )
    
    if success:
        flash(_('You have been added to the waiting list at position %(position)s. We will notify you if a ticket becomes available.', position=position), 'success')
    else:
        flash(_('Could not join waiting list: %(error)s', error=result), 'error')
    
    return redirect(url_for('main.event_detail', event_id=event_id))


@main_bp.route('/waiting-list/<int:waiting_id>/remove', methods=['POST'])
def remove_from_waiting_list(waiting_id):
    """Remove user from waiting list"""
    from app import verify_identifier
    
    waiting_entry = WaitingList.query.get_or_404(waiting_id)
    event_id = waiting_entry.event_id
    
    # Verify user identity
    current_ip = request.remote_addr
    current_session_id = session.get('_id')
    current_cookie = request.cookies.get('session')
    
    # Check if the request is from the same user
    is_same_user = False
    if verify_identifier(current_ip, waiting_entry.hashed_ip):
        is_same_user = True
    elif current_session_id and verify_identifier(current_session_id, waiting_entry.hashed_session):
        is_same_user = True
    elif current_cookie and verify_identifier(current_cookie, waiting_entry.hashed_cookie):
        is_same_user = True
    
    # Also allow if logged in with same username
    current_username = session.get('wiki_username')
    if current_username and current_username == waiting_entry.username:
        is_same_user = True
    
    if not is_same_user:
        flash(_('You can only remove yourself from the waiting list.'), 'error')
        return redirect(url_for('main.event_detail', event_id=event_id))
    
    # Remove from waiting list
    success, message = WaitingListService.remove_from_waiting_list(waiting_id)
    
    if success:
        flash(_('You have been removed from the waiting list.'), 'success')
    else:
        flash(_('Could not remove from waiting list: %(error)s', error=message), 'error')
    
    return redirect(url_for('main.event_detail', event_id=event_id))

