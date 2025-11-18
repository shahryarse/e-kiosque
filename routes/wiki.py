"""
Wiki user routes (dashboard for Wikimedia authenticated users to manage their events)
"""

from flask import Blueprint, render_template, request, redirect, url_for, session, flash, send_file, jsonify, abort, current_app
from flask_babel import gettext as _
from models import WikiUser, Event, Ticket
from extensions import db
from datetime import datetime, timedelta
import xlsxwriter
from io import BytesIO
import qrcode
import base64
import logging
from event_forms import EventForm, populate_form_from_request, populate_form_from_event, handle_event_creation, handle_event_update

wiki_bp = Blueprint('wiki', __name__, url_prefix='/wiki')
logger = logging.getLogger(__name__)


def wiki_login_required(f):
    """Decorator to require wiki login"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'wiki_username' not in session:
            flash(_('Please login with your Wikimedia account.'), 'warning')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


def update_event_status(event):
    """Update event status based on current date"""
    from datetime import timezone
    
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


@wiki_bp.route('/dashboard')
@wiki_login_required
def dashboard():
    """Dashboard for Wikimedia users to manage their events."""
    # Get the WikiUser
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('auth.wiki_login'))
    
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


@wiki_bp.route('/events/new', methods=['GET', 'POST'])
@wiki_login_required
def new_event():
    """Create a new event as a Wikimedia user."""
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('auth.wiki_login'))
    
    form = EventForm()
    if request.method == 'POST':
        # Get form data using the shared function
        form_data = populate_form_from_request(form)
        form_data['form'] = form
        
        # Use the shared function to handle event creation
        result = handle_event_creation(form_data, wiki_user, is_wiki=True)
        if result is True:
            return redirect(url_for('wiki.dashboard'))
        else:
            return result
    
    return render_template('wiki/new_event.html', form=form)


@wiki_bp.route('/events/<int:event_id>/edit', methods=['GET', 'POST'])
@wiki_login_required
def edit_event(event_id):
    """Edit an event as a Wikimedia user."""
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('auth.wiki_login'))
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        flash(_('You do not have permission to edit this event.'), 'error')
        return redirect(url_for('wiki.dashboard'))
    
    form = EventForm()
    
    if request.method == 'POST':
        # Get form data using the shared function
        form_data = populate_form_from_request(form)
        form_data['form'] = form
        
        # Use the shared function to handle event update
        result = handle_event_update(event, form_data, is_wiki=True)
        if result is True:
            return redirect(url_for('wiki.dashboard'))
        else:
            return result
    else:
        # Pre-populate form with event data
        populate_form_from_event(form, event)
    
    return render_template('wiki/edit_event.html', form=form, event=event)


@wiki_bp.route('/events/<int:event_id>/tickets')
@wiki_login_required
def manage_tickets(event_id):
    """Manage tickets for an event as a Wikimedia user."""
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('auth.wiki_login'))
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        flash(_('You do not have permission to manage tickets for this event.'), 'error')
        return redirect(url_for('wiki.dashboard'))
    
    tickets = Ticket.query.filter_by(event_id=event_id).order_by(Ticket.issue_date.desc()).all()
    return render_template('wiki/manage_tickets.html', event=event, tickets=tickets)


@wiki_bp.route('/events/<int:event_id>/bulk-ticket-action', methods=['POST'])
@wiki_login_required
def bulk_ticket_action(event_id):
    """Perform bulk actions on tickets for an event."""
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


@wiki_bp.route('/events/<int:event_id>/toggle-ticket', methods=['POST'])
@wiki_login_required
def toggle_ticket_status(event_id):
    """Toggle the status of a ticket."""
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


@wiki_bp.route('/events/<int:event_id>/delete-ticket', methods=['POST'])
@wiki_login_required
def delete_ticket(event_id):
    """Delete a ticket."""
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


@wiki_bp.route('/events/<int:event_id>/ticket-details', methods=['POST'])
@wiki_login_required
def get_ticket_details(event_id):
    """Get details of a ticket."""
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


@wiki_bp.route('/events/<int:event_id>/export-tickets')
@wiki_login_required
def export_tickets(event_id):
    """Export tickets for an event as an Excel file."""
    wiki_user = WikiUser.query.filter_by(username=session['wiki_username']).first()
    if not wiki_user:
        flash(_('User account not found. Please login again.'), 'error')
        return redirect(url_for('auth.wiki_login'))
    
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    # Check if this user created this event
    if event.wiki_creator_id != wiki_user.id:
        flash(_('You do not have permission to export tickets for this event.'), 'error')
        return redirect(url_for('wiki.dashboard'))
    
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


@wiki_bp.route('/events/<int:event_id>/delete', methods=['POST'])
@wiki_login_required
def delete_event(event_id):
    """Delete an event as a Wikimedia user."""
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
        current_app.logger.error(f"Error deleting event: {str(e)}")
        return jsonify({'success': False, 'message': _('An error occurred while deleting the event')}), 500


@wiki_bp.route('/validate_image', methods=['POST'])
def validate_image():
    """Validate image from Wikimedia Commons"""
    import requests
    
    # Check if it's a form submission or JSON request
    if request.is_json:
        data = request.json
        original_filename = data.get('filename', '').strip()
    else:
        original_filename = request.form.get('filename', '').strip()
    
    logger.debug(f"Received filename for validation: {original_filename}")
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
        "iiprop": "url|size",
        "format": "json"
    }

    headers = {
        'User-Agent': 'e-kiosque/1.0 (Toolforge; e-kiosque@toolforge.org) PythonRequests'
    }

    try:
        logger.debug(f"Querying Wikimedia Commons API with params: {params}")
        response = requests.get(api_url, params=params, headers=headers, timeout=5)
        response.raise_for_status()
        
        data = response.json()
        logger.debug(f"API Response received: {data}")

        # Navigate the API response structure
        query_result = data.get('query', {})
        pages = query_result.get('pages', {})
        
        # Check if the page exists (key is not '-1') and has imageinfo
        page_id = next(iter(pages), '-1')
        
        if page_id != '-1' and 'imageinfo' in pages[page_id]:
            image_info = pages[page_id]['imageinfo'][0]
            image_url = image_info.get('url')
            
            if image_url:
                logger.debug(f"Image found on Wikimedia Commons: {image_url}")
                return jsonify({
                    'exists': True,
                    'url': image_url
                })
            else:
                logger.warning("Image URL not found in API response imageinfo")
                return jsonify({'exists': False, 'message': _('Image URL not found in API response')})
        else:
            logger.info(f"Image not found on Wikimedia Commons (Page ID: {page_id})")
            return jsonify({'exists': False, 'message': _('Image not found on Wikimedia Commons')})

    except requests.exceptions.RequestException as e:
        logger.error(f"Wikimedia Commons API request failed: {str(e)}")
        return jsonify({'exists': False, 'message': f"Error querying Wikimedia API: {str(e)}"})
    except Exception as e:
        logger.exception("Unexpected error during image validation")
        return jsonify({'exists': False, 'message': str(e)})

