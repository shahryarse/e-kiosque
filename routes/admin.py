"""
Admin panel routes (dashboard, manage admins, manage events and tickets)
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_file, jsonify, abort, current_app
from flask_login import login_required, current_user
from flask_babel import gettext as _
from models import User, Event, Ticket, SiteNotice
from extensions import db
from datetime import datetime, timezone
from sqlalchemy import func
import xlsxwriter
from io import BytesIO
import qrcode
import base64
import logging
from event_forms import EventForm, populate_form_from_request, populate_form_from_event, handle_event_update
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, BooleanField
from wtforms.validators import DataRequired

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
logger = logging.getLogger(__name__)


def admin_required(f):
    """Decorator to require admin access"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (not current_user.is_admin and not current_user.is_super_admin):
            flash(_('Access denied. You must be an admin to access this page.'), 'error')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function


def super_admin_required(f):
    """Decorator to require super admin access"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_super_admin:
            flash(_('Access denied. Only super admin can access this page.'), 'error')
            return redirect(url_for('admin.dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/')
@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin dashboard with statistics"""
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


@admin_bp.route('/manage-admins')
@login_required
@super_admin_required
def manage_admins():
    """Manage admin users"""
    admins = User.query.filter(User.is_admin == True).all()
    return render_template('admin/manage_admins.html', admins=admins)


@admin_bp.route('/add-admin', methods=['GET', 'POST'])
@login_required
@super_admin_required
def add_admin():
    """Add a new admin user"""
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            
            if not username:
                flash(_('Username is required.'), 'error')
                return redirect(url_for('admin.add_admin'))
            
            if User.query.filter_by(username=username).first():
                flash(_('Username already exists.'), 'error')
                return redirect(url_for('admin.add_admin'))
            
            new_admin = User(
                username=username,
                is_admin=True
            )
            
            db.session.add(new_admin)
            db.session.commit()
            
            flash(_('Admin added successfully.'), 'success')
            return redirect(url_for('admin.manage_admins'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'{_("Error adding admin:")} {str(e)}', 'error')
            return redirect(url_for('admin.add_admin'))
    
    return render_template('admin/add_admin.html')


@admin_bp.route('/delete-admin/<int:admin_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_admin(admin_id):
    """Delete an admin user"""
    try:
        admin = db.session.get(User, admin_id)
        
        if admin.is_super_admin:
            flash(_('Cannot delete super admin.'), 'error')
            return redirect(url_for('admin.manage_admins'))
        
        db.session.delete(admin)
        db.session.commit()
        flash(_('Admin deleted successfully.'), 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'{_("Error deleting admin:")} {str(e)}', 'error')
    
    return redirect(url_for('admin.manage_admins'))


@admin_bp.route('/run-cleanup', methods=['POST'])
@login_required
@super_admin_required
def run_cleanup():
    """Manually run cleanup of old tickets"""
    # Run the cleanup
    now = datetime.now(timezone.utc)
    past_events = Event.query.filter(Event.date < now).all()
    tickets_deleted = 0
    
    for event in past_events:
        result = Ticket.query.filter_by(event_id=event.id).delete()
        tickets_deleted += result
    
    db.session.commit()
    flash(_('Cleanup complete. {} tickets from past events were deleted.').format(tickets_deleted), 'success')
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/events')
@login_required
@admin_required
def events():
    """List all events"""
    events = Event.query.order_by(Event.date.desc()).all()
    return render_template('admin/events.html', events=events)


@admin_bp.route('/events/<int:event_id>/edit', methods=['GET', 'POST'])
@login_required
@super_admin_required
def edit_event(event_id):
    """Edit an event"""
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
            return redirect(url_for('admin.events'))
        else:
            return result
    else:
        # Pre-populate form with event data
        populate_form_from_event(form, event)
    
    return render_template('admin/edit_event.html', form=form, event=event)


@admin_bp.route('/events/<int:event_id>/tickets')
@login_required
@super_admin_required
def manage_event_tickets(event_id):
    """Manage tickets for a specific event"""
    event = db.session.get(Event, event_id)
    if event is None:
        abort(404)
    
    tickets = Ticket.query.filter_by(event_id=event_id).order_by(Ticket.issue_date.desc()).all()
    return render_template('admin/manage_tickets.html', event=event, tickets=tickets)


@admin_bp.route('/events/<int:event_id>/ticket-details', methods=['POST'])
@login_required
@admin_required
def get_ticket_details(event_id):
    """Get details of a ticket for admin users."""
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


@admin_bp.route('/events/<int:event_id>/delete', methods=['POST'])
@login_required
@super_admin_required
def delete_event(event_id):
    """Delete an event"""
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
        current_app.logger.error(f"Error deleting event: {str(e)}")
        return jsonify({'success': False, 'message': _('An error occurred while deleting the event')}), 500


@admin_bp.route('/tickets')
@login_required
@admin_required
def tickets():
    """List all tickets"""
    tickets = Ticket.query.order_by(Ticket.issue_date.desc()).all()
    return render_template('admin/tickets.html', tickets=tickets)


@admin_bp.route('/tickets/<int:ticket_id>/details', methods=['POST'])
@login_required
@admin_required
def ticket_details(ticket_id):
    """Get details of a ticket"""
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


@admin_bp.route('/tickets/<int:ticket_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_ticket_status(ticket_id):
    """Toggle the status of a ticket"""
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


@admin_bp.route('/tickets/<int:ticket_id>/delete-ticket', methods=['POST'])
@login_required
@admin_required
def delete_ticket(ticket_id):
    """Delete a ticket"""
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


@admin_bp.route('/tickets/bulk-delete', methods=['POST'])
@login_required
@super_admin_required
def bulk_delete_tickets():
    """Bulk delete tickets"""
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


@admin_bp.route('/tickets/bulk-mark-used', methods=['POST'])
@login_required
@super_admin_required
def bulk_mark_used():
    """Bulk mark tickets as used"""
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


@admin_bp.route('/tickets/bulk-mark-unused', methods=['POST'])
@login_required
@super_admin_required
def bulk_mark_unused():
    """Bulk mark tickets as unused"""
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


@admin_bp.route('/tickets/export')
@login_required
@super_admin_required
def export_tickets():
    """Export tickets to Excel"""
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


@admin_bp.route('/analytics')
@login_required
@admin_required
def analytics():
    """Analytics dashboard"""
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


class SiteNoticeForm(FlaskForm):
    """Form for managing site notices"""
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    background_color = StringField('Background Color', validators=[DataRequired()], default='#FFF3CD')
    text_color = StringField('Text Color', validators=[DataRequired()], default='#212529')
    is_active = BooleanField('Active')


@admin_bp.route('/site-notice', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_site_notice():
    """Manage site-wide notices"""
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
                return redirect(url_for('admin.manage_site_notice'))
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


@admin_bp.route('/validate_image', methods=['POST'])
def validate_image():
    """Validate image from Wikimedia Commons"""
    import requests
    
    # Allow both logged-in users and wiki users to validate images
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
        'User-Agent': 'FlaskTicketApp/1.0 (https://yourdomain.com; your@email.com) PythonRequests'
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

