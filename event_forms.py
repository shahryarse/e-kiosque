from flask import flash, request, render_template
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, IntegerField, BooleanField, FileField
from wtforms.validators import DataRequired, Optional, Email
from datetime import datetime, timezone, timedelta
import random
import string
import requests
from flask_babel import gettext as _
from extensions import db
from models import Event, Ticket

class EventForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    date = StringField('Date', validators=[DataRequired()])
    time = StringField('Time', validators=[DataRequired()])
    timezone = SelectField('Timezone', validators=[DataRequired()], choices=[
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
    location = StringField('Location', validators=[DataRequired()])
    capacity = IntegerField('Capacity', validators=[DataRequired()])
    registration_start_date = StringField('Registration Start Date', validators=[DataRequired()])
    registration_start_time = StringField('Registration Start Time', validators=[DataRequired()])
    registration_end_date = StringField('Registration End Date', validators=[DataRequired()])
    registration_end_time = StringField('Registration End Time', validators=[DataRequired()])
    is_active = BooleanField('Active')
    is_private = BooleanField('Private Event')
    collect_name = BooleanField('Collect Name')
    name_optional = BooleanField('Name Optional')
    collect_email = BooleanField('Collect Email')
    email_optional = BooleanField('Email Optional')
    collect_username = BooleanField('Collect Username')
    username_optional = BooleanField('Username Optional')
    collect_phone = BooleanField('Collect Phone Number')
    phone_optional = BooleanField('Phone Number Optional')
    image_filename = StringField('Image Filename', validators=[Optional()])
    image = FileField('Upload Image', validators=[Optional()])
    commons_image = StringField('Wikimedia Commons Image', validators=[Optional()])

def generate_private_link():
    """Generate a complex private link using multiple random components"""
    # Generate a random string with mixed case letters, numbers, and special characters
    chars = string.ascii_letters + string.digits + '_-'
    while True:
        # Generate 4 segments of 16 characters each, joined by hyphens
        segments = []
        for _ in range(4):
            segment = ''.join(random.choices(chars, k=16))
            segments.append(segment)
        private_link = '-'.join(segments)
        
        # Check if the link is unique
        if not Event.query.filter_by(private_link=private_link).first():
            return private_link

def populate_form_from_request(form):
    """Populate form from request data"""
    # Capture all form values
    title = request.form.get('title')
    description = request.form.get('description')
    date_str = request.form.get('date')
    time_str = request.form.get('time')
    timezone_name = request.form.get('timezone')
    location = request.form.get('location')
    capacity = request.form.get('capacity')
    registration_start_date = request.form.get('registration_start_date')
    registration_start_time = request.form.get('registration_start_time')
    registration_end_date = request.form.get('registration_end_date')
    registration_end_time = request.form.get('registration_end_time')
    
    # Handle checkbox fields differently based on request method
    if request.method == 'POST':
        is_active = 'is_active' in request.form
        is_private = 'is_private' in request.form
        collect_name = 'collect_name' in request.form
        name_optional = 'name_optional' in request.form
        collect_email = 'collect_email' in request.form
        email_optional = 'email_optional' in request.form
        collect_username = 'collect_username' in request.form
        username_optional = 'username_optional' in request.form
        collect_phone = 'collect_phone' in request.form
        phone_optional = 'phone_optional' in request.form
    else:
        is_active = request.form.get('is_active') == 'true'
        is_private = request.form.get('is_private') == 'true'
        collect_name = request.form.get('collect_name') == 'true'
        name_optional = request.form.get('name_optional') == 'true'
        collect_email = request.form.get('collect_email') == 'true'
        email_optional = request.form.get('email_optional') == 'true'
        collect_username = request.form.get('collect_username') == 'true'
        username_optional = request.form.get('username_optional') == 'true'
        collect_phone = request.form.get('collect_phone') == 'true'
        phone_optional = request.form.get('phone_optional') == 'true'
    
    image_filename = request.form.get('image_filename')
    
    # Pre-populate form with submitted values
    form.title.data = title
    form.description.data = description
    form.date.data = date_str
    form.time.data = time_str
    form.timezone.data = timezone_name
    form.location.data = location
    if capacity:
        try:
            form.capacity.data = int(capacity)
        except ValueError:
            pass
    form.registration_start_date.data = registration_start_date
    form.registration_start_time.data = registration_start_time
    form.registration_end_date.data = registration_end_date
    form.registration_end_time.data = registration_end_time
    form.is_active.data = is_active
    form.is_private.data = is_private
    form.collect_name.data = collect_name
    form.name_optional.data = name_optional
    form.collect_email.data = collect_email
    form.email_optional.data = email_optional
    form.collect_username.data = collect_username
    form.username_optional.data = username_optional
    form.collect_phone.data = collect_phone
    form.phone_optional.data = phone_optional
    form.image_filename.data = image_filename
    
    # Return all the form values for further processing
    return {
        'title': title,
        'description': description,
        'date_str': date_str,
        'time_str': time_str,
        'timezone_name': timezone_name,
        'location': location,
        'capacity': capacity,
        'registration_start_date': registration_start_date,
        'registration_start_time': registration_start_time,
        'registration_end_date': registration_end_date,
        'registration_end_time': registration_end_time,
        'is_active': is_active,
        'is_private': is_private,
        'collect_name': collect_name,
        'name_optional': name_optional,
        'collect_email': collect_email,
        'email_optional': email_optional,
        'collect_username': collect_username,
        'username_optional': username_optional,
        'collect_phone': collect_phone,
        'phone_optional': phone_optional,
        'image_filename': image_filename
    }

def populate_form_from_event(form, event):
    """Populate form with event data"""
    form.title.data = event.title
    form.description.data = event.description
    form.date.data = event.date.strftime('%Y-%m-%d')
    form.time.data = event.time
    form.timezone.data = event.timezone
    form.location.data = event.location
    form.capacity.data = event.capacity
    form.registration_start_date.data = event.registration_start.strftime('%Y-%m-%d')
    form.registration_start_time.data = event.registration_start.strftime('%H:%M')
    form.registration_end_date.data = event.registration_end.strftime('%Y-%m-%d')
    form.registration_end_time.data = event.registration_end.strftime('%H:%M')
    form.is_active.data = event.is_active
    form.is_private.data = event.is_private
    form.collect_name.data = event.collect_name
    form.name_optional.data = event.name_optional
    form.collect_email.data = event.collect_email
    form.email_optional.data = event.email_optional
    form.collect_username.data = event.collect_username
    form.username_optional.data = event.username_optional
    form.collect_phone.data = event.collect_phone
    form.phone_optional.data = event.phone_optional
    
    # Handle image filename if the event has an image URL
    if event.image_url:
        # Extract the filename from the URL
        image_parts = event.image_url.split('/')
        if len(image_parts) > 0:
            # Try to extract the File: part from the URL
            filename = image_parts[-1]
            if 'File:' in event.image_url:
                filename = 'File:' + filename
            form.image_filename.data = filename

def validate_form_inputs(form_data, form, template_path, context=None):
    """Validate basic form inputs and return error response if invalid"""
    if not all([
        form_data['title'], form_data['description'], form_data['date_str'], 
        form_data['time_str'], form_data['timezone_name'], form_data['location'], 
        form_data['capacity'], form_data['registration_start_date'], 
        form_data['registration_start_time'], form_data['registration_end_date'], 
        form_data['registration_end_time']
    ]):
        flash(_('All fields are required.'), 'error')
        return render_template(template_path, form=form, **(context or {}))
    
    return None

def parse_event_dates(form_data):
    """Parse and convert event dates to timezone-aware datetime objects"""
    try:
        # Parse dates and times
        date = datetime.strptime(f"{form_data['date_str']} {form_data['time_str']}", '%Y-%m-%d %H:%M')
        registration_start = datetime.strptime(
            f"{form_data['registration_start_date']} {form_data['registration_start_time']}", '%Y-%m-%d %H:%M')
        registration_end = datetime.strptime(
            f"{form_data['registration_end_date']} {form_data['registration_end_time']}", '%Y-%m-%d %H:%M')
        
        # Convert to timezone-aware datetimes
        offset = form_data['timezone_name']
        hours, minutes = int(offset[1:3]), int(offset[4:6])
        sign = 1 if offset[0] == '+' else -1
        offset_seconds = sign * (hours * 3600 + minutes * 60)
        tz = timezone(timedelta(seconds=offset_seconds))
        
        # Make all datetimes timezone-aware
        date = date.replace(tzinfo=tz)
        registration_start = registration_start.replace(tzinfo=tz)
        registration_end = registration_end.replace(tzinfo=tz)
        
        # Get current time in the same timezone
        now = datetime.now(tz)
        
        # Validate date ordering
        validation_errors = []
        
        # Check if registration_end is after event date
        if registration_end > date:
            validation_errors.append(_('Registration end date cannot be after the event date.'))
        
        # Check if registration_start is after registration_end
        if registration_start > registration_end:
            validation_errors.append(_('Registration start date cannot be after registration end date.'))
        
        if validation_errors:
            return {'error': '\n'.join(validation_errors)}
        
        return {
            'date': date,
            'registration_start': registration_start,
            'registration_end': registration_end,
            'tz': tz,
            'now': now
        }
    except ValueError as e:
        return {'error': str(e)}

def validate_event_date(date_obj, form, template_path, context=None, is_edit=False):
    """Validate that event date is not in the past"""
    # Check if event date is in the past
    if date_obj['date'] < date_obj['now']:
        message = _('Cannot set event date to the past.') if is_edit else _('Cannot create an event in the past.')
        flash(message, 'error')
        # Create a new context that doesn't include 'form' to avoid duplication
        new_context = {}
        if context:
            new_context = {k: v for k, v in context.items() if k != 'form'}
        return render_template(template_path, form=form, **new_context)
    
    # Force is_active to False if event is in the past
    is_active = date_obj['date'] >= date_obj['now']
    
    return is_active

def validate_image(image_filename, form, template_path, context=None):
    """Validate image from Wikimedia Commons and return image URL"""
    if not image_filename or not image_filename.strip():
        return None
    
    # Validate image using the Wikimedia Commons API
    api_url = "https://commons.wikimedia.org/w/api.php"
    
    # Ensure filename starts with "File:" for the API query
    if not image_filename.lower().startswith('file:'):
        query_title = f"File:{image_filename}"
    else:
        query_title = image_filename
    
    params = {
        "action": "query",
        "titles": query_title,
        "prop": "imageinfo",
        "iiprop": "url",
        "format": "json"
    }
    
    headers = {
        'User-Agent': 'FlaskTicketApp/1.0 (https://toolforge.org/; your@email.com) PythonRequests'
    }
    
    try:
        response = requests.get(api_url, params=params, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        query_result = data.get('query', {})
        pages = query_result.get('pages', {})
        
        # Check if the page exists and has imageinfo
        page_id = next(iter(pages), '-1')
        
        if page_id != '-1' and 'imageinfo' in pages[page_id]:
            image_info = pages[page_id]['imageinfo'][0]
            image_url = image_info.get('url')
            
            if not image_url:
                flash(_('Image URL not found. Please make sure the image exists.'), 'error')
                # Create a new context that doesn't include 'form' to avoid duplication
                new_context = {}
                if context:
                    new_context = {k: v for k, v in context.items() if k != 'form'}
                return render_template(template_path, form=form, **new_context)
            
            return image_url
        else:
            flash(_('Image not found on Wikimedia Commons. Please check the filename.'), 'error')
            # Create a new context that doesn't include 'form' to avoid duplication
            new_context = {}
            if context:
                new_context = {k: v for k, v in context.items() if k != 'form'}
            return render_template(template_path, form=form, **new_context)
        
    except Exception as e:
        flash(f'{_("Error validating image:")} {str(e)}', 'error')
        # Create a new context that doesn't include 'form' to avoid duplication
        new_context = {}
        if context:
            new_context = {k: v for k, v in context.items() if k != 'form'}
        return render_template(template_path, form=form, **new_context)

def handle_event_creation(form_data, creator_info, is_wiki=False):
    """Handle event creation for both admin and wiki users"""
    # Determine template path based on user type
    template_path = 'wiki/new_event.html' if is_wiki else 'admin/new_event.html'
    context = {'form': form_data['form']}
    
    # Check for required fields
    error_response = validate_form_inputs(form_data, form_data['form'], template_path, context)
    if error_response:
        return error_response
    
    # Parse and validate dates
    date_obj = parse_event_dates(form_data)
    if 'error' in date_obj:
        flash(_('Invalid date or time format.'), 'error')
        return render_template(template_path, **context)
    
    # Validate event date
    is_active = validate_event_date(date_obj, form_data['form'], template_path, context)
    if isinstance(is_active, str):  # If it's a string, it's an error response
        return is_active
    form_data['is_active'] = is_active
    
    # Validate image and get URL
    image_url = None
    if form_data['image_filename'] and form_data['image_filename'].strip():
        image_url = validate_image(form_data['image_filename'], form_data['form'], template_path, context)
        if isinstance(image_url, str) and 'template' in image_url:  # If it contains 'template', it's an error response
            return image_url
    
    # Generate private link if event is private
    private_link = None
    if form_data['is_private']:
        private_link = generate_private_link()
    
    try:
        # Create new event
        event = Event(
            title=form_data['title'],
            description=form_data['description'],
            date=date_obj['date'],
            time=form_data['time_str'],
            timezone=form_data['timezone_name'],
            location=form_data['location'],
            capacity=int(form_data['capacity']),
            available_tickets=int(form_data['capacity']),
            registration_start=date_obj['registration_start'],
            registration_end=date_obj['registration_end'],
            is_active=form_data['is_active'],
            is_private=form_data['is_private'],
            private_link=private_link,
            collect_name=form_data['collect_name'],
            name_optional=form_data['name_optional'],
            collect_email=form_data['collect_email'],
            email_optional=form_data['email_optional'],
            collect_username=form_data['collect_username'],
            username_optional=form_data['username_optional'],
            collect_phone=form_data['collect_phone'],
            phone_optional=form_data['phone_optional'],
            image_url=image_url,
            creator=creator_info.username if is_wiki else creator_info.username  # Save creator's username
        )
        
        # Set creator based on user type
        if is_wiki:
            event.wiki_creator_id = creator_info.id
        else:
            event.created_by = creator_info.id
        
        db.session.add(event)
        db.session.commit()
        flash(_('Event created successfully.'), 'success')
        return True
    except Exception as e:
        db.session.rollback()
        flash(f'{_("Error creating event:")} {str(e)}', 'error')
        return render_template(template_path, form=form_data['form'])

def handle_event_update(event, form_data, is_wiki=False):
    """Handle event update for both admin and wiki users"""
    # Determine template path based on user type
    template_path = 'wiki/edit_event.html' if is_wiki else 'admin/edit_event.html'
    context = {'event': event, 'form': form_data['form']}
    
    # Check for required fields
    error_response = validate_form_inputs(form_data, form_data['form'], template_path, context)
    if error_response:
        return error_response
    
    # Parse and validate dates
    date_obj = parse_event_dates(form_data)
    if 'error' in date_obj:
        flash(_('Invalid date or time format.'), 'error')
        return render_template(template_path, **context)
    
    # Validate event date
    is_active = validate_event_date(date_obj, form_data['form'], template_path, context, is_edit=True)
    if isinstance(is_active, str):  # If it's a string, it's an error response
        return is_active
    form_data['is_active'] = is_active
    
    # Validate image and get URL
    image_url = event.image_url  # Default to current image URL
    if form_data['image_filename'] and form_data['image_filename'].strip():
        image_url = validate_image(form_data['image_filename'], form_data['form'], template_path, context)
        if isinstance(image_url, str) and 'template' in image_url:  # If it contains 'template', it's an error response
            return image_url
    # If the image field was cleared, set image_url to None
    elif form_data['image_filename'] == '':
        image_url = None
    
    # Generate private link if event is private and doesn't have one
    if form_data['is_private'] and not event.private_link:
        event.private_link = generate_private_link()
    
    try:
        # Update event
        event.title = form_data['title']
        event.description = form_data['description']
        event.date = date_obj['date']
        event.time = form_data['time_str']
        event.timezone = form_data['timezone_name']
        event.location = form_data['location']
        event.capacity = int(form_data['capacity'])
        
        # Calculate available tickets by subtracting used tickets from capacity
        used_tickets = Ticket.query.filter_by(event_id=event.id, is_used=True).count()
        event.available_tickets = int(form_data['capacity']) - used_tickets
        
        event.registration_start = date_obj['registration_start']
        event.registration_end = date_obj['registration_end']
        event.is_active = form_data['is_active']
        event.is_private = form_data['is_private']
        event.collect_name = form_data['collect_name']
        event.name_optional = form_data['name_optional']
        event.collect_email = form_data['collect_email']
        event.email_optional = form_data['email_optional']
        event.collect_username = form_data['collect_username']
        event.username_optional = form_data['username_optional']
        event.collect_phone = form_data['collect_phone']
        event.phone_optional = form_data['phone_optional']
        event.image_url = image_url
        
        db.session.commit()
        flash(_('Event updated successfully.'), 'success')
        return True
    except Exception as e:
        db.session.rollback()
        flash(f'{_("Error updating event:")} {str(e)}', 'error')
        return render_template(template_path, **context) 