"""
Authentication routes (Wikimedia OAuth login/logout)
"""

from flask import Blueprint, request, redirect, url_for, session, flash, current_app
from flask_login import login_user, logout_user
from flask_babel import gettext as _
from models import User, WikiUser
from extensions import db
import mwoauth
from datetime import datetime

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/wiki-login')
def wiki_login():
    """Initiate an OAuth login.
    
    Call the MediaWiki server to get request secrets and then redirect the
    user to the MediaWiki server to sign the request.
    """
    consumer_token = mwoauth.ConsumerToken(
        current_app.config['CONSUMER_KEY'], current_app.config['CONSUMER_SECRET'])
    try:
        redirect_url, request_token = mwoauth.initiate(
            current_app.config['OAUTH_MWURI'], consumer_token)
    except Exception as e:
        current_app.logger.exception('mwoauth.initiate failed')
        flash(f'OAuth initialization failed: {str(e)}', 'error')
        return redirect(url_for('main.index'))
    else:
        session['oauth_request_token'] = dict(zip(
            request_token._fields, request_token))
        return redirect(redirect_url)


@auth_bp.route('/oauth-callback')
def oauth_callback():
    """OAuth handshake callback."""
    if 'oauth_request_token' not in session:
        flash(_('OAuth callback failed. Are cookies disabled?'), 'error')
        return redirect(url_for('main.index'))
    
    consumer_token = mwoauth.ConsumerToken(
        current_app.config['CONSUMER_KEY'], current_app.config['CONSUMER_SECRET'])
    
    try:
        access_token = mwoauth.complete(
            current_app.config['OAUTH_MWURI'],
            consumer_token,
            mwoauth.RequestToken(**session['oauth_request_token']),
            request.query_string)
        
        identity = mwoauth.identify(
            current_app.config['OAUTH_MWURI'], consumer_token, access_token)
    except Exception as e:
        current_app.logger.exception('OAuth authentication failed')
        flash(f'OAuth authentication failed: {str(e)}', 'error')
        return redirect(url_for('main.index'))
    else:
        # Store access token and username in session
        session['oauth_access_token'] = dict(zip(
            access_token._fields, access_token))
        session['wiki_username'] = identity['username']
        
        # Get SUPERADMIN_USERNAME from app config
        SUPERADMIN_USERNAME = current_app.config.get('SUPERADMIN_USERNAME', '')
        
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
    
    return redirect(url_for('wiki.dashboard'))


@auth_bp.route('/wiki-logout')
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
    return redirect(url_for('main.index'))

