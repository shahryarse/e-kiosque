# e-kiosque ([Tool Link](https://meta.wikimedia.org/wiki/E-kiosque))

A secure ticket reservation service for Wikimedia events, deployed on Wikimedia Toolforge.

## Overview

e-kiosque is a Flask-based web application that provides a secure and user-friendly platform for managing event ticket reservations within the Wikimedia community. The system integrates with Wikimedia OAuth for authentication and includes features for event creation, ticket management, and user reservations.

## Features

### Event Management
- Create and manage events with basic information (title, description, date, time, location)
- Set event capacity and registration time windows
- Configure attendee information collection (name, email, username, phone)
- Support for private events with unique access links
- Event image upload capability
- Timezone support for global events

### Ticket System
- Simple ticket reservation system
- Unique ticket codes with QR generation
- Basic attendee information collection
- Ticket validation at event entry
- Ticket management interface for event organizers
- Automatic ticket expiry based on event date

### User Management
- Wikimedia OAuth integration
- Role-based access control (Superadmin, Admin, User)
- User session management
- IP-based rate limiting
- Secure cookie handling

### Security Features
- OAuth-based authentication
- Secure ticket generation and validation
- IP and session tracking for duplicate prevention
- Input validation and sanitization
- Secure error handling
- Environment-based configuration

## Installation

### Prerequisites
- Python 3.11+
- SQLite3
- Git

### Setup Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/e-kiosque.git
   cd e-kiosque
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure the application:**
   
   Copy the example config file:
   ```bash
   cp config.toml.example config.toml
   ```
   
   Edit `config.toml` and set:
   - `SECRET_KEY` - A random secret key for Flask sessions
   - `CONSUMER_KEY` - OAuth consumer key from Wikimedia
   - `CONSUMER_SECRET` - OAuth consumer secret from Wikimedia
   - `SUPERADMIN_USERNAME` - Your Wikimedia username
   - `SALT` - Random string for hashing (generate with `openssl rand -hex 32`)
   - `PEPPER` - Another random string for hashing

5. **Initialize the database:**
   ```bash
   python init_db.py
   ```

6. **Compile translations:**
   ```bash
   python compile_translations.py
   ```

7. **Run the application:**
   
   Development:
   ```bash
   python app.py
   ```
   
   Production (with Gunicorn):
   ```bash
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   ```

8. **Set up scheduled tasks:**
   
   See `CRONJOB_SETUP.md` for cron job configuration.

## Toolforge Deployment

1. Register OAuth consumer at [meta.wikimedia.org](https://meta.wikimedia.org/wiki/Special:OAuthConsumerRegistration/propose)
2. Configure callback URL: `https://your-tool-name.toolforge.org/oauth-callback`
3. Request "Basic rights" permissions
4. Set Tool's maintainer as contact email
5. Deploy to Toolforge using standard deployment procedures

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For questions or support, please contact on sh1380se@gmail.com. 
~ Shahryar Sahebekhtiari
