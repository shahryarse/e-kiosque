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

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure the application:
   - Create `config.toml` with necessary OAuth credentials
   - Set up environment variables
4. Initialize the database:
   ```bash
   flask db upgrade
   ```
5. Run the application:
   ```bash
   flask run
   ```

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
