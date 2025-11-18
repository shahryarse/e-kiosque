#!/usr/bin/env python3
"""
Scheduled Tasks for e-kiosque
This script should be run periodically via cron job to perform maintenance tasks.

Recommended cron schedule:
*/5 * * * * cd /path/to/e-kiosque && python3 cronjob_tasks.py

This runs every 5 minutes to update event statuses and clean up old data.
"""

from app import app, db
from models import Event, Ticket
from datetime import datetime, timezone, timedelta
import logging
import sys

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cronjob.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("cronjob_tasks")


def update_event_statuses():
    """
    Update the is_active status of all events based on their date.
    This should be run periodically instead of on every page load.
    """
    logger.info("Starting event status update task")
    
    try:
        with app.app_context():
            # Get all active events
            active_events = Event.query.filter_by(is_active=True).all()
            updated_count = 0
            
            for event in active_events:
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
                
                # Update status if event has passed
                if event.date < now:
                    event.is_active = False
                    updated_count += 1
                    logger.info(f"Deactivated event: {event.id} - {event.title} (Date: {event.date})")
            
            db.session.commit()
            logger.info(f"Event status update complete. {updated_count} events deactivated.")
            return updated_count
            
    except Exception as e:
        logger.error(f"Error during event status update: {str(e)}")
        db.session.rollback()
        return 0


def cleanup_old_tickets():
    """
    Clean up tickets for events that have ended more than 7 days ago.
    This helps maintain privacy and reduce database size.
    """
    logger.info("Starting old ticket cleanup task")
    
    try:
        with app.app_context():
            # Calculate the cutoff date (7 days ago)
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=7)
            logger.info(f"Cleaning up tickets for events before: {cutoff_date}")
            
            # Get past events older than 7 days
            old_events = Event.query.filter(Event.date < cutoff_date).all()
            logger.info(f"Found {len(old_events)} old events")
            
            tickets_deleted = 0
            
            for event in old_events:
                logger.info(f"Processing event: {event.id} - {event.title} (Date: {event.date})")
                result = Ticket.query.filter_by(event_id=event.id).delete()
                tickets_deleted += result
                logger.info(f"  - Deleted {result} tickets")
            
            db.session.commit()
            logger.info(f"Cleanup complete. Total tickets deleted: {tickets_deleted}")
            return tickets_deleted
            
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        db.session.rollback()
        return 0


def cleanup_expired_access_restrictions():
    """
    Clean up expired access restriction records.
    These are temporary records used for rate limiting.
    """
    logger.info("Starting access restriction cleanup task")
    
    try:
        with app.app_context():
            from models import AccessRestriction
            
            now = datetime.now(timezone.utc)
            
            # Delete expired restrictions
            deleted_count = AccessRestriction.query.filter(
                AccessRestriction.expiry_time < now
            ).delete()
            
            db.session.commit()
            logger.info(f"Access restriction cleanup complete. {deleted_count} records deleted.")
            return deleted_count
            
    except Exception as e:
        logger.error(f"Error during access restriction cleanup: {str(e)}")
        db.session.rollback()
        return 0


def run_all_tasks():
    """Run all scheduled tasks"""
    logger.info("=" * 60)
    logger.info("Starting all scheduled tasks")
    logger.info("=" * 60)
    
    # Task 1: Update event statuses
    events_updated = update_event_statuses()
    
    # Task 2: Cleanup old tickets (only once per day is enough)
    # Check if we should run this (you can add time check here)
    current_hour = datetime.now().hour
    if current_hour == 2:  # Run cleanup at 2 AM
        tickets_deleted = cleanup_old_tickets()
        restrictions_deleted = cleanup_expired_access_restrictions()
    else:
        logger.info("Skipping cleanup tasks (not scheduled time)")
        tickets_deleted = 0
        restrictions_deleted = 0
    
    logger.info("=" * 60)
    logger.info(f"All tasks completed. Summary:")
    logger.info(f"  - Events deactivated: {events_updated}")
    logger.info(f"  - Tickets deleted: {tickets_deleted}")
    logger.info(f"  - Access restrictions cleaned: {restrictions_deleted}")
    logger.info("=" * 60)


if __name__ == "__main__":
    try:
        run_all_tasks()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error in cronjob: {str(e)}")
        sys.exit(1)

