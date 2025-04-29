#!/usr/bin/env python
"""
Script for scheduled cleanup of expired ticket data.
This can be run as a daily cron job to automatically clean up old data.
"""

from app import app, db
from models import Event, Ticket
from datetime import datetime, timezone
import logging
import sys

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cleanup.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("cleanup")

def perform_cleanup():
    """Clean up old ticket data after events end"""
    logger.info("Starting scheduled cleanup process")
    
    try:
        with app.app_context():
            now = datetime.now(timezone.utc)
            logger.info(f"Current time: {now}")
            
            past_events = Event.query.filter(Event.date < now).all()
            logger.info(f"Found {len(past_events)} past events")
            
            tickets_deleted = 0
            
            for event in past_events:
                logger.info(f"Processing event: {event.id} - {event.title} (Date: {event.date})")
                result = Ticket.query.filter_by(event_id=event.id).delete()
                tickets_deleted += result
                logger.info(f"  - Deleted {result} tickets")
            
            db.session.commit()
            logger.info(f"Cleanup complete. Total tickets deleted: {tickets_deleted}")
            return tickets_deleted
    
    except Exception as e:
        logger.error(f"Error during cleanup: {str(e)}")
        return 0

if __name__ == "__main__":
    tickets_deleted = perform_cleanup()
    print(f"Cleanup complete. {tickets_deleted} tickets deleted.") 