"""
Waiting List Service for e-kiosque
Handles all waiting list operations including adding users, promoting them, and notifications
"""

from models import WaitingList, Event, Ticket
from extensions import db
from sqlalchemy import func
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class WaitingListService:
    """Service class for managing waiting lists"""
    
    @staticmethod
    def can_join_waiting_list(event_id, email=None, username=None, hashed_ip=None):
        """
        Check if a user can join the waiting list
        Returns: (can_join: bool, reason: str, position: int or None)
        """
        event = Event.query.get(event_id)
        if not event:
            return False, "Event not found", None
        
        # Check if waiting list is enabled
        if not event.enable_waiting_list:
            return False, "Waiting list is not enabled for this event", None
        
        # Check if tickets are still available
        if event.available_tickets > 0:
            return False, "Tickets are still available", None
        
        # Check if already in waiting list by email
        if email:
            existing = WaitingList.query.filter_by(
                event_id=event_id,
                email=email,
                converted_to_ticket=False
            ).first()
            if existing:
                return False, f"Already in waiting list at position {existing.position}", existing.position
        
        # Check if already in waiting list by username
        if username:
            existing = WaitingList.query.filter_by(
                event_id=event_id,
                username=username,
                converted_to_ticket=False
            ).first()
            if existing:
                return False, f"Already in waiting list at position {existing.position}", existing.position
        
        # Check if already has a ticket
        if username:
            ticket = Ticket.query.filter_by(
                event_id=event_id,
                username=username
            ).first()
            if ticket:
                return False, "Already has a ticket for this event", None
        
        # Check waiting list capacity
        current_count = WaitingList.query.filter_by(
            event_id=event_id,
            converted_to_ticket=False
        ).count()
        
        if current_count >= event.max_waiting_list:
            return False, "Waiting list is full", None
        
        return True, "Can join", None
    
    @staticmethod
    def add_to_waiting_list(event_id, name, email, username, phone, hashed_ip, hashed_session, hashed_cookie):
        """
        Add a user to the waiting list
        Returns: (success: bool, waiting_entry or error_message, position)
        """
        try:
            # Double-check eligibility
            can_join, reason, existing_position = WaitingListService.can_join_waiting_list(
                event_id, email, username, hashed_ip
            )
            
            if not can_join:
                return False, reason, existing_position
            
            # Get next position
            max_position = db.session.query(func.max(WaitingList.position)).filter_by(
                event_id=event_id,
                converted_to_ticket=False
            ).scalar() or 0
            
            next_position = max_position + 1
            
            # Create waiting list entry
            waiting_entry = WaitingList(
                event_id=event_id,
                name=name,
                email=email,
                username=username,
                phone=phone,
                hashed_ip=hashed_ip,
                hashed_session=hashed_session,
                hashed_cookie=hashed_cookie,
                position=next_position,
                joined_at=datetime.utcnow()
            )
            
            db.session.add(waiting_entry)
            db.session.commit()
            
            logger.info(f"Added {email} to waiting list for event {event_id} at position {next_position}")
            
            return True, waiting_entry, next_position
            
        except Exception as e:
            logger.error(f"Error adding to waiting list: {str(e)}")
            db.session.rollback()
            return False, str(e), None
    
    @staticmethod
    def get_waiting_list_position(event_id, email=None, username=None):
        """Get the position of a user in the waiting list"""
        query = WaitingList.query.filter_by(
            event_id=event_id,
            converted_to_ticket=False
        )
        
        if email:
            entry = query.filter_by(email=email).first()
        elif username:
            entry = query.filter_by(username=username).first()
        else:
            return None
        
        return entry.position if entry else None
    
    @staticmethod
    def get_waiting_list_count(event_id):
        """Get total count of people in waiting list"""
        return WaitingList.query.filter_by(
            event_id=event_id,
            converted_to_ticket=False
        ).count()
    
    @staticmethod
    def remove_from_waiting_list(waiting_id):
        """Remove a user from the waiting list and reorder positions"""
        try:
            waiting_entry = WaitingList.query.get(waiting_id)
            if not waiting_entry:
                return False, "Entry not found"
            
            event_id = waiting_entry.event_id
            removed_position = waiting_entry.position
            
            # Delete the entry
            db.session.delete(waiting_entry)
            
            # Reorder positions for remaining entries
            remaining_entries = WaitingList.query.filter(
                WaitingList.event_id == event_id,
                WaitingList.position > removed_position,
                WaitingList.converted_to_ticket == False
            ).order_by(WaitingList.position).all()
            
            for entry in remaining_entries:
                entry.position -= 1
            
            db.session.commit()
            
            logger.info(f"Removed waiting list entry {waiting_id} and reordered positions")
            
            return True, "Removed successfully"
            
        except Exception as e:
            logger.error(f"Error removing from waiting list: {str(e)}")
            db.session.rollback()
            return False, str(e)
    
    @staticmethod
    def promote_next_person(event_id):
        """
        When a ticket becomes available, promote the next person in line
        Returns: (success: bool, waiting_entry or error_message)
        """
        try:
            event = Event.query.get(event_id)
            if not event:
                return False, "Event not found"
            
            # Check if there are available tickets
            if event.available_tickets <= 0:
                return False, "No available tickets"
            
            # Get the first person in the waiting list who hasn't been notified yet
            next_person = WaitingList.query.filter_by(
                event_id=event_id,
                notified=False,
                converted_to_ticket=False
            ).order_by(WaitingList.position).first()
            
            if not next_person:
                return False, "No one in waiting list"
            
            # Mark as notified
            next_person.notified = True
            next_person.notification_sent_at = datetime.utcnow()
            db.session.commit()
            
            logger.info(f"Promoted {next_person.email} from waiting list for event {event_id}")
            
            return True, next_person
            
        except Exception as e:
            logger.error(f"Error promoting from waiting list: {str(e)}")
            db.session.rollback()
            return False, str(e)
    
    @staticmethod
    def convert_to_ticket(waiting_id, ticket_code, qr_base64=None):
        """
        Convert a waiting list entry to an actual ticket
        This is called when the user confirms their reservation
        """
        try:
            waiting_entry = WaitingList.query.get(waiting_id)
            if not waiting_entry:
                return False, "Waiting list entry not found", None
            
            event = waiting_entry.event
            
            # Check if already converted
            if waiting_entry.converted_to_ticket:
                return False, "Already converted to ticket", None
            
            # Check if tickets are available
            if event.available_tickets <= 0:
                return False, "No tickets available", None
            
            # Create the ticket
            ticket = Ticket(
                event_id=event.id,
                ticket_code=ticket_code,
                name=waiting_entry.name,
                email=waiting_entry.email,
                username=waiting_entry.username,
                phone=waiting_entry.phone,
                hashed_ip=waiting_entry.hashed_ip,
                hashed_session=waiting_entry.hashed_session,
                hashed_cookie=waiting_entry.hashed_cookie,
                expiry_time=event.date
            )
            
            db.session.add(ticket)
            
            # Update event capacity
            event.available_tickets -= 1
            
            # Mark waiting list entry as converted
            waiting_entry.converted_to_ticket = True
            waiting_entry.converted_at = datetime.utcnow()
            
            db.session.commit()
            
            logger.info(f"Converted waiting list entry {waiting_id} to ticket {ticket.id}")
            
            return True, "Converted successfully", ticket
            
        except Exception as e:
            logger.error(f"Error converting to ticket: {str(e)}")
            db.session.rollback()
            return False, str(e), None
    
    @staticmethod
    def get_event_waiting_list(event_id, include_converted=False):
        """Get all people in the waiting list for an event"""
        query = WaitingList.query.filter_by(event_id=event_id)
        
        if not include_converted:
            query = query.filter_by(converted_to_ticket=False)
        
        return query.order_by(WaitingList.position).all()

