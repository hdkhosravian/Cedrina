"""Event Publisher Infrastructure Service.

This service provides concrete implementation of the domain event publishing interface,
enabling the domain layer to publish events without coupling to infrastructure concerns.
"""

import asyncio
from typing import List, Optional, Set

from src.domain.events.password_reset_events import BaseDomainEvent
from src.common.events import IEventPublisher
from src.infrastructure.services.base_service import BaseInfrastructureService


class InMemoryEventPublisher(IEventPublisher, BaseInfrastructureService):
    """In-memory event publisher for development.
    
    This implementation stores events in memory and can be used for:
    - Development environments
    - Event replay and debugging
    - Event filtering and inspection
    
    In production, this could be replaced with:
    - Redis pub/sub implementation
    - RabbitMQ/Apache Kafka integration
    - Database event store implementation
    """
    
    def __init__(self):
        """Initialize event publisher with in-memory storage."""
        super().__init__(service_name="InMemoryEventPublisher")
        
        self._published_events: List[BaseDomainEvent] = []
        self._event_filters: Set[str] = set()
        self._subscribers: List[callable] = []
    
    @property
    def events(self) -> List[BaseDomainEvent]:
        """Get all published events (compatibility property for tests).
        
        Returns:
            List[BaseDomainEvent]: All published events
        """
        return self._published_events
    
    async def publish(self, event: BaseDomainEvent) -> None:
        """Publish a single domain event.
        
        Args:
            event: Domain event to publish
        """
        operation = "publish_event"
        
        try:
            # Store event for inspection/replay
            self._published_events.append(event)
            
            # Check if event type is filtered
            event_type = type(event).__name__
            if self._event_filters and event_type not in self._event_filters:
                self._log_warning(
                    operation=operation,
                    message="Event filtered out",
                    event_type=event_type,
                    event_id=getattr(event, 'correlation_id', None),
                )
                return
            
            # Notify subscribers asynchronously
            if self._subscribers:
                await self._notify_subscribers(event)
            
            self._log_success(
                operation=operation,
                event_type=event_type,
                user_id=getattr(event, 'user_id', None),
                correlation_id=getattr(event, 'correlation_id', None),
                occurred_at=event.timestamp.isoformat(),
            )
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
            )
            # Don't re-raise to prevent domain operations from failing
            # due to event publishing issues
    
    async def publish_many(self, events: List[BaseDomainEvent]) -> None:
        """Publish multiple domain events.
        
        Args:
            events: List of domain events to publish
        """
        operation = "publish_many_events"
        
        if not events:
            return
        
        try:
            # Publish events concurrently for better performance
            tasks = [self.publish(event) for event in events]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            self._log_success(
                operation=operation,
                event_count=len(events),
                event_types=[type(e).__name__ for e in events],
            )
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
            )
    
    def add_event_filter(self, event_type: str) -> None:
        """Add event type to filter (only filtered types will be published).
        
        Args:
            event_type: Name of event type to filter
        """
        self._event_filters.add(event_type)
        self._log_success(
            operation="add_event_filter",
            event_type=event_type
        )
    
    def remove_event_filter(self, event_type: str) -> None:
        """Remove event type from filter.
        
        Args:
            event_type: Name of event type to remove from filter
        """
        self._event_filters.discard(event_type)
        self._log_success(
            operation="remove_event_filter",
            event_type=event_type
        )
    
    def clear_event_filters(self) -> None:
        """Clear all event filters (publish all events)."""
        self._event_filters.clear()
        self._log_success(operation="clear_event_filters")
    
    def add_subscriber(self, callback: callable) -> None:
        """Add event subscriber callback.
        
        Args:
            callback: Async function to call when events are published
        """
        self._subscribers.append(callback)
        self._log_success(operation="add_subscriber")
    
    def get_published_events(
        self, 
        event_type: Optional[str] = None,
        user_id: Optional[int] = None,
        correlation_id: Optional[str] = None,
    ) -> List[BaseDomainEvent]:
        """Get published events with optional filtering.
        
        Args:
            event_type: Filter by event type name
            user_id: Filter by user ID
            correlation_id: Filter by correlation ID
            
        Returns:
            List[BaseDomainEvent]: Filtered list of published events
        """
        events = self._published_events
        
        if event_type:
            events = [e for e in events if type(e).__name__ == event_type]
        
        if user_id is not None:
            events = [e for e in events if getattr(e, 'user_id', None) == user_id]
        
        if correlation_id:
            events = [e for e in events if getattr(e, 'correlation_id', None) == correlation_id]
        
        return events
    
    def clear_published_events(self) -> None:
        """Clear all stored published events."""
        event_count = len(self._published_events)
        self._published_events.clear()
        self._log_success(
            operation="clear_published_events",
            event_count=event_count
        )
    
    def clear_events(self) -> None:
        """Clear all stored published events (alias for compatibility)."""
        self.clear_published_events()
    
    def get_event_count(self) -> int:
        """Get total number of published events.
        
        Returns:
            int: Number of events published
        """
        return len(self._published_events)
    
    def get_events_by_type(self, event_type: type) -> List[BaseDomainEvent]:
        """Get published events by type.
        
        Args:
            event_type: Type of events to retrieve
            
        Returns:
            List[BaseDomainEvent]: List of events of specified type
        """
        return [e for e in self._published_events if isinstance(e, event_type)]
    
    def get_events_by_user(self, user_id: int) -> List[BaseDomainEvent]:
        """Get published events for a specific user.
        
        Args:
            user_id: User ID to filter by
            
        Returns:
            List[BaseDomainEvent]: List of events for the user
        """
        return [e for e in self._published_events if getattr(e, 'user_id', None) == user_id]
    
    async def _notify_subscribers(self, event: BaseDomainEvent) -> None:
        """Notify all subscribers of published event.
        
        Args:
            event: Event to notify subscribers about
        """
        operation = "notify_subscribers"
        
        try:
            # Notify subscribers concurrently
            tasks = []
            for subscriber in self._subscribers:
                if asyncio.iscoroutinefunction(subscriber):
                    tasks.append(subscriber(event))
                else:
                    # Handle sync callbacks by running in thread pool
                    tasks.append(asyncio.get_event_loop().run_in_executor(
                        None, subscriber, event
                    ))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
            )


class ProductionEventPublisher(IEventPublisher, BaseInfrastructureService):
    """Production event publisher using Redis pub/sub.
    
    This implementation would use Redis for production deployments,
    providing scalable event publishing across multiple service instances.
    """
    
    def __init__(self, redis_client):
        """Initialize with Redis client.
        
        Args:
            redis_client: Redis async client for pub/sub
        """
        super().__init__(service_name="ProductionEventPublisher")
        self._redis = redis_client
    
    async def publish(self, event: BaseDomainEvent) -> None:
        """Publish event via Redis pub/sub.
        
        Args:
            event: Domain event to publish
        """
        operation = "publish_event"
        
        try:
            # Implementation would serialize event and publish to Redis
            # This is a placeholder for future production implementation
            self._log_success(
                operation=operation,
                event_type=type(event).__name__,
                user_id=getattr(event, 'user_id', None),
            )
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation,
            )
    
    async def publish_many(self, events: List[BaseDomainEvent]) -> None:
        """Publish multiple events via Redis pipeline.
        
        Args:
            events: List of domain events to publish
        """
        # Implementation would use Redis pipeline for batch publishing
        for event in events:
            await self.publish(event) 