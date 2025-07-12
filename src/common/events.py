"""Common event publishing interface for domain events.

This module provides the IEventPublisher interface that can be used across
all layers without creating circular dependencies.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Protocol


class BaseDomainEvent(Protocol):
    """Protocol for domain events to avoid circular imports."""
    pass


class IEventPublisher(ABC):
    """Interface for domain event publishing and distribution.
    
    This service provides a mechanism for publishing events that occur within
    the domain (e.g., `UserRegistered`, `PasswordChanged`). It decouples the part
    of the domain that raises the event from the listeners that handle it,
    enabling a clean, event-driven architecture.
    
    DDD Principles:
    - Single Responsibility: Handles only event publishing operations
    - Domain Events: Publishes domain events for loose coupling
    - Ubiquitous Language: Method names reflect event concepts
    - Dependency Inversion: Abstracts event infrastructure from domain
    """

    @abstractmethod
    async def publish(self, event: BaseDomainEvent) -> None:
        """Publishes a single domain event.

        Args:
            event: The `BaseDomainEvent` to be published to all listeners.
        """
        raise NotImplementedError

    @abstractmethod
    async def publish_many(self, events: List[BaseDomainEvent]) -> None:
        """Publishes a list of domain events.

        This can be used to publish multiple events that occur as part of a
        single transaction or use case.

        Args:
            events: A list of `BaseDomainEvent` objects to be published.
        """
        raise NotImplementedError 