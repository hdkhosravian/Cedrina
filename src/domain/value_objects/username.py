"""Secure Username value object for domain modeling with enhanced security validation.

This value object encapsulates username business rules and validation,
providing a type-safe representation of usernames in the domain with
comprehensive security controls.

SECURITY NOTE: This class provides enterprise-grade security validation
including injection attack detection, Unicode normalization, and comprehensive
security risk assessment.
"""

from src.domain.validation.secure_username import SecureUsername

# Re-export SecureUsername as Username for backward compatibility
Username = SecureUsername 