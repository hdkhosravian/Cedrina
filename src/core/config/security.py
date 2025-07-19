"""Security configuration settings for the Cedrina application.

This module defines security-related configuration parameters including
timing patterns for error standardization, rate limiting, and other
security features. Optimized for powerful servers and multi-server deployments.

EASY CONFIGURATION:
All timing values can be changed via environment variables - no code changes needed!
See docs/SECURITY_TIMING_CONFIG.md for complete configuration guide.

Quick examples:
  SECURITY_TIMING_SLOW_MIN=0.4 SECURITY_TIMING_SLOW_MAX=0.8  # Default for powerful servers
  SECURITY_TIMING_SLOW_MIN=0.5 SECURITY_TIMING_SLOW_MAX=1.0  # Extra security (slower)
  SECURITY_TIMING_SLOW_MIN=0.2 SECURITY_TIMING_SLOW_MAX=0.4  # Less powerful servers
  SECURITY_TIMING_SLOW_MIN=0.01 SECURITY_TIMING_SLOW_MAX=0.05  # Very very very very super fast
"""

import os
from typing import Dict, Tuple

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SecuritySettings(BaseSettings):
    """Security configuration settings with optimized defaults for powerful servers.
    
    Security considerations:
    - Timing patterns are designed to prevent timing attacks on powerful hardware
    - All timing values are configurable via environment variables
    - Server performance detection for automatic timing adjustment
    - Multi-server consistency through deterministic algorithms
    
    Performance considerations:
    - Timing ranges scale with server capabilities
    - CPU-intensive operations are optimized for modern hardware
    - Configurable operation counts for different server types
    """
    
    model_config = SettingsConfigDict(
        env_prefix="SECURITY_",
        case_sensitive=True
    )
    
    # Timing pattern configuration (in seconds)
    # Optimized for powerful servers - increased ranges for better security
    TIMING_FAST_MIN: float = Field(
        default=0.02,  # 20ms minimum for fast operations
        ge=0.0001,  # Allow ultra-fast values (0.1ms minimum)
        le=1.0,
        description="Minimum time for fast timing pattern (validation errors)"
    )
    TIMING_FAST_MAX: float = Field(
        default=0.05,  # 50ms maximum for fast operations
        ge=0.0001,  # Allow ultra-fast values (0.1ms minimum)
        le=1.0,
        description="Maximum time for fast timing pattern (validation errors)"
    )
    
    TIMING_MEDIUM_MIN: float = Field(
        default=0.08,  # 80ms minimum for medium operations
        ge=0.0001,  # Allow ultra-fast values (0.1ms minimum)
        le=2.0,
        description="Minimum time for medium timing pattern (authorization errors)"
    )
    TIMING_MEDIUM_MAX: float = Field(
        default=0.15,  # 150ms maximum for medium operations
        ge=0.0001,  # Allow ultra-fast values (0.1ms minimum)
        le=2.0,
        description="Maximum time for medium timing pattern (authorization errors)"
    )
    
    TIMING_SLOW_MIN: float = Field(
        default=0.4,  # 400ms minimum for slow operations (powerful server optimized)
        ge=0.0001,  # Allow ultra-fast values (0.1ms minimum)
        le=5.0,
        description="Minimum time for slow timing pattern (authentication failures)"
    )
    TIMING_SLOW_MAX: float = Field(
        default=0.8,  # 800ms maximum for slow operations (powerful server optimized)
        ge=0.0001,  # Allow ultra-fast values (0.1ms minimum)
        le=5.0,
        description="Maximum time for slow timing pattern (authentication failures)"
    )
    
    TIMING_VARIABLE_MIN: float = Field(
        default=0.4,  # 400ms minimum for variable operations
        ge=0.0001,  # Allow ultra-fast values (0.1ms minimum)
        le=5.0,
        description="Minimum time for variable timing pattern (deterministic but variable)"
    )
    TIMING_VARIABLE_MAX: float = Field(
        default=0.8,  # 800ms maximum for variable operations
        ge=0.0001,  # Allow ultra-fast values (0.1ms minimum)
        le=5.0,
        description="Maximum time for variable timing pattern (deterministic but variable)"
    )
    
    # CPU operation scaling factors for different server types
    # These determine how many cryptographic operations to perform
    CPU_OPERATIONS_PER_MS_SLOW: int = Field(
        default=20000,  # 20k operations per ms for slow patterns (powerful server)
        ge=1000,
        le=100000,
        description="CPU operations per millisecond for slow timing patterns"
    )
    CPU_OPERATIONS_PER_MS_MEDIUM: int = Field(
        default=8000,  # 8k operations per ms for medium patterns
        ge=1000,
        le=50000,
        description="CPU operations per millisecond for medium timing patterns"
    )
    CPU_OPERATIONS_PER_MS_FAST: int = Field(
        default=2000,  # 2k operations per ms for fast patterns
        ge=100,
        le=10000,
        description="CPU operations per millisecond for fast timing patterns"
    )
    
    # Server performance detection
    AUTO_DETECT_SERVER_PERFORMANCE: bool = Field(
        default=True,
        description="Automatically detect server performance and adjust timing"
    )
    SERVER_PERFORMANCE_MULTIPLIER: float = Field(
        default=1.0,
        ge=0.1,
        le=10.0,
        description="Manual multiplier for server performance (1.0 = standard, 2.0 = 2x faster)"
    )
    
    # Security algorithm configuration
    USE_ADVANCED_CRYPTO_OPERATIONS: bool = Field(
        default=True,
        description="Use advanced cryptographic operations for better security"
    )
    ENABLE_DETERMINISTIC_TIMING: bool = Field(
        default=True,
        description="Enable deterministic timing based on correlation IDs"
    )
    
    # Multi-server consistency settings
    SERVER_INSTANCE_ID: str = Field(
        default="",
        description="Unique identifier for this server instance (for timing consistency)"
    )
    TIMING_CONSISTENCY_ENABLED: bool = Field(
        default=True,
        description="Ensure timing consistency across multiple server instances"
    )
    
    # Audit logging security
    AUDIT_INTEGRITY_KEY: str = Field(
        default="",
        description="Key for HMAC-based audit log integrity protection (required for production)"
    )
    
    @field_validator('TIMING_FAST_MAX')
    @classmethod
    def validate_fast_timing(cls, v, info):
        """Validate that fast timing max is greater than min."""
        if 'TIMING_FAST_MIN' in info.data and v <= info.data['TIMING_FAST_MIN']:
            raise ValueError("TIMING_FAST_MAX must be greater than TIMING_FAST_MIN")
        return v
    
    @field_validator('TIMING_MEDIUM_MAX')
    @classmethod
    def validate_medium_timing(cls, v, info):
        """Validate that medium timing max is greater than min."""
        if 'TIMING_MEDIUM_MIN' in info.data and v <= info.data['TIMING_MEDIUM_MIN']:
            raise ValueError("TIMING_MEDIUM_MAX must be greater than TIMING_MEDIUM_MIN")
        return v
    
    @field_validator('TIMING_SLOW_MAX')
    @classmethod
    def validate_slow_timing(cls, v, info):
        """Validate that slow timing max is greater than min."""
        if 'TIMING_SLOW_MIN' in info.data and v <= info.data['TIMING_SLOW_MIN']:
            raise ValueError("TIMING_SLOW_MAX must be greater than TIMING_SLOW_MIN")
        return v
    
    @field_validator('TIMING_VARIABLE_MAX')
    @classmethod
    def validate_variable_timing(cls, v, info):
        """Validate that variable timing max is greater than min."""
        if 'TIMING_VARIABLE_MIN' in info.data and v <= info.data['TIMING_VARIABLE_MIN']:
            raise ValueError("TIMING_VARIABLE_MAX must be greater than TIMING_VARIABLE_MIN")
        return v
    
    def get_timing_ranges(self) -> Dict[str, Tuple[float, float]]:
        """Get timing ranges with performance adjustment applied.
        
        Returns:
            Dict mapping timing pattern names to (min, max) tuples in seconds
        """
        # Apply server performance multiplier
        multiplier = self._get_performance_multiplier()
        
        ranges = {
            "FAST": (
                self.TIMING_FAST_MIN * multiplier,
                self.TIMING_FAST_MAX * multiplier
            ),
            "MEDIUM": (
                self.TIMING_MEDIUM_MIN * multiplier,
                self.TIMING_MEDIUM_MAX * multiplier
            ),
            "SLOW": (
                self.TIMING_SLOW_MIN * multiplier,
                self.TIMING_SLOW_MAX * multiplier
            ),
            "VARIABLE": (
                self.TIMING_VARIABLE_MIN * multiplier,
                self.TIMING_VARIABLE_MAX * multiplier
            )
        }
        
        return ranges
    
    def get_cpu_operations_per_ms(self, pattern: str) -> int:
        """Get CPU operations per millisecond for a timing pattern.
        
        Args:
            pattern: Timing pattern name (FAST, MEDIUM, SLOW)
            
        Returns:
            int: Number of CPU operations per millisecond
        """
        operations_map = {
            "FAST": self.CPU_OPERATIONS_PER_MS_FAST,
            "MEDIUM": self.CPU_OPERATIONS_PER_MS_MEDIUM,
            "SLOW": self.CPU_OPERATIONS_PER_MS_SLOW,
            "VARIABLE": self.CPU_OPERATIONS_PER_MS_SLOW  # Variable uses slow pattern operations
        }
        
        return operations_map.get(pattern.upper(), self.CPU_OPERATIONS_PER_MS_MEDIUM)
    
    def _get_performance_multiplier(self) -> float:
        """Calculate performance multiplier based on server capabilities.
        
        Returns:
            float: Performance multiplier (1.0 = standard, <1.0 = slower, >1.0 = faster)
        """
        if not self.AUTO_DETECT_SERVER_PERFORMANCE:
            return self.SERVER_PERFORMANCE_MULTIPLIER
        
        # Auto-detect based on CPU cores and available memory
        try:
            import multiprocessing
            import psutil
            
            cpu_count = multiprocessing.cpu_count()
            memory_gb = psutil.virtual_memory().total / (1024**3)
            
            # Calculate performance score
            # More cores and memory = higher performance = lower timing multiplier
            performance_score = (cpu_count * 0.3) + (memory_gb * 0.1)
            
            # Convert to multiplier (higher score = lower multiplier for faster timing)
            if performance_score > 8:
                multiplier = 0.5  # Very powerful server
            elif performance_score > 4:
                multiplier = 0.7  # Powerful server
            elif performance_score > 2:
                multiplier = 0.9  # Standard server
            else:
                multiplier = 1.2  # Less powerful server
            
            # Apply manual override if set
            if self.SERVER_PERFORMANCE_MULTIPLIER != 1.0:
                multiplier *= self.SERVER_PERFORMANCE_MULTIPLIER
            
            return max(0.1, min(5.0, multiplier))  # Clamp between 0.1 and 5.0
            
        except (ImportError, AttributeError):
            # Fallback to manual multiplier if psutil not available
            return self.SERVER_PERFORMANCE_MULTIPLIER
    
    def get_server_instance_id(self) -> str:
        """Get unique server instance ID for timing consistency.
        
        Returns:
            str: Unique identifier for this server instance
        """
        if self.SERVER_INSTANCE_ID:
            return self.SERVER_INSTANCE_ID
        
        # Generate from hostname and process ID
        import socket
        import os
        
        hostname = socket.gethostname()
        pid = os.getpid()
        
        return f"{hostname}-{pid}" 