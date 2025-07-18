"""Tests for the RateLimit value objects.

This module contains comprehensive tests for the RateLimitWindow and RateLimitState value objects,
ensuring they properly handle rate limiting logic and edge cases in production scenarios.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

import pytest
from src.domain.value_objects.rate_limit import RateLimitWindow, RateLimitState


class TestRateLimitWindow:
    """Test cases for RateLimitWindow value object."""

    def test_valid_rate_limit_window_creation(self):
        """Test creating a valid rate limit window."""
        # Arrange
        window_duration = timedelta(minutes=5)
        max_attempts = 3
        user_id = 123
        last_attempt_at = datetime.now(timezone.utc)
        
        # Act
        rate_limit_window = RateLimitWindow(
            window_duration=window_duration,
            max_attempts=max_attempts,
            user_id=user_id,
            last_attempt_at=last_attempt_at
        )
        
        # Assert
        assert rate_limit_window.window_duration == window_duration
        assert rate_limit_window.max_attempts == max_attempts
        assert rate_limit_window.user_id == user_id
        assert rate_limit_window.last_attempt_at == last_attempt_at

    def test_rate_limit_window_without_last_attempt(self):
        """Test creating rate limit window without last attempt."""
        # Arrange
        window_duration = timedelta(minutes=10)
        max_attempts = 5
        user_id = 456
        
        # Act
        rate_limit_window = RateLimitWindow(
            window_duration=window_duration,
            max_attempts=max_attempts,
            user_id=user_id
        )
        
        # Assert
        assert rate_limit_window.window_duration == window_duration
        assert rate_limit_window.max_attempts == max_attempts
        assert rate_limit_window.user_id == user_id
        assert rate_limit_window.last_attempt_at is None

    def test_rate_limit_window_invalid_duration(self):
        """Test that negative window duration raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="Rate limit window duration must be positive"):
            RateLimitWindow(
                window_duration=timedelta(seconds=-1),
                max_attempts=1,
                user_id=123
            )

    def test_rate_limit_window_zero_duration(self):
        """Test that zero window duration raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="Rate limit window duration must be positive"):
            RateLimitWindow(
                window_duration=timedelta(seconds=0),
                max_attempts=1,
                user_id=123
            )

    def test_rate_limit_window_invalid_max_attempts(self):
        """Test that invalid max attempts raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="Max attempts must be positive"):
            RateLimitWindow(
                window_duration=timedelta(minutes=5),
                max_attempts=0,
                user_id=123
            )

    def test_rate_limit_window_negative_max_attempts(self):
        """Test that negative max attempts raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="Max attempts must be positive"):
            RateLimitWindow(
                window_duration=timedelta(minutes=5),
                max_attempts=-1,
                user_id=123
            )

    def test_rate_limit_window_invalid_user_id(self):
        """Test that invalid user ID raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="User ID must be positive"):
            RateLimitWindow(
                window_duration=timedelta(minutes=5),
                max_attempts=1,
                user_id=0
            )

    def test_rate_limit_window_negative_user_id(self):
        """Test that negative user ID raises ValueError."""
        # Act & Assert
        with pytest.raises(ValueError, match="User ID must be positive"):
            RateLimitWindow(
                window_duration=timedelta(minutes=5),
                max_attempts=1,
                user_id=-1
            )

    def test_rate_limit_window_timezone_naive_timestamp(self):
        """Test that timezone-naive timestamp raises ValueError."""
        # Arrange
        naive_timestamp = datetime.now()  # No timezone info
        
        # Act & Assert
        with pytest.raises(ValueError, match="Last attempt timestamp must be timezone-aware"):
            RateLimitWindow(
                window_duration=timedelta(minutes=5),
                max_attempts=1,
                user_id=123,
                last_attempt_at=naive_timestamp
            )

    def test_rate_limit_window_create_default(self):
        """Test create_default class method."""
        # Arrange
        user_id = 789
        
        # Act
        rate_limit_window = RateLimitWindow.create_default(user_id)
        
        # Assert
        assert rate_limit_window.window_duration == timedelta(minutes=RateLimitWindow.DEFAULT_WINDOW_MINUTES)
        assert rate_limit_window.max_attempts == RateLimitWindow.DEFAULT_MAX_ATTEMPTS
        assert rate_limit_window.user_id == user_id
        assert rate_limit_window.last_attempt_at is None

    def test_rate_limit_window_create_custom(self):
        """Test create_custom class method."""
        # Arrange
        user_id = 456
        window_minutes = 15
        max_attempts = 10
        
        # Act
        rate_limit_window = RateLimitWindow.create_custom(
            user_id=user_id,
            window_minutes=window_minutes,
            max_attempts=max_attempts
        )
        
        # Assert
        assert rate_limit_window.window_duration == timedelta(minutes=window_minutes)
        assert rate_limit_window.max_attempts == max_attempts
        assert rate_limit_window.user_id == user_id
        assert rate_limit_window.last_attempt_at is None

    def test_rate_limit_window_is_limit_exceeded_no_previous_attempts(self):
        """Test is_limit_exceeded when no previous attempts exist."""
        # Arrange
        rate_limit_window = RateLimitWindow.create_default(user_id=123)
        
        # Act
        is_exceeded = rate_limit_window.is_limit_exceeded()
        
        # Assert
        assert is_exceeded is False

    def test_rate_limit_window_is_limit_exceeded_within_window(self):
        """Test is_limit_exceeded when within window."""
        # Arrange
        current_time = datetime.now(timezone.utc)
        last_attempt = current_time - timedelta(minutes=2)  # Within 5-minute window
        
        rate_limit_window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=last_attempt
        )
        
        # Act
        is_exceeded = rate_limit_window.is_limit_exceeded(current_time)
        
        # Assert
        assert is_exceeded is True

    def test_rate_limit_window_is_limit_exceeded_outside_window(self):
        """Test is_limit_exceeded when outside window."""
        # Arrange
        current_time = datetime.now(timezone.utc)
        last_attempt = current_time - timedelta(minutes=6)  # Outside 5-minute window
        
        rate_limit_window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=last_attempt
        )
        
        # Act
        is_exceeded = rate_limit_window.is_limit_exceeded(current_time)
        
        # Assert
        assert is_exceeded is False

    def test_rate_limit_window_record_attempt(self):
        """Test record_attempt method."""
        # Arrange
        original_window = RateLimitWindow.create_default(user_id=123)
        attempt_time = datetime.now(timezone.utc)
        
        # Act
        updated_window = original_window.record_attempt(attempt_time)
        
        # Assert
        assert updated_window.window_duration == original_window.window_duration
        assert updated_window.max_attempts == original_window.max_attempts
        assert updated_window.user_id == original_window.user_id
        assert updated_window.last_attempt_at == attempt_time
        assert updated_window is not original_window  # Should be a new instance

    def test_rate_limit_window_record_attempt_default_time(self):
        """Test record_attempt method with default time."""
        # Arrange
        original_window = RateLimitWindow.create_default(user_id=123)
        
        # Act
        updated_window = original_window.record_attempt()
        
        # Assert
        assert updated_window.window_duration == original_window.window_duration
        assert updated_window.max_attempts == original_window.max_attempts
        assert updated_window.user_id == original_window.user_id
        assert updated_window.last_attempt_at is not None
        assert updated_window.last_attempt_at.tzinfo == timezone.utc

    def test_rate_limit_window_time_until_reset_not_limited(self):
        """Test time_until_reset when not rate limited."""
        # Arrange
        current_time = datetime.now(timezone.utc)
        last_attempt = current_time - timedelta(minutes=6)  # Outside window
        
        rate_limit_window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=last_attempt
        )
        
        # Act
        time_until_reset = rate_limit_window.time_until_reset(current_time)
        
        # Assert
        assert time_until_reset is None

    def test_rate_limit_window_time_until_reset_limited(self):
        """Test time_until_reset when rate limited."""
        # Arrange
        current_time = datetime.now(timezone.utc)
        last_attempt = current_time - timedelta(minutes=2)  # Within window
        
        rate_limit_window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=last_attempt
        )
        
        # Act
        time_until_reset = rate_limit_window.time_until_reset(current_time)
        
        # Assert
        assert time_until_reset is not None
        assert time_until_reset.total_seconds() > 0
        assert time_until_reset.total_seconds() <= 180  # Should be around 3 minutes

    def test_rate_limit_window_immutability(self):
        """Test that rate limit window is immutable."""
        # Arrange
        rate_limit_window = RateLimitWindow.create_default(user_id=123)
        
        # Act & Assert
        with pytest.raises(AttributeError):
            rate_limit_window.user_id = 456  # type: ignore

    def test_rate_limit_window_equality(self):
        """Test rate limit window equality."""
        # Arrange
        timestamp = datetime.now(timezone.utc)
        window1 = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=timestamp
        )
        window2 = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=timestamp
        )
        window3 = RateLimitWindow(
            window_duration=timedelta(minutes=10),
            max_attempts=1,
            user_id=123,
            last_attempt_at=timestamp
        )
        
        # Act & Assert
        assert window1 == window2
        assert window1 != window3
        assert window1 != "invalid"  # Different type

    def test_rate_limit_window_hash(self):
        """Test rate limit window hash."""
        # Arrange
        timestamp = datetime.now(timezone.utc)
        window1 = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=timestamp
        )
        window2 = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=timestamp
        )
        window3 = RateLimitWindow(
            window_duration=timedelta(minutes=10),
            max_attempts=1,
            user_id=123,
            last_attempt_at=timestamp
        )
        
        # Act & Assert
        assert hash(window1) == hash(window2)
        assert hash(window1) != hash(window3)

    def test_rate_limit_window_production_scenario_high_volume(self):
        """Test rate limit window creation under high-volume scenario simulation."""
        # Act & Assert - Simulate high-volume processing
        windows = []
        for i in range(1, 51):  # Simulate 50 rate limit windows (starting from 1)
            window = RateLimitWindow.create_default(user_id=i)
            windows.append(window)
            assert window.user_id == i
            assert window.window_duration == timedelta(minutes=RateLimitWindow.DEFAULT_WINDOW_MINUTES)
            assert window.max_attempts == RateLimitWindow.DEFAULT_MAX_ATTEMPTS
        
        # All windows should be valid
        for window in windows:
            assert isinstance(window, RateLimitWindow)
            assert window.user_id > 0
            assert window.max_attempts > 0
            assert window.window_duration.total_seconds() > 0

    def test_rate_limit_window_production_scenario_time_precision(self):
        """Test rate limit window with precise time handling."""
        # Arrange
        base_time = datetime.now(timezone.utc)
        window = RateLimitWindow.create_default(user_id=123)
        
        # Act
        updated_window = window.record_attempt(base_time)
        
        # Assert
        assert updated_window.last_attempt_at == base_time
        assert updated_window.is_limit_exceeded(base_time) is True
        assert updated_window.is_limit_exceeded(base_time + timedelta(minutes=6)) is False


class TestRateLimitState:
    """Test cases for RateLimitState value object."""

    def test_rate_limit_state_initialization(self):
        """Test rate limit state initialization."""
        # Act
        rate_limit_state = RateLimitState()
        
        # Assert
        assert rate_limit_state._windows == {}

    def test_rate_limit_state_get_window_nonexistent(self):
        """Test get_window for nonexistent user."""
        # Arrange
        rate_limit_state = RateLimitState()
        
        # Act
        window = rate_limit_state.get_window(user_id=123)
        
        # Assert
        assert window is None

    def test_rate_limit_state_set_and_get_window(self):
        """Test set_window and get_window."""
        # Arrange
        rate_limit_state = RateLimitState()
        window = RateLimitWindow.create_default(user_id=123)
        
        # Act
        rate_limit_state.set_window(window)
        retrieved_window = rate_limit_state.get_window(user_id=123)
        
        # Assert
        assert retrieved_window == window

    def test_rate_limit_state_is_user_limited_no_window(self):
        """Test is_user_limited when no window exists."""
        # Arrange
        rate_limit_state = RateLimitState()
        
        # Act
        is_limited = rate_limit_state.is_user_limited(user_id=123)
        
        # Assert
        assert is_limited is False

    def test_rate_limit_state_is_user_limited_not_limited(self):
        """Test is_user_limited when user is not limited."""
        # Arrange
        rate_limit_state = RateLimitState()
        current_time = datetime.now(timezone.utc)
        last_attempt = current_time - timedelta(minutes=6)  # Outside window
        
        window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=last_attempt
        )
        rate_limit_state.set_window(window)
        
        # Act
        is_limited = rate_limit_state.is_user_limited(user_id=123, current_time=current_time)
        
        # Assert
        assert is_limited is False

    def test_rate_limit_state_is_user_limited_limited(self):
        """Test is_user_limited when user is limited."""
        # Arrange
        rate_limit_state = RateLimitState()
        current_time = datetime.now(timezone.utc)
        last_attempt = current_time - timedelta(minutes=2)  # Within window
        
        window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=last_attempt
        )
        rate_limit_state.set_window(window)
        
        # Act
        is_limited = rate_limit_state.is_user_limited(user_id=123, current_time=current_time)
        
        # Assert
        assert is_limited is True

    def test_rate_limit_state_record_attempt_new_user(self):
        """Test record_attempt for new user."""
        # Arrange
        rate_limit_state = RateLimitState()
        attempt_time = datetime.now(timezone.utc)
        
        # Act
        rate_limit_state.record_attempt(user_id=123, attempt_time=attempt_time)
        
        # Assert
        window = rate_limit_state.get_window(user_id=123)
        assert window is not None
        assert window.user_id == 123
        assert window.last_attempt_at == attempt_time
        assert window.window_duration == timedelta(minutes=RateLimitWindow.DEFAULT_WINDOW_MINUTES)
        assert window.max_attempts == RateLimitWindow.DEFAULT_MAX_ATTEMPTS

    def test_rate_limit_state_record_attempt_existing_user(self):
        """Test record_attempt for existing user."""
        # Arrange
        rate_limit_state = RateLimitState()
        original_time = datetime.now(timezone.utc)
        new_time = original_time + timedelta(minutes=1)
        
        # Create initial window
        original_window = RateLimitWindow.create_default(user_id=123)
        original_window = original_window.record_attempt(original_time)
        rate_limit_state.set_window(original_window)
        
        # Act
        rate_limit_state.record_attempt(user_id=123, attempt_time=new_time)
        
        # Assert
        updated_window = rate_limit_state.get_window(user_id=123)
        assert updated_window is not None
        assert updated_window.last_attempt_at == new_time
        assert updated_window.user_id == 123

    def test_rate_limit_state_cleanup_expired_windows(self):
        """Test cleanup_expired_windows method."""
        # Arrange
        rate_limit_state = RateLimitState()
        current_time = datetime.now(timezone.utc)
        
        # Create expired window
        expired_window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=current_time - timedelta(minutes=6)  # Expired
        )
        
        # Create active window
        active_window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=456,
            last_attempt_at=current_time - timedelta(minutes=2)  # Still active
        )
        
        rate_limit_state.set_window(expired_window)
        rate_limit_state.set_window(active_window)
        
        # Act
        cleaned_count = rate_limit_state.cleanup_expired_windows(current_time)
        
        # Assert
        assert cleaned_count == 1
        assert rate_limit_state.get_window(user_id=123) is None  # Expired window removed
        assert rate_limit_state.get_window(user_id=456) is not None  # Active window remains

    def test_rate_limit_state_cleanup_no_expired_windows(self):
        """Test cleanup_expired_windows when no windows are expired."""
        # Arrange
        rate_limit_state = RateLimitState()
        current_time = datetime.now(timezone.utc)
        
        # Create active window
        active_window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=current_time - timedelta(minutes=2)  # Still active
        )
        
        rate_limit_state.set_window(active_window)
        
        # Act
        cleaned_count = rate_limit_state.cleanup_expired_windows(current_time)
        
        # Assert
        assert cleaned_count == 0
        assert rate_limit_state.get_window(user_id=123) is not None  # Window remains

    def test_rate_limit_state_production_scenario_multiple_users(self):
        """Test rate limit state with multiple users."""
        # Arrange
        rate_limit_state = RateLimitState()
        current_time = datetime.now(timezone.utc)
        
        # Act - Simulate multiple users making attempts
        for user_id in range(1, 11):  # 10 users
            rate_limit_state.record_attempt(user_id=user_id, attempt_time=current_time)
        
        # Assert
        for user_id in range(1, 11):
            window = rate_limit_state.get_window(user_id=user_id)
            assert window is not None
            assert window.user_id == user_id
            assert window.last_attempt_at == current_time
            assert rate_limit_state.is_user_limited(user_id=user_id, current_time=current_time) is True

    def test_rate_limit_state_production_scenario_cleanup_performance(self):
        """Test cleanup performance with many windows."""
        # Arrange
        rate_limit_state = RateLimitState()
        current_time = datetime.now(timezone.utc)
        
        # Create many windows (mix of expired and active)
        for user_id in range(1, 101):  # 100 users
            if user_id % 2 == 0:  # Even users have expired windows
                last_attempt = current_time - timedelta(minutes=6)
            else:  # Odd users have active windows
                last_attempt = current_time - timedelta(minutes=2)
            
            window = RateLimitWindow(
                window_duration=timedelta(minutes=5),
                max_attempts=1,
                user_id=user_id,
                last_attempt_at=last_attempt
            )
            rate_limit_state.set_window(window)
        
        # Act
        cleaned_count = rate_limit_state.cleanup_expired_windows(current_time)
        
        # Assert
        assert cleaned_count == 50  # Half of the windows should be expired
        assert len(rate_limit_state._windows) == 50  # Half should remain

    def test_rate_limit_state_edge_case_empty_state(self):
        """Test edge case with empty state."""
        # Arrange
        rate_limit_state = RateLimitState()
        current_time = datetime.now(timezone.utc)
        
        # Act
        is_limited = rate_limit_state.is_user_limited(user_id=123, current_time=current_time)
        cleaned_count = rate_limit_state.cleanup_expired_windows(current_time)
        
        # Assert
        assert is_limited is False
        assert cleaned_count == 0

    def test_rate_limit_state_edge_case_boundary_times(self):
        """Test edge case with boundary times."""
        # Arrange
        rate_limit_state = RateLimitState()
        current_time = datetime.now(timezone.utc)
        exact_boundary_time = current_time - timedelta(minutes=5)  # Exactly at boundary
        
        window = RateLimitWindow(
            window_duration=timedelta(minutes=5),
            max_attempts=1,
            user_id=123,
            last_attempt_at=exact_boundary_time
        )
        rate_limit_state.set_window(window)
        
        # Act
        is_limited = rate_limit_state.is_user_limited(user_id=123, current_time=current_time)
        
        # Assert
        assert is_limited is False  # Should be exactly at boundary, not limited 