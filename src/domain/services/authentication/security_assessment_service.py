"""
Security Assessment Domain Service.

This domain service implements security threat assessment and risk analysis
following Domain-Driven Design principles with clear separation of concerns.

Domain Concepts:
- Security Assessment: Comprehensive threat analysis with risk scoring
- Threat Indicators: Specific security signals and patterns
- Risk Scoring: Quantitative assessment of security threats
- Threat Response: Appropriate actions based on threat level

Business Rules:
- All security contexts must be assessed for threats
- Threat levels determine response actions
- Confidence scores must be validated
- Security incidents require immediate response
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import structlog

from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.token_responses import SecurityAssessment, SecurityThreatLevel
from src.common.events import IEventPublisher
from src.domain.events.authentication_events import SecurityIncidentEvent

from .base_authentication_service import BaseAuthenticationService, ServiceContext

logger = structlog.get_logger(__name__)


class SecurityAssessmentService(BaseAuthenticationService):
    """
    Domain service for comprehensive security threat assessment.
    
    This service implements advanced security threat analysis and risk
    assessment following Domain-Driven Design principles with clear
    business logic and security patterns.
    
    Security Features:
    - Real-time threat pattern analysis
    - Risk scoring with confidence metrics
    - Threat indicator identification
    - Automated response recommendations
    - Security incident detection and reporting
    
    Business Rules:
    - All security contexts must be assessed
    - Threat levels determine response actions
    - Critical threats require immediate family compromise
    - Security incidents are published for monitoring
    """
    
    def __init__(self, event_publisher: IEventPublisher):
        """
        Initialize security assessment service.
        
        Args:
            event_publisher: Publisher for security domain events
        """
        super().__init__(event_publisher)
        self._security_metrics = {
            "assessments_performed": 0,
            "critical_threats_detected": 0,
            "high_threats_detected": 0,
            "medium_threats_detected": 0,
            "low_threats_detected": 0,
        }
    
    async def assess_security_threat(
        self,
        security_context: SecurityContext,
        correlation_id: Optional[str] = None
    ) -> SecurityAssessment:
        """
        Assess security threat level based on context.
        
        This method implements comprehensive security threat analysis
        following domain business rules and security patterns.
        
        Args:
            security_context: Security context for threat analysis
            correlation_id: Request correlation ID for tracking
            
        Returns:
            SecurityAssessment: Comprehensive threat assessment result
            
        Business Rules:
        - Internal network IPs indicate lower threat level
        - External network IPs require enhanced monitoring
        - Suspicious user agents trigger higher threat levels
        - Geographic anomalies indicate potential threats
        - Time-based patterns affect threat assessment
        """
        context = ServiceContext(
            correlation_id=correlation_id or "",
            operation="security_assessment"
        )
        
        async with self._operation_context(context) as ctx:
            # Initialize threat indicators
            indicators = []
            confidence_score = 0.95
            
            # Analyze client IP address
            threat_level = await self._analyze_client_ip(
                security_context.client_ip, indicators
            )
            
            # Analyze user agent
            threat_level = await self._analyze_user_agent(
                security_context.user_agent, threat_level, indicators
            )
            
            # Analyze geographic location
            threat_level = await self._analyze_geographic_location(
                security_context.client_ip, threat_level, indicators
            )
            
            # Analyze time patterns
            threat_level = await self._analyze_time_patterns(
                security_context.request_timestamp, threat_level, indicators
            )
            
            # Analyze request patterns
            threat_level = await self._analyze_request_patterns(
                security_context, threat_level, indicators
            )
            
            # Update confidence score based on indicators
            confidence_score = self._calculate_confidence_score(indicators)
            
            # Determine recommended action
            recommended_action = self._determine_recommended_action(
                threat_level, indicators
            )
            
            # Update security metrics
            self._update_security_metrics(threat_level)
            
            assessment = SecurityAssessment(
                threat_level=threat_level,
                confidence_score=confidence_score,
                indicators=indicators,
                recommended_action=recommended_action
            )
            
            logger.info(
                "Security threat assessment completed",
                threat_level=threat_level.value,
                confidence_score=confidence_score,
                indicators_count=len(indicators),
                correlation_id=ctx.correlation_id
            )
            
            return assessment
    
    async def handle_critical_security_threat(
        self,
        assessment: SecurityAssessment,
        user_id: int,
        correlation_id: Optional[str] = None
    ) -> None:
        """
        Handle critical security threats with immediate response.
        
        This method implements immediate response to critical security
        threats following domain business rules and security patterns.
        
        Args:
            assessment: Security assessment indicating critical threat
            user_id: User ID affected by the threat
            correlation_id: Request correlation ID for tracking
            
        Business Rules:
        - Critical threats require immediate family compromise
        - Security incidents must be published for monitoring
        - Comprehensive logging is required for forensics
        - Response actions must be immediate and decisive
        """
        context = ServiceContext(
            correlation_id=correlation_id or "",
            operation="critical_threat_handling"
        )
        
        async with self._operation_context(context) as ctx:
            # Publish critical security incident
            event = SecurityIncidentEvent(
                incident_type="critical_security_threat",
                threat_level=assessment.threat_level,
                description=f"Critical security threat detected: {assessment.recommended_action}",
                user_id=user_id,
                correlation_id=ctx.correlation_id,
                metadata={
                    "confidence_score": assessment.confidence_score,
                    "indicators": assessment.indicators,
                    "recommended_action": assessment.recommended_action
                }
            )
            
            await self._publish_domain_event(event, ctx, logger)
            
            logger.critical(
                "Critical security threat detected",
                user_id=user_id,
                threat_level=assessment.threat_level.value,
                confidence_score=assessment.confidence_score,
                indicators=assessment.indicators,
                correlation_id=ctx.correlation_id
            )
    
    # === Private Security Analysis Methods ===
    
    async def _analyze_client_ip(
        self,
        client_ip: str,
        indicators: List[str]
    ) -> SecurityThreatLevel:
        """Analyze client IP address for threat indicators."""
        if not client_ip:
            indicators.append("missing_client_ip")
            return SecurityThreatLevel.HIGH
        
        # Internal network analysis
        if client_ip.startswith(("10.", "192.168.", "172.")):
            indicators.append("internal_network")
            return SecurityThreatLevel.LOW
        
        # External network analysis
        indicators.append("external_network")
        return SecurityThreatLevel.MEDIUM
    
    async def _analyze_user_agent(
        self,
        user_agent: str,
        current_threat_level: SecurityThreatLevel,
        indicators: List[str]
    ) -> SecurityThreatLevel:
        """Analyze user agent for threat indicators."""
        if not user_agent:
            indicators.append("missing_user_agent")
            return SecurityThreatLevel.HIGH
        
        # Check for suspicious user agents
        suspicious_patterns = [
            "bot", "crawler", "scraper", "automation", "headless",
            "phantom", "selenium", "webdriver", "python-requests"
        ]
        
        user_agent_lower = user_agent.lower()
        for pattern in suspicious_patterns:
            if pattern in user_agent_lower:
                indicators.append(f"suspicious_user_agent_{pattern}")
                return SecurityThreatLevel.HIGH
        
        # Normal user agent
        indicators.append("normal_user_agent")
        return current_threat_level
    
    async def _analyze_geographic_location(
        self,
        client_ip: str,
        current_threat_level: SecurityThreatLevel,
        indicators: List[str]
    ) -> SecurityThreatLevel:
        """Analyze geographic location for threat indicators."""
        # Placeholder for geographic analysis
        # In production, this would integrate with IP geolocation services
        indicators.append("geographic_analysis_skipped")
        return current_threat_level
    
    async def _analyze_time_patterns(
        self,
        timestamp: datetime,
        current_threat_level: SecurityThreatLevel,
        indicators: List[str]
    ) -> SecurityThreatLevel:
        """Analyze time patterns for threat indicators."""
        # Check for unusual hours (2 AM - 6 AM)
        hour = timestamp.hour
        if 2 <= hour <= 6:
            indicators.append("unusual_hours")
            return SecurityThreatLevel.HIGH
        
        indicators.append("normal_hours")
        return current_threat_level
    
    async def _analyze_request_patterns(
        self,
        security_context: SecurityContext,
        current_threat_level: SecurityThreatLevel,
        indicators: List[str]
    ) -> SecurityThreatLevel:
        """Analyze request patterns for threat indicators."""
        # Placeholder for request pattern analysis
        # In production, this would analyze request frequency, patterns, etc.
        indicators.append("request_pattern_analysis_skipped")
        return current_threat_level
    
    def _calculate_confidence_score(self, indicators: List[str]) -> float:
        """Calculate confidence score based on indicators."""
        base_score = 0.95
        
        # Reduce confidence for suspicious indicators
        suspicious_indicators = [
            "missing_client_ip", "missing_user_agent", "suspicious_user_agent",
            "unusual_hours", "external_network"
        ]
        
        for indicator in indicators:
            if any(suspicious in indicator for suspicious in suspicious_indicators):
                base_score -= 0.1
        
        return max(0.5, base_score)
    
    def _determine_recommended_action(
        self,
        threat_level: SecurityThreatLevel,
        indicators: List[str]
    ) -> str:
        """Determine recommended action based on threat level."""
        if threat_level == SecurityThreatLevel.CRITICAL:
            return "immediate_family_compromise"
        elif threat_level == SecurityThreatLevel.HIGH:
            return "enhanced_monitoring"
        elif threat_level == SecurityThreatLevel.MEDIUM:
            return "standard_monitoring"
        else:
            return "normal_operation"
    
    def _update_security_metrics(self, threat_level: SecurityThreatLevel) -> None:
        """Update security metrics."""
        self._security_metrics["assessments_performed"] += 1
        
        if threat_level == SecurityThreatLevel.CRITICAL:
            self._security_metrics["critical_threats_detected"] += 1
        elif threat_level == SecurityThreatLevel.HIGH:
            self._security_metrics["high_threats_detected"] += 1
        elif threat_level == SecurityThreatLevel.MEDIUM:
            self._security_metrics["medium_threats_detected"] += 1
        else:
            self._security_metrics["low_threats_detected"] += 1
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security metrics."""
        return self._security_metrics.copy()
    
    async def _validate_operation_prerequisites(self, context: ServiceContext) -> None:
        """Validate operation prerequisites for security assessment.
        
        Args:
            context: Service context
            
        Raises:
            AuthenticationError: If prerequisites are not met
        """
        # Security assessment service has no specific prerequisites
        # All operations are valid as long as the service is initialized
        pass 