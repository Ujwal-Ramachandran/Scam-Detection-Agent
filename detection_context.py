"""
Detection Context - Shared state object for phishing detection pipeline
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Optional
import json
import uuid


@dataclass
class DetectionContext:
    """
    Thread-safe context object passed through detection pipeline.
    Each agent reads from and writes to this shared context.
    """
    
    # Unique identifier for this detection
    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    
    # ===== Input Data =====
    sender_name: Optional[str] = None
    sender_mobile_number: Optional[str] = None
    sender_message: Optional[str] = None
    message_timestamp: Optional[datetime] = None
    
    # ===== Location Data =====
    host_location: Optional[Dict] = None  # {ip, city, country, timezone, etc.}
    sender_country: Optional[str] = None
    sender_carrier: Optional[str] = None
    sender_phone_valid: Optional[bool] = None
    
    # ===== URL Data =====
    urls_found: List[str] = field(default_factory=list)
    expanded_urls: Dict[str, str] = field(default_factory=dict)  # original -> expanded
    url_shortener_used: bool = False
    
    # ===== Risk Tracking =====
    risk_score: int = 0
    red_flags: List[Dict] = field(default_factory=list)  # Suspicious indicators
    green_flags: List[Dict] = field(default_factory=list)  # Legitimate indicators
    
    # ===== Agent Results (for backward compatibility) =====
    agent_results: Dict[str, Dict] = field(default_factory=dict)
    
    # ===== Content Analysis Data =====
    page_title: Optional[str] = None
    form_fields_detected: List[str] = field(default_factory=list)
    brand_impersonation: Optional[str] = None
    
    # ===== Security Data =====
    security_headers_score: int = 0
    ssl_certificate_valid: Optional[bool] = None
    
    # ===== Final Verdict =====
    final_verdict: Optional[str] = None  # 'safe', 'phishing', 'uncertain'
    final_confidence: float = 0.0
    detected_by: Optional[str] = None  # Which agent made final determination
    
    # ===== Metadata =====
    metadata: Dict = field(default_factory=dict)  # For any additional data
    
    def add_risk(self, points: int, reason: str, agent_name: str):
        """
        Add risk points with audit trail
        
        Args:
            points: Risk points to add (positive integer)
            reason: Human-readable explanation
            agent_name: Name of agent adding the risk
        """
        self.risk_score += points
        self.red_flags.append({
            'agent': agent_name,
            'reason': reason,
            'points': points,
            'timestamp': datetime.now().isoformat()
        })
    
    def add_green_flag(self, reason: str, agent_name: str):
        """
        Add positive indicator (legitimate signal)
        
        Args:
            reason: Human-readable explanation
            agent_name: Name of agent adding the flag
        """
        self.green_flags.append({
            'agent': agent_name,
            'reason': reason,
            'timestamp': datetime.now().isoformat()
        })
    
    def set_agent_result(self, agent_name: str, result: Dict):
        """
        Store agent's full result (backward compatibility)
        
        Args:
            agent_name: Name of the agent
            result: Dict containing verdict, confidence, reasoning, etc.
        """
        self.agent_results[agent_name] = result
    
    def get_summary(self) -> Dict:
        """
        Get quick summary of detection status
        
        Returns:
            Dict with key metrics
        """
        return {
            'detection_id': self.detection_id,
            'timestamp': self.timestamp.isoformat(),
            'risk_score': self.risk_score,
            'red_flags_count': len(self.red_flags),
            'green_flags_count': len(self.green_flags),
            'agents_run': list(self.agent_results.keys()),
            'final_verdict': self.final_verdict,
            'final_confidence': self.final_confidence
        }
    
    def to_json(self) -> str:
        """
        Serialize context to JSON string for storage
        
        Returns:
            JSON string representation
        """
        data = asdict(self)
        # Convert datetime objects to ISO format strings
        data['timestamp'] = self.timestamp.isoformat()
        if self.message_timestamp:
            data['message_timestamp'] = self.message_timestamp.isoformat()
        
        return json.dumps(data, indent=2, default=str)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'DetectionContext':
        """
        Deserialize context from JSON string
        
        Args:
            json_str: JSON string representation
            
        Returns:
            DetectionContext instance
        """
        data = json.loads(json_str)
        
        # Convert ISO format strings back to datetime objects
        if 'timestamp' in data:
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        if 'message_timestamp' in data and data['message_timestamp']:
            data['message_timestamp'] = datetime.fromisoformat(data['message_timestamp'])
        
        return cls(**data)
    
    def __str__(self) -> str:
        """String representation for debugging"""
        return (f"DetectionContext(id={self.detection_id[:8]}..., "
                f"verdict={self.final_verdict}, "
                f"risk_score={self.risk_score}, "
                f"confidence={self.final_confidence:.2f})")
