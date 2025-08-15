"""
Mock API source for testing and demonstration
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import random
import asyncio
from .base import ScamSource
from ..database import ScamRecord


class MockSource(ScamSource):
    """Mock source for testing and demonstration purposes"""
    
    def __init__(self):
        super().__init__("mock")
        self.rate_limit_delay = 0.1  # Fast for testing
    
    def is_configured(self) -> bool:
        """Mock source is always configured"""
        return True
    
    async def fetch_recent_scams(self, limit: int = 50) -> List[ScamRecord]:
        """Generate mock scam records"""
        await asyncio.sleep(0.1)  # Simulate API delay
        
        scam_templates = [
            {
                "title": "Fake PayPal Security Alert",
                "description": "Phishing email claiming PayPal account suspended",
                "type": "phishing",
                "urls": ["http://paypal-security.fake-domain.com"],
                "severity": 8.5
            },
            {
                "title": "IRS Tax Refund Scam",
                "description": "Fraudulent email claiming tax refund available",
                "type": "fraud",
                "severity": 7.0
            },
            {
                "title": "Tech Support Robocall",
                "description": "Automated call claiming computer virus detected",
                "type": "robocall",
                "phone": "+1-800-555-SCAM",
                "severity": 6.5
            },
            {
                "title": "Fake Amazon Order Confirmation",
                "description": "Phishing email with malicious attachment",
                "type": "phishing",
                "urls": ["http://amazon-orders.suspicious-site.net"],
                "severity": 8.0
            },
            {
                "title": "Romance Scam Profile",
                "description": "Fake dating profile used for financial fraud",
                "type": "romance_scam",
                "severity": 7.5
            },
            {
                "title": "Cryptocurrency Investment Fraud",
                "description": "Fake investment platform promising high returns",
                "type": "investment_fraud",
                "urls": ["http://crypto-profits.scam-site.org"],
                "severity": 9.0
            },
            {
                "title": "Fake Microsoft Support",
                "description": "Cold call claiming Windows license expired",
                "type": "tech_support",
                "phone": "+1-888-555-FAKE",
                "severity": 6.0
            },
            {
                "title": "Lottery Winner Notification",
                "description": "Email claiming lottery win, requesting fees",
                "type": "lottery_scam",
                "severity": 5.5
            }
        ]
        
        locations = ["US", "UK", "CA", "AU", "DE", "FR", "IN", "BR", "MX", "JP"]
        
        scams = []
        for i in range(min(limit, len(scam_templates) * 3)):
            template = random.choice(scam_templates)
            
            # Add some variation
            variation_id = random.randint(1000, 9999)
            
            # Random timestamp within last 7 days
            days_ago = random.uniform(0, 7)
            first_seen = datetime.utcnow() - timedelta(days=days_ago)
            
            scam = ScamRecord(
                title=f"{template['title']} #{variation_id}",
                description=template['description'],
                scam_type=template['type'],
                source="mock",
                source_id=f"mock_{i}_{variation_id}",
                url=template.get('urls', [None])[0] if template.get('urls') else None,
                phone=template.get('phone'),
                location=random.choice(locations),
                severity=template['severity'] + random.uniform(-1.0, 1.0),
                confidence=random.uniform(0.6, 0.95),
                first_seen=first_seen,
                is_verified=random.choice([True, False, False]),  # 33% verified
                tags=[template['type'], "mock"],
                raw_data={
                    "mock_id": variation_id,
                    "template": template['title'],
                    "generated_at": datetime.utcnow().isoformat()
                }
            )
            
            # Clamp severity to valid range
            scam.severity = max(0.0, min(10.0, scam.severity))
            
            scams.append(scam)
        
        return scams[:limit]
    
    async def search_scams(self, query: str, limit: int = 50) -> List[ScamRecord]:
        """Search mock scams (filter by query)"""
        all_scams = await self.fetch_recent_scams(limit * 2)
        
        # Simple text search
        query_lower = query.lower()
        matching_scams = []
        
        for scam in all_scams:
            if (query_lower in scam.title.lower() or 
                query_lower in scam.description.lower() or
                query_lower in scam.scam_type.lower()):
                matching_scams.append(scam)
        
        return matching_scams[:limit]
