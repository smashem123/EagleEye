"""
Trend analysis and predictive analytics for scam detection
Advanced analytics for identifying emerging threats and hotspots
"""
import asyncio
import statistics
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, Counter


class TrendDirection(Enum):
    """Direction of trend movement"""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"


class TrendSeverity(Enum):
    """Severity levels for trends"""
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TrendData:
    """Trend analysis data for scam patterns"""
    metric_name: str
    time_period: str
    current_value: float
    previous_value: float
    change_percentage: float
    trend_direction: TrendDirection
    trend_severity: TrendSeverity
    confidence_score: float
    data_points: List[float]
    prediction_next_period: float
    analysis_timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'metric_name': self.metric_name,
            'time_period': self.time_period,
            'current_value': self.current_value,
            'previous_value': self.previous_value,
            'change_percentage': self.change_percentage,
            'trend_direction': self.trend_direction.value,
            'trend_severity': self.trend_severity.value,
            'confidence_score': self.confidence_score,
            'data_points': self.data_points,
            'prediction_next_period': self.prediction_next_period,
            'analysis_timestamp': self.analysis_timestamp.isoformat()
        }


@dataclass
class HotspotData:
    """Geographic hotspot analysis data"""
    location: str
    location_type: str
    scam_count: int
    scam_density: float
    dominant_scam_types: List[str]
    risk_score: float
    trend_direction: TrendDirection
    emergence_date: datetime
    related_locations: List[str]
    prediction_growth: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'location': self.location,
            'location_type': self.location_type,
            'scam_count': self.scam_count,
            'scam_density': self.scam_density,
            'dominant_scam_types': self.dominant_scam_types,
            'risk_score': self.risk_score,
            'trend_direction': self.trend_direction.value,
            'emergence_date': self.emergence_date.isoformat(),
            'related_locations': self.related_locations,
            'prediction_growth': self.prediction_growth
        }


class TrendAnalyzer:
    """Advanced trend analysis and predictive analytics engine"""
    
    def __init__(self):
        self.min_data_points = 5
        self.prediction_horizon_days = 30
        
        # Scam type weights for severity calculation
        self.scam_severity_weights = {
            'phishing': 3.0,
            'malware': 4.0,
            'identity_theft': 4.5,
            'financial_fraud': 4.0,
            'romance_scam': 3.5,
            'investment_fraud': 4.0,
            'tech_support': 2.5,
            'robocall': 2.0,
            'spam': 1.0
        }
        
        # Geographic risk multipliers
        self.location_risk_multipliers = {
            'urban': 1.2,
            'suburban': 1.0,
            'rural': 0.8,
            'tourist_area': 1.5,
            'business_district': 1.3
        }
    
    async def analyze_scam_trends(self, 
                                 scam_data: List[Dict[str, Any]], 
                                 time_period: str = "7d") -> List[TrendData]:
        """Analyze trends in scam data over time"""
        
        # Group data by time periods
        time_series = self._group_by_time_period(scam_data, time_period)
        
        trends = []
        
        # Analyze overall scam volume trends
        volume_trend = self._analyze_volume_trend(time_series, time_period)
        if volume_trend:
            trends.append(volume_trend)
        
        # Analyze scam type trends
        type_trends = self._analyze_scam_type_trends(scam_data, time_period)
        trends.extend(type_trends)
        
        # Analyze geographic trends
        geo_trends = self._analyze_geographic_trends(scam_data, time_period)
        trends.extend(geo_trends)
        
        # Analyze severity trends
        severity_trend = self._analyze_severity_trends(scam_data, time_period)
        if severity_trend:
            trends.append(severity_trend)
        
        return trends
    
    async def detect_hotspots(self, 
                             scam_data: List[Dict[str, Any]], 
                             location_data: List[Dict[str, Any]] = None) -> List[HotspotData]:
        """Detect geographic scam hotspots"""
        
        # Group scams by location
        location_groups = defaultdict(list)
        for scam in scam_data:
            location = scam.get('location', 'Unknown')
            if location != 'Unknown':
                location_groups[location].append(scam)
        
        hotspots = []
        
        for location, scams in location_groups.items():
            if len(scams) < 3:  # Skip locations with too few scams
                continue
            
            hotspot = await self._analyze_location_hotspot(location, scams, location_data)
            if hotspot and hotspot.risk_score > 5.0:
                hotspots.append(hotspot)
        
        # Sort by risk score
        hotspots.sort(key=lambda x: x.risk_score, reverse=True)
        
        return hotspots[:20]  # Return top 20 hotspots
    
    async def predict_emerging_threats(self, 
                                      scam_data: List[Dict[str, Any]], 
                                      days_ahead: int = 30) -> Dict[str, Any]:
        """Predict emerging threats and trends"""
        
        predictions = {
            'volume_prediction': await self._predict_scam_volume(scam_data, days_ahead),
            'type_predictions': await self._predict_scam_types(scam_data, days_ahead),
            'geographic_predictions': await self._predict_geographic_spread(scam_data, days_ahead),
            'new_threat_indicators': await self._detect_new_threat_patterns(scam_data),
            'confidence_score': 0.75,  # Overall prediction confidence
            'prediction_date': datetime.now().isoformat(),
            'horizon_days': days_ahead
        }
        
        return predictions
    
    def _group_by_time_period(self, scam_data: List[Dict[str, Any]], period: str) -> Dict[str, List[Dict]]:
        """Group scam data by time periods"""
        time_groups = defaultdict(list)
        
        for scam in scam_data:
            timestamp = scam.get('first_seen')
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    continue
            elif not isinstance(timestamp, datetime):
                continue
            
            # Create time key based on period
            if period == "1d":
                time_key = timestamp.strftime("%Y-%m-%d")
            elif period == "7d":
                # Group by week
                week_start = timestamp - timedelta(days=timestamp.weekday())
                time_key = week_start.strftime("%Y-W%U")
            elif period == "30d":
                time_key = timestamp.strftime("%Y-%m")
            else:
                time_key = timestamp.strftime("%Y-%m-%d")
            
            time_groups[time_key].append(scam)
        
        return time_groups
    
    def _analyze_volume_trend(self, time_series: Dict[str, List], period: str) -> Optional[TrendData]:
        """Analyze overall scam volume trends"""
        if len(time_series) < 2:
            return None
        
        # Get volume data points
        sorted_periods = sorted(time_series.keys())
        volume_data = [len(time_series[period]) for period in sorted_periods]
        
        if len(volume_data) < self.min_data_points:
            return None
        
        current_value = volume_data[-1]
        previous_value = volume_data[-2] if len(volume_data) > 1 else current_value
        
        # Calculate change percentage
        change_pct = ((current_value - previous_value) / max(previous_value, 1)) * 100
        
        # Determine trend direction
        trend_direction = self._calculate_trend_direction(volume_data)
        
        # Calculate severity
        trend_severity = self._calculate_trend_severity(change_pct, 'volume')
        
        # Simple linear prediction
        prediction = self._simple_linear_prediction(volume_data)
        
        # Confidence based on data consistency
        confidence = self._calculate_confidence(volume_data)
        
        return TrendData(
            metric_name="scam_volume",
            time_period=period,
            current_value=current_value,
            previous_value=previous_value,
            change_percentage=change_pct,
            trend_direction=trend_direction,
            trend_severity=trend_severity,
            confidence_score=confidence,
            data_points=volume_data,
            prediction_next_period=prediction,
            analysis_timestamp=datetime.now()
        )
    
    def _analyze_scam_type_trends(self, scam_data: List[Dict[str, Any]], period: str) -> List[TrendData]:
        """Analyze trends for different scam types"""
        trends = []
        
        # Group by scam type and time
        type_time_groups = defaultdict(lambda: defaultdict(int))
        
        for scam in scam_data:
            scam_type = scam.get('scam_type', 'unknown')
            timestamp = scam.get('first_seen')
            
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    continue
            
            if period == "7d":
                week_start = timestamp - timedelta(days=timestamp.weekday())
                time_key = week_start.strftime("%Y-W%U")
            else:
                time_key = timestamp.strftime("%Y-%m-%d")
            
            type_time_groups[scam_type][time_key] += 1
        
        # Analyze each scam type
        for scam_type, time_data in type_time_groups.items():
            if len(time_data) < 2:
                continue
            
            sorted_periods = sorted(time_data.keys())
            volume_data = [time_data[period] for period in sorted_periods]
            
            if len(volume_data) < self.min_data_points:
                continue
            
            current_value = volume_data[-1]
            previous_value = volume_data[-2] if len(volume_data) > 1 else current_value
            change_pct = ((current_value - previous_value) / max(previous_value, 1)) * 100
            
            trend_direction = self._calculate_trend_direction(volume_data)
            trend_severity = self._calculate_trend_severity(change_pct, scam_type)
            prediction = self._simple_linear_prediction(volume_data)
            confidence = self._calculate_confidence(volume_data)
            
            trends.append(TrendData(
                metric_name=f"scam_type_{scam_type}",
                time_period=period,
                current_value=current_value,
                previous_value=previous_value,
                change_percentage=change_pct,
                trend_direction=trend_direction,
                trend_severity=trend_severity,
                confidence_score=confidence,
                data_points=volume_data,
                prediction_next_period=prediction,
                analysis_timestamp=datetime.now()
            ))
        
        return trends
    
    def _analyze_geographic_trends(self, scam_data: List[Dict[str, Any]], period: str) -> List[TrendData]:
        """Analyze geographic distribution trends"""
        trends = []
        
        # Group by location and time
        location_time_groups = defaultdict(lambda: defaultdict(int))
        
        for scam in scam_data:
            location = scam.get('location', 'Unknown')
            if location == 'Unknown':
                continue
                
            timestamp = scam.get('first_seen')
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    continue
            
            if period == "7d":
                week_start = timestamp - timedelta(days=timestamp.weekday())
                time_key = week_start.strftime("%Y-W%U")
            else:
                time_key = timestamp.strftime("%Y-%m-%d")
            
            location_time_groups[location][time_key] += 1
        
        # Analyze top locations only
        location_totals = {loc: sum(data.values()) for loc, data in location_time_groups.items()}
        top_locations = sorted(location_totals.items(), key=lambda x: x[1], reverse=True)[:10]
        
        for location, _ in top_locations:
            time_data = location_time_groups[location]
            if len(time_data) < 2:
                continue
            
            sorted_periods = sorted(time_data.keys())
            volume_data = [time_data[period] for period in sorted_periods]
            
            if len(volume_data) < self.min_data_points:
                continue
            
            current_value = volume_data[-1]
            previous_value = volume_data[-2] if len(volume_data) > 1 else current_value
            change_pct = ((current_value - previous_value) / max(previous_value, 1)) * 100
            
            trend_direction = self._calculate_trend_direction(volume_data)
            trend_severity = self._calculate_trend_severity(change_pct, 'geographic')
            prediction = self._simple_linear_prediction(volume_data)
            confidence = self._calculate_confidence(volume_data)
            
            trends.append(TrendData(
                metric_name=f"location_{location.replace(' ', '_')}",
                time_period=period,
                current_value=current_value,
                previous_value=previous_value,
                change_percentage=change_pct,
                trend_direction=trend_direction,
                trend_severity=trend_severity,
                confidence_score=confidence,
                data_points=volume_data,
                prediction_next_period=prediction,
                analysis_timestamp=datetime.now()
            ))
        
        return trends
    
    def _analyze_severity_trends(self, scam_data: List[Dict[str, Any]], period: str) -> Optional[TrendData]:
        """Analyze trends in scam severity"""
        # Group by time and calculate average severity
        time_severity = defaultdict(list)
        
        for scam in scam_data:
            timestamp = scam.get('first_seen')
            severity = scam.get('severity', 5.0)
            
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except:
                    continue
            
            if period == "7d":
                week_start = timestamp - timedelta(days=timestamp.weekday())
                time_key = week_start.strftime("%Y-W%U")
            else:
                time_key = timestamp.strftime("%Y-%m-%d")
            
            time_severity[time_key].append(severity)
        
        if len(time_severity) < 2:
            return None
        
        # Calculate average severity per period
        sorted_periods = sorted(time_severity.keys())
        severity_data = [statistics.mean(time_severity[period]) for period in sorted_periods]
        
        if len(severity_data) < self.min_data_points:
            return None
        
        current_value = severity_data[-1]
        previous_value = severity_data[-2] if len(severity_data) > 1 else current_value
        change_pct = ((current_value - previous_value) / max(previous_value, 1)) * 100
        
        trend_direction = self._calculate_trend_direction(severity_data)
        trend_severity = self._calculate_trend_severity(change_pct, 'severity')
        prediction = self._simple_linear_prediction(severity_data)
        confidence = self._calculate_confidence(severity_data)
        
        return TrendData(
            metric_name="average_severity",
            time_period=period,
            current_value=current_value,
            previous_value=previous_value,
            change_percentage=change_pct,
            trend_direction=trend_direction,
            trend_severity=trend_severity,
            confidence_score=confidence,
            data_points=severity_data,
            prediction_next_period=prediction,
            analysis_timestamp=datetime.now()
        )
    
    async def _analyze_location_hotspot(self, 
                                       location: str, 
                                       scams: List[Dict], 
                                       location_data: List[Dict] = None) -> Optional[HotspotData]:
        """Analyze a specific location for hotspot characteristics"""
        
        scam_count = len(scams)
        
        # Calculate scam density (scams per day)
        if scams:
            timestamps = []
            for scam in scams:
                ts = scam.get('first_seen')
                if isinstance(ts, str):
                    try:
                        timestamps.append(datetime.fromisoformat(ts.replace('Z', '+00:00')))
                    except:
                        continue
                elif isinstance(ts, datetime):
                    timestamps.append(ts)
            
            if timestamps:
                min_date = min(timestamps)
                max_date = max(timestamps)
                days = max((max_date - min_date).days, 1)
                scam_density = scam_count / days
            else:
                scam_density = scam_count
        else:
            scam_density = 0
        
        # Analyze dominant scam types
        scam_types = [scam.get('scam_type', 'unknown') for scam in scams]
        type_counts = Counter(scam_types)
        dominant_types = [scam_type for scam_type, _ in type_counts.most_common(3)]
        
        # Calculate risk score
        risk_score = self._calculate_hotspot_risk_score(
            scam_count, scam_density, dominant_types, location
        )
        
        # Determine trend direction
        recent_scams = [s for s in scams if self._is_recent(s.get('first_seen'), days=7)]
        older_scams = [s for s in scams if not self._is_recent(s.get('first_seen'), days=7)]
        
        if len(recent_scams) > len(older_scams):
            trend_direction = TrendDirection.INCREASING
        elif len(recent_scams) < len(older_scams) * 0.5:
            trend_direction = TrendDirection.DECREASING
        else:
            trend_direction = TrendDirection.STABLE
        
        # Find emergence date (first scam)
        emergence_date = min(timestamps) if timestamps else datetime.now()
        
        # Find related locations (simplified)
        related_locations = self._find_related_locations(location, scams)
        
        # Predict growth
        prediction_growth = self._predict_hotspot_growth(scam_count, scam_density, trend_direction)
        
        return HotspotData(
            location=location,
            location_type="city",  # Simplified
            scam_count=scam_count,
            scam_density=scam_density,
            dominant_scam_types=dominant_types,
            risk_score=risk_score,
            trend_direction=trend_direction,
            emergence_date=emergence_date,
            related_locations=related_locations,
            prediction_growth=prediction_growth
        )
    
    def _calculate_trend_direction(self, data_points: List[float]) -> TrendDirection:
        """Calculate overall trend direction from data points"""
        if len(data_points) < 3:
            return TrendDirection.STABLE
        
        # Calculate simple moving average trend
        recent_avg = statistics.mean(data_points[-3:])
        earlier_avg = statistics.mean(data_points[:-3])
        
        # Calculate volatility
        volatility = statistics.stdev(data_points) if len(data_points) > 1 else 0
        avg_value = statistics.mean(data_points)
        volatility_ratio = volatility / max(avg_value, 1)
        
        if volatility_ratio > 0.5:
            return TrendDirection.VOLATILE
        elif recent_avg > earlier_avg * 1.1:
            return TrendDirection.INCREASING
        elif recent_avg < earlier_avg * 0.9:
            return TrendDirection.DECREASING
        else:
            return TrendDirection.STABLE
    
    def _calculate_trend_severity(self, change_pct: float, metric_type: str) -> TrendSeverity:
        """Calculate trend severity based on change percentage and type"""
        abs_change = abs(change_pct)
        
        # Adjust thresholds based on metric type
        if metric_type in self.scam_severity_weights:
            weight = self.scam_severity_weights[metric_type]
            abs_change *= weight
        
        if abs_change >= 50:
            return TrendSeverity.CRITICAL
        elif abs_change >= 25:
            return TrendSeverity.HIGH
        elif abs_change >= 10:
            return TrendSeverity.MODERATE
        else:
            return TrendSeverity.LOW
    
    def _simple_linear_prediction(self, data_points: List[float]) -> float:
        """Simple linear regression prediction for next period"""
        if len(data_points) < 2:
            return data_points[0] if data_points else 0
        
        # Simple linear trend calculation
        x_values = list(range(len(data_points)))
        n = len(data_points)
        
        sum_x = sum(x_values)
        sum_y = sum(data_points)
        sum_xy = sum(x * y for x, y in zip(x_values, data_points))
        sum_x2 = sum(x * x for x in x_values)
        
        # Calculate slope
        slope = (n * sum_xy - sum_x * sum_y) / max(n * sum_x2 - sum_x * sum_x, 1)
        intercept = (sum_y - slope * sum_x) / n
        
        # Predict next value
        next_x = len(data_points)
        prediction = slope * next_x + intercept
        
        return max(0, prediction)  # Don't predict negative values
    
    def _calculate_confidence(self, data_points: List[float]) -> float:
        """Calculate confidence score based on data consistency"""
        if len(data_points) < 2:
            return 0.5
        
        # Calculate coefficient of variation
        mean_val = statistics.mean(data_points)
        std_val = statistics.stdev(data_points) if len(data_points) > 1 else 0
        
        if mean_val == 0:
            return 0.5
        
        cv = std_val / mean_val
        
        # Convert to confidence (lower CV = higher confidence)
        confidence = max(0.1, min(0.95, 1.0 - cv))
        
        # Boost confidence with more data points
        data_boost = min(0.2, len(data_points) * 0.02)
        confidence += data_boost
        
        return min(0.95, confidence)
    
    def _calculate_hotspot_risk_score(self, 
                                     count: int, 
                                     density: float, 
                                     types: List[str], 
                                     location: str) -> float:
        """Calculate risk score for a hotspot"""
        score = 0.0
        
        # Base score from count
        score += min(count * 0.1, 3.0)
        
        # Density factor
        score += min(density * 0.5, 3.0)
        
        # Scam type severity
        for scam_type in types:
            weight = self.scam_severity_weights.get(scam_type, 2.0)
            score += weight * 0.3
        
        # Location risk multiplier (simplified)
        if 'city' in location.lower():
            score *= 1.2
        elif 'rural' in location.lower():
            score *= 0.8
        
        return min(10.0, score)
    
    def _is_recent(self, timestamp, days: int = 7) -> bool:
        """Check if timestamp is within recent period"""
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                return False
        elif not isinstance(timestamp, datetime):
            return False
        
        cutoff = datetime.now() - timedelta(days=days)
        return timestamp >= cutoff
    
    def _find_related_locations(self, location: str, scams: List[Dict]) -> List[str]:
        """Find locations related to this hotspot"""
        # Simplified: find locations mentioned in scam data
        related = set()
        
        for scam in scams:
            # Look for location mentions in description or other fields
            desc = scam.get('description', '').lower()
            if location.lower() not in desc:
                continue
            
            # Simple pattern matching for location names
            words = desc.split()
            for word in words:
                if len(word) > 3 and word.istitle():
                    related.add(word)
        
        return list(related)[:5]  # Return top 5
    
    def _predict_hotspot_growth(self, count: int, density: float, trend: TrendDirection) -> float:
        """Predict hotspot growth percentage"""
        base_growth = 0.0
        
        if trend == TrendDirection.INCREASING:
            base_growth = 25.0
        elif trend == TrendDirection.DECREASING:
            base_growth = -15.0
        elif trend == TrendDirection.VOLATILE:
            base_growth = 10.0
        
        # Adjust based on current metrics
        if density > 5.0:
            base_growth += 10.0
        if count > 50:
            base_growth += 5.0
        
        return base_growth
    
    async def _predict_scam_volume(self, scam_data: List[Dict], days_ahead: int) -> Dict[str, Any]:
        """Predict overall scam volume"""
        # Simple trend-based prediction
        recent_data = [s for s in scam_data if self._is_recent(s.get('first_seen'), days=30)]
        
        current_daily_avg = len(recent_data) / 30
        prediction = current_daily_avg * days_ahead
        
        return {
            'predicted_volume': int(prediction),
            'current_daily_average': current_daily_avg,
            'confidence': 0.7
        }
    
    async def _predict_scam_types(self, scam_data: List[Dict], days_ahead: int) -> Dict[str, Any]:
        """Predict scam type distribution"""
        type_counts = Counter(scam.get('scam_type', 'unknown') for scam in scam_data)
        total = sum(type_counts.values())
        
        predictions = {}
        for scam_type, count in type_counts.most_common(5):
            percentage = (count / total) * 100
            predictions[scam_type] = {
                'current_percentage': percentage,
                'predicted_growth': 5.0 if percentage > 15 else 10.0
            }
        
        return predictions
    
    async def _predict_geographic_spread(self, scam_data: List[Dict], days_ahead: int) -> Dict[str, Any]:
        """Predict geographic spread patterns"""
        location_counts = Counter(scam.get('location', 'Unknown') for scam in scam_data)
        
        return {
            'emerging_locations': [loc for loc, count in location_counts.most_common(3) if count > 5],
            'spread_risk': 'moderate',
            'new_areas_predicted': 2
        }
    
    async def _detect_new_threat_patterns(self, scam_data: List[Dict]) -> List[Dict[str, Any]]:
        """Detect emerging threat patterns"""
        patterns = []
        
        # Analyze recent scams for new patterns
        recent_scams = [s for s in scam_data if self._is_recent(s.get('first_seen'), days=14)]
        
        if len(recent_scams) > 10:
            # Look for new scam types
            recent_types = Counter(s.get('scam_type') for s in recent_scams)
            all_types = Counter(s.get('scam_type') for s in scam_data)
            
            for scam_type, recent_count in recent_types.items():
                total_count = all_types[scam_type]
                if recent_count / total_count > 0.5:  # More than 50% are recent
                    patterns.append({
                        'pattern_type': 'emerging_scam_type',
                        'scam_type': scam_type,
                        'recent_count': recent_count,
                        'growth_rate': 'high'
                    })
        
        return patterns

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict

import asyncio


@dataclass
class TrendData:
    """Trend analysis data point."""
    location: str
    state: str
    complaint_count: int
    trend_direction: str  # 'increasing', 'decreasing', 'stable'
    trend_percentage: float
    risk_score: float
    top_scam_types: List[Dict[str, Any]]
    recent_activity: List[Dict[str, Any]]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'location': self.location,
            'state': self.state,
            'complaint_count': self.complaint_count,
            'trend_direction': self.trend_direction,
            'trend_percentage': self.trend_percentage,
            'risk_score': self.risk_score,
            'top_scam_types': self.top_scam_types,
            'recent_activity': self.recent_activity
        }


@dataclass
class HotspotData:
    """Scam hotspot information."""
    location: str
    state: str
    latitude: float
    longitude: float
    intensity_score: float
    complaint_density: float
    dominant_scam_type: str
    active_numbers: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'location': self.location,
            'state': self.state,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'intensity_score': self.intensity_score,
            'complaint_density': self.complaint_density,
            'dominant_scam_type': self.dominant_scam_type,
            'active_numbers': self.active_numbers
        }


class TrendAnalyzer:
    """Main trend analysis system."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.ftc_db_path = config_dir / "ftc_dnc.db"
        self.fcc_db_path = config_dir / "fcc_complaints.db"
        self.trends_db_path = config_dir / "trends.db"
        
        self.init_trends_database()
    
    def init_trends_database(self):
        """Initialize trends analysis database."""
        with sqlite3.connect(self.trends_db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS trend_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    location TEXT,
                    state TEXT,
                    snapshot_date DATE,
                    complaint_count INTEGER,
                    scam_types TEXT,
                    risk_score REAL,
                    data_source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_location_date 
                ON trend_snapshots(location, state, snapshot_date)
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS hotspots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    location TEXT,
                    state TEXT,
                    latitude REAL,
                    longitude REAL,
                    intensity_score REAL,
                    complaint_density REAL,
                    dominant_scam_type TEXT,
                    active_numbers TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            ''')
    
    def capture_trend_snapshot(self) -> bool:
        """Capture current trend data for analysis."""
        try:
            snapshot_date = datetime.now().date()
            
            # Get FTC data
            ftc_trends = self._analyze_ftc_trends()
            
            # Get FCC data
            fcc_trends = self._analyze_fcc_trends()
            
            # Combine and store snapshots
            with sqlite3.connect(self.trends_db_path) as conn:
                for trend in ftc_trends + fcc_trends:
                    conn.execute('''
                        INSERT OR REPLACE INTO trend_snapshots 
                        (location, state, snapshot_date, complaint_count, 
                         scam_types, risk_score, data_source)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        trend['location'], trend['state'], snapshot_date,
                        trend['complaint_count'], json.dumps(trend['scam_types']),
                        trend['risk_score'], trend['data_source']
                    ))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error capturing trend snapshot: {e}")
            return False
    
    def _analyze_ftc_trends(self) -> List[Dict[str, Any]]:
        """Analyze FTC complaint trends."""
        trends = []
        
        try:
            with sqlite3.connect(self.ftc_db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get complaints by location for last 30 days
                thirty_days_ago = datetime.now() - timedelta(days=30)
                
                results = conn.execute('''
                    SELECT city, state, COUNT(*) as complaint_count,
                           GROUP_CONCAT(DISTINCT call_type) as call_types,
                           AVG(CASE WHEN is_robocall = 1 THEN 8.0 ELSE 5.0 END) as avg_risk
                    FROM ftc_complaints 
                    WHERE date_received >= ?
                    GROUP BY city, state
                    HAVING complaint_count >= 3
                    ORDER BY complaint_count DESC
                ''', (thirty_days_ago,)).fetchall()
                
                for row in results:
                    scam_types = row['call_types'].split(',') if row['call_types'] else []
                    
                    trends.append({
                        'location': row['city'],
                        'state': row['state'],
                        'complaint_count': row['complaint_count'],
                        'scam_types': scam_types,
                        'risk_score': row['avg_risk'],
                        'data_source': 'ftc'
                    })
                
        except Exception as e:
            print(f"Error analyzing FTC trends: {e}")
        
        return trends
    
    def _analyze_fcc_trends(self) -> List[Dict[str, Any]]:
        """Analyze FCC complaint trends."""
        trends = []
        
        try:
            with sqlite3.connect(self.fcc_db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get complaints by location for last 30 days
                thirty_days_ago = datetime.now() - timedelta(days=30)
                
                results = conn.execute('''
                    SELECT city, state, COUNT(*) as complaint_count,
                           GROUP_CONCAT(DISTINCT issue_type) as issue_types
                    FROM fcc_complaints 
                    WHERE date_received >= ? AND city IS NOT NULL
                    GROUP BY city, state
                    HAVING complaint_count >= 2
                    ORDER BY complaint_count DESC
                ''', (thirty_days_ago,)).fetchall()
                
                for row in results:
                    issue_types = row['issue_types'].split(',') if row['issue_types'] else []
                    
                    # Calculate risk score based on issue types
                    risk_score = 5.0
                    if any('unwanted' in issue.lower() for issue in issue_types):
                        risk_score += 2.0
                    if any('robocall' in issue.lower() for issue in issue_types):
                        risk_score += 3.0
                    
                    trends.append({
                        'location': row['city'],
                        'state': row['state'],
                        'complaint_count': row['complaint_count'],
                        'scam_types': issue_types,
                        'risk_score': min(risk_score, 10.0),
                        'data_source': 'fcc'
                    })
                
        except Exception as e:
            print(f"Error analyzing FCC trends: {e}")
        
        return trends
    
    def get_trending_locations(self, days: int = 7, limit: int = 20) -> List[TrendData]:
        """Get locations with trending scam activity."""
        try:
            with sqlite3.connect(self.trends_db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get current period data
                current_start = datetime.now() - timedelta(days=days)
                current_results = conn.execute('''
                    SELECT location, state, 
                           SUM(complaint_count) as current_complaints,
                           AVG(risk_score) as avg_risk,
                           GROUP_CONCAT(scam_types) as all_scam_types
                    FROM trend_snapshots 
                    WHERE snapshot_date >= ?
                    GROUP BY location, state
                    ORDER BY current_complaints DESC
                    LIMIT ?
                ''', (current_start.date(), limit)).fetchall()
                
                trends = []
                
                for row in current_results:
                    location = row['location']
                    state = row['state']
                    current_complaints = row['current_complaints']
                    
                    # Get previous period data for comparison
                    previous_start = current_start - timedelta(days=days)
                    previous_end = current_start
                    
                    previous_result = conn.execute('''
                        SELECT SUM(complaint_count) as previous_complaints
                        FROM trend_snapshots 
                        WHERE location = ? AND state = ?
                        AND snapshot_date >= ? AND snapshot_date < ?
                    ''', (location, state, previous_start.date(), previous_end.date())).fetchone()
                    
                    previous_complaints = previous_result['previous_complaints'] or 0
                    
                    # Calculate trend
                    if previous_complaints > 0:
                        trend_percentage = ((current_complaints - previous_complaints) / previous_complaints) * 100
                    else:
                        trend_percentage = 100.0 if current_complaints > 0 else 0.0
                    
                    # Determine trend direction
                    if trend_percentage > 20:
                        trend_direction = 'increasing'
                    elif trend_percentage < -20:
                        trend_direction = 'decreasing'
                    else:
                        trend_direction = 'stable'
                    
                    # Parse scam types
                    all_scam_types_str = row['all_scam_types'] or ''
                    scam_type_counts = defaultdict(int)
                    
                    for types_json in all_scam_types_str.split(','):
                        if types_json.strip():
                            try:
                                types_list = json.loads(types_json.strip())
                                for scam_type in types_list:
                                    scam_type_counts[scam_type] += 1
                            except:
                                continue
                    
                    top_scam_types = [
                        {'type': scam_type, 'count': count}
                        for scam_type, count in sorted(scam_type_counts.items(), 
                                                     key=lambda x: x[1], reverse=True)[:5]
                    ]
                    
                    # Get recent activity
                    recent_activity = self._get_recent_activity(location, state, days=3)
                    
                    trend_data = TrendData(
                        location=location,
                        state=state,
                        complaint_count=current_complaints,
                        trend_direction=trend_direction,
                        trend_percentage=round(trend_percentage, 1),
                        risk_score=round(row['avg_risk'], 1),
                        top_scam_types=top_scam_types,
                        recent_activity=recent_activity
                    )
                    
                    trends.append(trend_data)
                
                return trends
                
        except Exception as e:
            print(f"Error getting trending locations: {e}")
            return []
    
    def _get_recent_activity(self, location: str, state: str, days: int = 3) -> List[Dict[str, Any]]:
        """Get recent activity for a location."""
        activity = []
        
        try:
            # Check FTC complaints
            with sqlite3.connect(self.ftc_db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                recent_date = datetime.now() - timedelta(days=days)
                
                ftc_results = conn.execute('''
                    SELECT phone_number, caller_id_name, subject, date_received, is_robocall
                    FROM ftc_complaints 
                    WHERE city = ? AND state = ? AND date_received >= ?
                    ORDER BY date_received DESC
                    LIMIT 5
                ''', (location, state, recent_date)).fetchall()
                
                for row in ftc_results:
                    activity.append({
                        'source': 'FTC',
                        'phone_number': row['phone_number'],
                        'caller_name': row['caller_id_name'],
                        'subject': row['subject'],
                        'date': row['date_received'],
                        'is_robocall': bool(row['is_robocall'])
                    })
            
            # Check FCC complaints
            with sqlite3.connect(self.fcc_db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                fcc_results = conn.execute('''
                    SELECT issue_type, company_name, date_received
                    FROM fcc_complaints 
                    WHERE city = ? AND state = ? AND date_received >= ?
                    ORDER BY date_received DESC
                    LIMIT 3
                ''', (location, state, recent_date)).fetchall()
                
                for row in fcc_results:
                    activity.append({
                        'source': 'FCC',
                        'issue_type': row['issue_type'],
                        'company': row['company_name'],
                        'date': row['date_received']
                    })
                
        except Exception as e:
            print(f"Error getting recent activity: {e}")
        
        return activity[:8]  # Limit to 8 most recent items
    
    def detect_hotspots(self, min_intensity: float = 7.0) -> List[HotspotData]:
        """Detect scam hotspots based on complaint density and intensity."""
        hotspots = []
        
        try:
            # Get geolocation service
            from .geolocation import GeolocationService
            geo_service = GeolocationService(self.config_dir)
            
            with sqlite3.connect(self.trends_db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get high-activity locations from last 14 days
                two_weeks_ago = datetime.now() - timedelta(days=14)
                
                results = conn.execute('''
                    SELECT location, state, 
                           SUM(complaint_count) as total_complaints,
                           AVG(risk_score) as avg_risk,
                           COUNT(DISTINCT snapshot_date) as active_days
                    FROM trend_snapshots 
                    WHERE snapshot_date >= ?
                    GROUP BY location, state
                    HAVING total_complaints >= 10 AND avg_risk >= ?
                    ORDER BY total_complaints DESC, avg_risk DESC
                ''', (two_weeks_ago.date(), min_intensity)).fetchall()
                
                for row in results:
                    location = row['location']
                    state = row['state']
                    
                    # Get geographic coordinates
                    geo_data = geo_service._lookup_city_state(location, state)
                    if not geo_data:
                        continue
                    
                    # Calculate intensity score
                    complaint_density = row['total_complaints'] / row['active_days']
                    intensity_score = (row['avg_risk'] * 0.6) + (complaint_density * 0.4)
                    
                    # Get active phone numbers
                    active_numbers = self._get_active_numbers(location, state)
                    
                    # Get dominant scam type
                    dominant_scam_type = self._get_dominant_scam_type(location, state)
                    
                    hotspot = HotspotData(
                        location=location,
                        state=state,
                        latitude=geo_data.latitude,
                        longitude=geo_data.longitude,
                        intensity_score=round(intensity_score, 2),
                        complaint_density=round(complaint_density, 2),
                        dominant_scam_type=dominant_scam_type,
                        active_numbers=active_numbers
                    )
                    
                    hotspots.append(hotspot)
                    
                    # Cache hotspot
                    self._cache_hotspot(hotspot)
                
        except Exception as e:
            print(f"Error detecting hotspots: {e}")
        
        return hotspots
    
    def _get_active_numbers(self, location: str, state: str, limit: int = 10) -> List[str]:
        """Get most active phone numbers for a location."""
        active_numbers = []
        
        try:
            with sqlite3.connect(self.ftc_db_path) as conn:
                recent_date = datetime.now() - timedelta(days=7)
                
                results = conn.execute('''
                    SELECT phone_number, COUNT(*) as complaint_count
                    FROM ftc_complaints 
                    WHERE city = ? AND state = ? AND date_received >= ?
                    GROUP BY phone_number
                    ORDER BY complaint_count DESC
                    LIMIT ?
                ''', (location, state, recent_date, limit)).fetchall()
                
                active_numbers = [row[0] for row in results if row[0]]
                
        except Exception as e:
            print(f"Error getting active numbers: {e}")
        
        return active_numbers
    
    def _get_dominant_scam_type(self, location: str, state: str) -> str:
        """Get the most common scam type for a location."""
        try:
            with sqlite3.connect(self.ftc_db_path) as conn:
                recent_date = datetime.now() - timedelta(days=14)
                
                result = conn.execute('''
                    SELECT call_type, COUNT(*) as count
                    FROM ftc_complaints 
                    WHERE city = ? AND state = ? AND date_received >= ?
                    GROUP BY call_type
                    ORDER BY count DESC
                    LIMIT 1
                ''', (location, state, recent_date)).fetchone()
                
                return result[0] if result else 'unknown'
                
        except Exception as e:
            print(f"Error getting dominant scam type: {e}")
            return 'unknown'
    
    def _cache_hotspot(self, hotspot: HotspotData) -> bool:
        """Cache hotspot data."""
        try:
            expires_at = datetime.now() + timedelta(hours=6)  # 6-hour cache
            
            with sqlite3.connect(self.trends_db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO hotspots 
                    (location, state, latitude, longitude, intensity_score,
                     complaint_density, dominant_scam_type, active_numbers, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    hotspot.location, hotspot.state, hotspot.latitude, hotspot.longitude,
                    hotspot.intensity_score, hotspot.complaint_density,
                    hotspot.dominant_scam_type, json.dumps(hotspot.active_numbers),
                    expires_at
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error caching hotspot: {e}")
            return False
    
    def get_predictive_insights(self, location: str = None, state: str = None) -> Dict[str, Any]:
        """Get predictive insights about scam trends."""
        insights = {
            'trend_forecast': [],
            'risk_assessment': {},
            'recommendations': [],
            'emerging_patterns': []
        }
        
        try:
            with sqlite3.connect(self.trends_db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get historical data for trend forecasting
                thirty_days_ago = datetime.now() - timedelta(days=30)
                
                query = '''
                    SELECT location, state, snapshot_date, complaint_count, risk_score
                    FROM trend_snapshots 
                    WHERE snapshot_date >= ?
                '''
                params = [thirty_days_ago.date()]
                
                if location and state:
                    query += ' AND location = ? AND state = ?'
                    params.extend([location, state])
                
                query += ' ORDER BY snapshot_date DESC'
                
                results = conn.execute(query, params).fetchall()
                
                # Analyze trends
                location_trends = defaultdict(list)
                for row in results:
                    key = f"{row['location']}, {row['state']}"
                    location_trends[key].append({
                        'date': row['snapshot_date'],
                        'complaints': row['complaint_count'],
                        'risk': row['risk_score']
                    })
                
                # Generate forecasts
                for loc, data in location_trends.items():
                    if len(data) >= 7:  # Need at least a week of data
                        forecast = self._generate_forecast(data)
                        insights['trend_forecast'].append({
                            'location': loc,
                            'forecast': forecast
                        })
                
                # Risk assessment
                insights['risk_assessment'] = self._assess_current_risk()
                
                # Generate recommendations
                insights['recommendations'] = self._generate_recommendations(location_trends)
                
                # Detect emerging patterns
                insights['emerging_patterns'] = self._detect_emerging_patterns()
                
        except Exception as e:
            print(f"Error generating predictive insights: {e}")
        
        return insights
    
    def _generate_forecast(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate simple trend forecast."""
        if len(data) < 7:
            return {'error': 'Insufficient data'}
        
        # Simple moving average forecast
        recent_complaints = [d['complaints'] for d in data[:7]]
        recent_risk = [d['risk'] for d in data[:7]]
        
        avg_complaints = sum(recent_complaints) / len(recent_complaints)
        avg_risk = sum(recent_risk) / len(recent_risk)
        
        # Calculate trend
        if len(data) >= 14:
            older_complaints = [d['complaints'] for d in data[7:14]]
            older_avg = sum(older_complaints) / len(older_complaints)
            
            if older_avg > 0:
                trend_change = ((avg_complaints - older_avg) / older_avg) * 100
            else:
                trend_change = 0.0
        else:
            trend_change = 0.0
        
        return {
            'predicted_complaints': round(avg_complaints),
            'predicted_risk': round(avg_risk, 1),
            'trend_change_percent': round(trend_change, 1),
            'confidence': 'medium' if len(data) >= 14 else 'low'
        }
    
    def _assess_current_risk(self) -> Dict[str, Any]:
        """Assess current overall risk level."""
        try:
            with sqlite3.connect(self.trends_db_path) as conn:
                recent_date = datetime.now() - timedelta(days=7)
                
                result = conn.execute('''
                    SELECT AVG(risk_score) as avg_risk,
                           SUM(complaint_count) as total_complaints,
                           COUNT(DISTINCT location || ',' || state) as affected_locations
                    FROM trend_snapshots 
                    WHERE snapshot_date >= ?
                ''', (recent_date.date(),)).fetchone()
                
                if result and result[0]:
                    avg_risk = result[0]
                    total_complaints = result[1] or 0
                    affected_locations = result[2] or 0
                    
                    # Determine risk level
                    if avg_risk >= 8.0:
                        risk_level = 'high'
                    elif avg_risk >= 6.0:
                        risk_level = 'medium'
                    else:
                        risk_level = 'low'
                    
                    return {
                        'overall_risk_level': risk_level,
                        'average_risk_score': round(avg_risk, 1),
                        'total_complaints': total_complaints,
                        'affected_locations': affected_locations
                    }
                
        except Exception as e:
            print(f"Error assessing current risk: {e}")
        
        return {'overall_risk_level': 'unknown'}
    
    def _generate_recommendations(self, location_trends: Dict[str, List]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        # Analyze trends for recommendations
        high_risk_locations = []
        increasing_trend_locations = []
        
        for location, data in location_trends.items():
            if len(data) >= 3:
                recent_risk = sum(d['risk'] for d in data[:3]) / 3
                if recent_risk >= 7.5:
                    high_risk_locations.append(location)
                
                if len(data) >= 6:
                    recent_complaints = sum(d['complaints'] for d in data[:3])
                    older_complaints = sum(d['complaints'] for d in data[3:6])
                    
                    if recent_complaints > older_complaints * 1.2:
                        increasing_trend_locations.append(location)
        
        if high_risk_locations:
            recommendations.append(f"High-risk areas detected: {', '.join(high_risk_locations[:3])}. Consider increased monitoring.")
        
        if increasing_trend_locations:
            recommendations.append(f"Increasing scam activity in: {', '.join(increasing_trend_locations[:3])}. Alert residents.")
        
        if not recommendations:
            recommendations.append("Current scam activity levels are within normal ranges.")
        
        return recommendations
    
    def _detect_emerging_patterns(self) -> List[Dict[str, Any]]:
        """Detect emerging scam patterns."""
        patterns = []
        
        try:
            # Check for new scam types appearing frequently
            with sqlite3.connect(self.ftc_db_path) as conn:
                recent_date = datetime.now() - timedelta(days=7)
                
                results = conn.execute('''
                    SELECT call_type, COUNT(*) as count
                    FROM ftc_complaints 
                    WHERE date_received >= ?
                    GROUP BY call_type
                    HAVING count >= 5
                    ORDER BY count DESC
                ''', (recent_date,)).fetchall()
                
                for call_type, count in results:
                    patterns.append({
                        'type': 'emerging_scam_type',
                        'pattern': call_type,
                        'frequency': count,
                        'timeframe': '7 days'
                    })
                
        except Exception as e:
            print(f"Error detecting emerging patterns: {e}")
        
        return patterns[:5]  # Top 5 patterns
