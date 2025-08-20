"""
Geolocation intelligence service for EagleEye
Location-based threat analysis and geographic scam mapping
"""
import asyncio
import re
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class LocationType(Enum):
    """Types of geographic locations"""
    COUNTRY = "country"
    STATE = "state"
    CITY = "city"
    ZIP_CODE = "zip_code"
    IP_ADDRESS = "ip_address"
    PHONE_AREA = "phone_area"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Threat levels for geographic areas"""
    MINIMAL = "minimal"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LocationData:
    """Geographic location data with threat intelligence"""
    location_string: str
    location_type: LocationType
    country: str
    state: Optional[str]
    city: Optional[str]
    zip_code: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    threat_level: ThreatLevel
    scam_density: float
    recent_scam_count: int
    scam_types: List[str]
    risk_factors: List[str]
    population: Optional[int]
    analysis_timestamp: datetime


class GeolocationService:
    """Geolocation intelligence and threat mapping service"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.timeout = 10.0
        
        # High-risk geographic areas
        self.high_risk_countries = {
            'NG': 4.0, 'GH': 3.5, 'IN': 3.0, 'PK': 3.0, 'BD': 2.5, 'CN': 2.0, 'RU': 2.0
        }
        
        self.high_risk_us_states = {
            'FL': 2.5, 'CA': 2.0, 'NY': 2.0, 'TX': 1.8, 'NV': 1.5
        }
    
    async def analyze_location(self, location: str, context: Optional[str] = None) -> LocationData:
        """Analyze a location for scam threat intelligence"""
        location_type = self._determine_location_type(location)
        parsed_location = await self._parse_location(location, location_type)
        coordinates = await self._get_coordinates(parsed_location)
        threat_level, scam_density = self._calculate_threat_level(parsed_location, location_type)
        recent_scam_count, scam_types = await self._get_scam_statistics(parsed_location)
        risk_factors = self._identify_risk_factors(parsed_location, location_type, context)
        population = await self._get_population_data(parsed_location)
        
        return LocationData(
            location_string=location,
            location_type=location_type,
            country=parsed_location.get('country', 'Unknown'),
            state=parsed_location.get('state'),
            city=parsed_location.get('city'),
            zip_code=parsed_location.get('zip_code'),
            latitude=coordinates[0] if coordinates else None,
            longitude=coordinates[1] if coordinates else None,
            threat_level=threat_level,
            scam_density=scam_density,
            recent_scam_count=recent_scam_count,
            scam_types=scam_types,
            risk_factors=risk_factors,
            population=population,
            analysis_timestamp=datetime.now()
        )
    
    def _determine_location_type(self, location: str) -> LocationType:
        """Determine what type of location this is"""
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', location):
            return LocationType.IP_ADDRESS
        elif re.match(r'^\d{5}(-\d{4})?$', location):
            return LocationType.ZIP_CODE
        elif re.match(r'^\d{3}$', location):
            return LocationType.PHONE_AREA
        elif len(location.upper()) == 2:
            return LocationType.COUNTRY
        return LocationType.CITY
    
    async def _parse_location(self, location: str, location_type: LocationType) -> Dict[str, str]:
        """Parse location string into components"""
        if location_type == LocationType.ZIP_CODE:
            zip_map = {
                '10001': {'city': 'New York', 'state': 'NY', 'country': 'US'},
                '90210': {'city': 'Beverly Hills', 'state': 'CA', 'country': 'US'}
            }
            return zip_map.get(location, {'city': 'Unknown', 'state': 'Unknown', 'country': 'US'})
        elif location_type == LocationType.COUNTRY:
            return {'country': location.upper()}
        return {'city': location, 'country': 'Unknown'}
    
    async def _get_coordinates(self, parsed_location: Dict[str, str]) -> Optional[Tuple[float, float]]:
        """Get latitude/longitude coordinates (mock implementation)"""
        city_coords = {
            'New York': (40.7128, -74.0060),
            'Los Angeles': (34.0522, -118.2437),
            'Chicago': (41.8781, -87.6298)
        }
        city = parsed_location.get('city', '')
        return city_coords.get(city)
    
    def _calculate_threat_level(self, parsed_location: Dict[str, str], location_type: LocationType) -> Tuple[ThreatLevel, float]:
        """Calculate threat level and scam density for location"""
        risk_score = 1.0
        country = parsed_location.get('country', '').upper()
        if country in self.high_risk_countries:
            risk_score += self.high_risk_countries[country]
        
        scam_density = min(risk_score * 50, 500)
        
        if risk_score >= 5.0:
            return ThreatLevel.CRITICAL, scam_density
        elif risk_score >= 4.0:
            return ThreatLevel.HIGH, scam_density
        elif risk_score >= 3.0:
            return ThreatLevel.MODERATE, scam_density
        elif risk_score >= 2.0:
            return ThreatLevel.LOW, scam_density
        else:
            return ThreatLevel.MINIMAL, scam_density
    
    async def _get_scam_statistics(self, parsed_location: Dict[str, str]) -> Tuple[int, List[str]]:
        """Get recent scam statistics for location"""
        country = parsed_location.get('country', '').upper()
        if country == 'NG':
            return 156, ['advance_fee_fraud', 'romance_scam', 'lottery_scam']
        elif country == 'IN':
            return 89, ['tech_support_scam', 'fake_charity', 'phishing']
        return 12, ['phishing', 'fake_website']
    
    def _identify_risk_factors(self, parsed_location: Dict[str, str], location_type: LocationType, context: Optional[str]) -> List[str]:
        """Identify specific risk factors for this location"""
        risk_factors = []
        country = parsed_location.get('country', '').upper()
        
        if country in self.high_risk_countries:
            risk_factors.append(f"high_risk_country:{country}")
        
        if country == 'NG':
            risk_factors.extend(['advance_fee_fraud_origin', 'romance_scam_hub'])
        elif country == 'IN':
            risk_factors.extend(['tech_support_scam_center', 'call_center_fraud'])
        
        return risk_factors
    
    async def _get_population_data(self, parsed_location: Dict[str, str]) -> Optional[int]:
        """Get population data for location"""
        city_populations = {
            'New York': 8_336_817, 'Los Angeles': 3_979_576, 'Chicago': 2_693_976
        }
        city = parsed_location.get('city', '')
        return city_populations.get(city)

import sqlite3
import json
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

import httpx


@dataclass
class LocationData:
    """Geographic location information."""
    latitude: float
    longitude: float
    city: str
    state: str
    country: str
    zip_code: str = None
    county: str = None
    timezone: str = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'latitude': self.latitude,
            'longitude': self.longitude,
            'city': self.city,
            'state': self.state,
            'country': self.country,
            'zip_code': self.zip_code,
            'county': self.county,
            'timezone': self.timezone
        }


@dataclass
class GeofenceResult:
    """Result of geofence query."""
    center_lat: float
    center_lon: float
    radius_miles: float
    locations_in_fence: List[LocationData]
    bounding_box: Dict[str, float]
    cities_covered: List[str]
    states_covered: List[str]


class GeolocationCache:
    """Caching system for geolocation lookups."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize geolocation cache database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS location_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    lat REAL,
                    lon REAL,
                    city TEXT,
                    state TEXT,
                    country TEXT,
                    zip_code TEXT,
                    county TEXT,
                    timezone TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_lat_lon 
                ON location_cache(lat, lon)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_city_state 
                ON location_cache(city, state)
            ''')
            
            # US ZIP code database (simplified)
            conn.execute('''
                CREATE TABLE IF NOT EXISTS us_zipcodes (
                    zip_code TEXT PRIMARY KEY,
                    city TEXT,
                    state TEXT,
                    latitude REAL,
                    longitude REAL,
                    county TEXT,
                    timezone TEXT
                )
            ''')
            
            # Populate with sample ZIP codes
            self._populate_sample_zipcodes(conn)
    
    def _populate_sample_zipcodes(self, conn):
        """Populate database with sample ZIP code data."""
        sample_zipcodes = [
            ('10001', 'New York', 'NY', 40.7505, -73.9971, 'New York', 'America/New_York'),
            ('90210', 'Beverly Hills', 'CA', 34.0901, -118.4065, 'Los Angeles', 'America/Los_Angeles'),
            ('60601', 'Chicago', 'IL', 41.8825, -87.6441, 'Cook', 'America/Chicago'),
            ('77001', 'Houston', 'TX', 29.7604, -95.3698, 'Harris', 'America/Chicago'),
            ('33101', 'Miami', 'FL', 25.7617, -80.1918, 'Miami-Dade', 'America/New_York'),
            ('98101', 'Seattle', 'WA', 47.6062, -122.3321, 'King', 'America/Los_Angeles'),
            ('02101', 'Boston', 'MA', 42.3601, -71.0589, 'Suffolk', 'America/New_York'),
            ('30301', 'Atlanta', 'GA', 33.7490, -84.3880, 'Fulton', 'America/New_York'),
            ('85001', 'Phoenix', 'AZ', 33.4484, -112.0740, 'Maricopa', 'America/Phoenix'),
            ('19101', 'Philadelphia', 'PA', 39.9526, -75.1652, 'Philadelphia', 'America/New_York')
        ]
        
        for zipcode_data in sample_zipcodes:
            conn.execute('''
                INSERT OR IGNORE INTO us_zipcodes 
                (zip_code, city, state, latitude, longitude, county, timezone)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', zipcode_data)
        
        conn.commit()
    
    def cache_location(self, location: LocationData, ttl_hours: int = 24) -> bool:
        """Cache location data with TTL."""
        try:
            expires_at = datetime.now() + timedelta(hours=ttl_hours)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO location_cache 
                    (lat, lon, city, state, country, zip_code, county, timezone, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    location.latitude, location.longitude, location.city,
                    location.state, location.country, location.zip_code,
                    location.county, location.timezone, expires_at
                ))
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error caching location: {e}")
            return False
    
    def get_cached_location(self, lat: float, lon: float, 
                           tolerance: float = 0.01) -> Optional[LocationData]:
        """Get cached location within tolerance."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Find location within tolerance and not expired
                result = conn.execute('''
                    SELECT * FROM location_cache 
                    WHERE ABS(lat - ?) <= ? AND ABS(lon - ?) <= ?
                    AND expires_at > ?
                    ORDER BY (ABS(lat - ?) + ABS(lon - ?)) ASC
                    LIMIT 1
                ''', (lat, tolerance, lon, tolerance, datetime.now(), lat, lon)).fetchone()
                
                if result:
                    return LocationData(
                        latitude=result['lat'],
                        longitude=result['lon'],
                        city=result['city'],
                        state=result['state'],
                        country=result['country'],
                        zip_code=result['zip_code'],
                        county=result['county'],
                        timezone=result['timezone']
                    )
                
                return None
                
        except Exception as e:
            print(f"Error getting cached location: {e}")
            return None
    
    def lookup_zipcode(self, zip_code: str) -> Optional[LocationData]:
        """Lookup location by ZIP code."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                result = conn.execute('''
                    SELECT * FROM us_zipcodes WHERE zip_code = ?
                ''', (zip_code,)).fetchone()
                
                if result:
                    return LocationData(
                        latitude=result['latitude'],
                        longitude=result['longitude'],
                        city=result['city'],
                        state=result['state'],
                        country='US',
                        zip_code=result['zip_code'],
                        county=result['county'],
                        timezone=result['timezone']
                    )
                
                return None
                
        except Exception as e:
            print(f"Error looking up ZIP code: {e}")
            return None
    
    def find_nearby_zipcodes(self, lat: float, lon: float, 
                            radius_miles: float = 25) -> List[Dict[str, Any]]:
        """Find ZIP codes within radius."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Use Haversine formula approximation for nearby search
                # 1 degree ≈ 69 miles
                lat_delta = radius_miles / 69.0
                lon_delta = radius_miles / (69.0 * math.cos(math.radians(lat)))
                
                results = conn.execute('''
                    SELECT *, 
                           (? - latitude) * (? - latitude) + (? - longitude) * (? - longitude) as distance_sq
                    FROM us_zipcodes 
                    WHERE latitude BETWEEN ? AND ?
                    AND longitude BETWEEN ? AND ?
                    ORDER BY distance_sq
                    LIMIT 50
                ''', (
                    lat, lat, lon, lon,
                    lat - lat_delta, lat + lat_delta,
                    lon - lon_delta, lon + lon_delta
                )).fetchall()
                
                nearby = []
                for result in results:
                    # Calculate actual distance
                    distance = self._calculate_distance(
                        lat, lon, result['latitude'], result['longitude']
                    )
                    
                    if distance <= radius_miles:
                        nearby.append({
                            'zip_code': result['zip_code'],
                            'city': result['city'],
                            'state': result['state'],
                            'latitude': result['latitude'],
                            'longitude': result['longitude'],
                            'distance_miles': round(distance, 2)
                        })
                
                return nearby
                
        except Exception as e:
            print(f"Error finding nearby ZIP codes: {e}")
            return []
    
    def _calculate_distance(self, lat1: float, lon1: float, 
                           lat2: float, lon2: float) -> float:
        """Calculate distance between two points using Haversine formula."""
        R = 3959  # Earth's radius in miles
        
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)
        
        a = (math.sin(delta_lat / 2) ** 2 + 
             math.cos(lat1_rad) * math.cos(lat2_rad) * 
             math.sin(delta_lon / 2) ** 2)
        
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return R * c


class GeolocationService:
    """Main geolocation service."""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.cache = GeolocationCache(config_dir / "geolocation.db")
        
        # Rate limiting for external APIs
        self.rate_limit_delay = 1.0
        self.last_request_time = 0
    
    async def reverse_geocode(self, lat: float, lon: float) -> Optional[LocationData]:
        """Convert lat/lon to location information."""
        # Check cache first
        cached = self.cache.get_cached_location(lat, lon)
        if cached:
            return cached
        
        # Try external geocoding service
        location = await self._external_reverse_geocode(lat, lon)
        
        if location:
            # Cache the result
            self.cache.cache_location(location)
            return location
        
        # Fallback to approximate location based on nearby ZIP codes
        return self._approximate_location(lat, lon)
    
    async def _external_reverse_geocode(self, lat: float, lon: float) -> Optional[LocationData]:
        """Use external geocoding service (mock implementation)."""
        try:
            # In production, you would use services like:
            # - OpenStreetMap Nominatim (free)
            # - Google Geocoding API (requires key)
            # - MapBox Geocoding API (requires key)
            
            # Mock implementation based on approximate US regions
            location = self._mock_reverse_geocode(lat, lon)
            return location
            
        except Exception as e:
            print(f"External geocoding failed: {e}")
            return None
    
    def _mock_reverse_geocode(self, lat: float, lon: float) -> Optional[LocationData]:
        """Mock reverse geocoding for demonstration."""
        # Simple region-based approximation for US
        if 24.0 <= lat <= 49.0 and -125.0 <= lon <= -66.0:  # Continental US bounds
            # Determine approximate region
            if lat >= 40.0:  # Northern states
                if lon <= -100.0:  # Western
                    city, state = "Denver", "CO"
                else:  # Eastern
                    city, state = "New York", "NY"
            else:  # Southern states
                if lon <= -100.0:  # Western
                    city, state = "Phoenix", "AZ"
                else:  # Eastern
                    city, state = "Atlanta", "GA"
            
            return LocationData(
                latitude=lat,
                longitude=lon,
                city=city,
                state=state,
                country="US"
            )
        
        return None
    
    def _approximate_location(self, lat: float, lon: float) -> Optional[LocationData]:
        """Approximate location using nearby ZIP codes."""
        nearby_zips = self.cache.find_nearby_zipcodes(lat, lon, radius_miles=50)
        
        if nearby_zips:
            # Use the closest ZIP code
            closest = nearby_zips[0]
            return LocationData(
                latitude=lat,
                longitude=lon,
                city=closest['city'],
                state=closest['state'],
                country="US",
                zip_code=closest['zip_code']
            )
        
        return None
    
    def geocode_address(self, address: str) -> Optional[LocationData]:
        """Convert address to coordinates (simplified)."""
        # Parse common address formats
        address_lower = address.lower().strip()
        
        # Check if it's a ZIP code
        if address.isdigit() and len(address) == 5:
            return self.cache.lookup_zipcode(address)
        
        # Check for "City, State" format
        if ',' in address:
            parts = [part.strip() for part in address.split(',')]
            if len(parts) == 2:
                city, state = parts
                return self._lookup_city_state(city, state)
        
        return None
    
    def _lookup_city_state(self, city: str, state: str) -> Optional[LocationData]:
        """Lookup coordinates for city/state."""
        try:
            with sqlite3.connect(self.cache.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                result = conn.execute('''
                    SELECT * FROM us_zipcodes 
                    WHERE LOWER(city) = ? AND LOWER(state) = ?
                    LIMIT 1
                ''', (city.lower(), state.lower())).fetchone()
                
                if result:
                    return LocationData(
                        latitude=result['latitude'],
                        longitude=result['longitude'],
                        city=result['city'],
                        state=result['state'],
                        country='US',
                        zip_code=result['zip_code'],
                        county=result['county'],
                        timezone=result['timezone']
                    )
                
                return None
                
        except Exception as e:
            print(f"Error looking up city/state: {e}")
            return None
    
    def create_geofence(self, lat: float, lon: float, 
                       radius_miles: float) -> GeofenceResult:
        """Create geofence and find locations within it."""
        # Calculate bounding box
        lat_delta = radius_miles / 69.0
        lon_delta = radius_miles / (69.0 * math.cos(math.radians(lat)))
        
        bounding_box = {
            'north': lat + lat_delta,
            'south': lat - lat_delta,
            'east': lon + lon_delta,
            'west': lon - lon_delta
        }
        
        # Find locations within fence
        nearby_zips = self.cache.find_nearby_zipcodes(lat, lon, radius_miles)
        
        locations_in_fence = []
        cities_covered = set()
        states_covered = set()
        
        for zip_data in nearby_zips:
            location = LocationData(
                latitude=zip_data['latitude'],
                longitude=zip_data['longitude'],
                city=zip_data['city'],
                state=zip_data['state'],
                country='US',
                zip_code=zip_data['zip_code']
            )
            locations_in_fence.append(location)
            cities_covered.add(zip_data['city'])
            states_covered.add(zip_data['state'])
        
        return GeofenceResult(
            center_lat=lat,
            center_lon=lon,
            radius_miles=radius_miles,
            locations_in_fence=locations_in_fence,
            bounding_box=bounding_box,
            cities_covered=list(cities_covered),
            states_covered=list(states_covered)
        )
    
    def get_trending_locations(self, complaint_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze trending scam locations from complaint data."""
        location_counts = {}
        
        for complaint in complaint_data:
            state = complaint.get('state', '').upper()
            city = complaint.get('city', '').title()
            
            if state and city:
                location_key = f"{city}, {state}"
                if location_key not in location_counts:
                    location_counts[location_key] = {
                        'city': city,
                        'state': state,
                        'count': 0,
                        'recent_complaints': []
                    }
                
                location_counts[location_key]['count'] += 1
                location_counts[location_key]['recent_complaints'].append(complaint)
        
        # Sort by complaint count
        trending = sorted(
            location_counts.values(),
            key=lambda x: x['count'],
            reverse=True
        )
        
        # Add geographic data
        for location in trending[:20]:  # Top 20 locations
            geo_data = self._lookup_city_state(location['city'], location['state'])
            if geo_data:
                location['latitude'] = geo_data.latitude
                location['longitude'] = geo_data.longitude
                location['zip_code'] = geo_data.zip_code
        
        return trending[:20]
