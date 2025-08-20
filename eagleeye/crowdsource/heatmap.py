"""
Real-time scam heatmap with regional trend analysis
Visualizes scam activity patterns by geographic region
"""
import asyncio
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from collections import defaultdict

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class RegionalData:
    """Regional scam data for heatmap"""
    region: str
    country: str
    latitude: float
    longitude: float
    total_reports: int
    verified_reports: int
    scam_types: Dict[str, int]
    risk_level: str
    last_updated: datetime
    trend_direction: str  # 'increasing', 'decreasing', 'stable'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'region': self.region,
            'country': self.country,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'total_reports': self.total_reports,
            'verified_reports': self.verified_reports,
            'scam_types': self.scam_types,
            'risk_level': self.risk_level,
            'last_updated': self.last_updated.isoformat(),
            'trend_direction': self.trend_direction
        }


class ScamHeatmap:
    """Generates real-time scam heatmaps and regional analysis"""
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or Path.home() / ".eagleeye" / "crowdsource.db"
        self.geoip_db_path = Path.home() / ".eagleeye" / "GeoLite2-City.mmdb"
        
        # IP geolocation service fallback
        self.ip_api_url = "http://ip-api.com/json/"
        
        # Risk level thresholds
        self.risk_thresholds = {
            'low': 5,
            'medium': 20,
            'high': 50,
            'critical': 100
        }
    
    def _get_coordinates_from_location(self, location: str) -> Tuple[float, float]:
        """Get coordinates from location string"""
        # Simple coordinate mapping for common locations
        location_coords = {
            'united states': (39.8283, -98.5795),
            'canada': (56.1304, -106.3468),
            'united kingdom': (55.3781, -3.4360),
            'germany': (51.1657, 10.4515),
            'france': (46.2276, 2.2137),
            'australia': (-25.2744, 133.7751),
            'japan': (36.2048, 138.2529),
            'china': (35.8617, 104.1954),
            'india': (20.5937, 78.9629),
            'brazil': (-14.2350, -51.9253),
            'russia': (61.5240, 105.3188),
            'mexico': (23.6345, -102.5528),
            'italy': (41.8719, 12.5674),
            'spain': (40.4637, -3.7492),
            'netherlands': (52.1326, 5.2913),
            'sweden': (60.1282, 18.6435),
            'norway': (60.4720, 8.4689),
            'denmark': (56.2639, 9.5018),
            'finland': (61.9241, 25.7482),
            'poland': (51.9194, 19.1451),
            'south korea': (35.9078, 127.7669),
            'singapore': (1.3521, 103.8198),
            'new zealand': (-40.9006, 174.8860),
            'south africa': (-30.5595, 22.9375),
            'nigeria': (9.0820, 8.6753),
            'egypt': (26.0975, 30.0444),
            'turkey': (38.9637, 35.2433),
            'israel': (31.0461, 34.8516),
            'saudi arabia': (23.8859, 45.0792),
            'uae': (23.4241, 53.8478),
            'thailand': (15.8700, 100.9925),
            'vietnam': (14.0583, 108.2772),
            'philippines': (12.8797, 121.7740),
            'indonesia': (-0.7893, 113.9213),
            'malaysia': (4.2105, 101.9758),
            'argentina': (-38.4161, -63.6167),
            'chile': (-35.6751, -71.5430),
            'colombia': (4.5709, -74.2973),
            'peru': (-9.1900, -75.0152),
            'venezuela': (6.4238, -66.5897)
        }
        
        location_lower = location.lower().strip()
        
        # Direct lookup
        if location_lower in location_coords:
            return location_coords[location_lower]
        
        # Partial matching for cities/states
        for loc, coords in location_coords.items():
            if loc in location_lower or location_lower in loc:
                return coords
        
        # Default to center of world if no match
        return (0.0, 0.0)
    
    def _determine_risk_level(self, total_reports: int, verified_reports: int) -> str:
        """Determine risk level based on report counts"""
        # Use verified reports for more accurate assessment
        base_score = verified_reports if verified_reports > 0 else total_reports * 0.3
        
        if base_score >= self.risk_thresholds['critical']:
            return 'critical'
        elif base_score >= self.risk_thresholds['high']:
            return 'high'
        elif base_score >= self.risk_thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_trend(self, region: str, days: int = 7) -> str:
        """Calculate trend direction for a region"""
        cutoff_date = datetime.now() - timedelta(days=days)
        older_cutoff = cutoff_date - timedelta(days=days)
        
        with sqlite3.connect(self.db_path) as conn:
            # Recent reports
            cursor = conn.execute("""
                SELECT COUNT(*) FROM user_reports 
                WHERE location = ? AND timestamp >= ?
            """, (region, cutoff_date.isoformat()))
            recent_count = cursor.fetchone()[0]
            
            # Older reports for comparison
            cursor = conn.execute("""
                SELECT COUNT(*) FROM user_reports 
                WHERE location = ? AND timestamp >= ? AND timestamp < ?
            """, (region, older_cutoff.isoformat(), cutoff_date.isoformat()))
            older_count = cursor.fetchone()[0]
            
            if recent_count > older_count * 1.2:
                return 'increasing'
            elif recent_count < older_count * 0.8:
                return 'decreasing'
            else:
                return 'stable'
    
    async def generate_heatmap_data(self, days: int = 30) -> List[RegionalData]:
        """Generate heatmap data for the specified time period"""
        cutoff_date = datetime.now() - timedelta(days=days)
        regional_data = []
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get regional statistics
            cursor = conn.execute("""
                SELECT region, total_reports, verified_reports, scam_types, last_updated
                FROM regional_stats
                WHERE total_reports > 0
                ORDER BY total_reports DESC
            """)
            
            for row in cursor.fetchall():
                region = row['region']
                if not region:
                    continue
                
                # Get coordinates
                lat, lon = self._get_coordinates_from_location(region)
                
                # Parse scam types
                scam_types = json.loads(row['scam_types']) if row['scam_types'] else {}
                
                # Determine risk level
                risk_level = self._determine_risk_level(
                    row['total_reports'], 
                    row['verified_reports']
                )
                
                # Calculate trend
                trend = self._calculate_trend(region)
                
                # Determine country from region
                country = self._extract_country_from_region(region)
                
                regional_data.append(RegionalData(
                    region=region,
                    country=country,
                    latitude=lat,
                    longitude=lon,
                    total_reports=row['total_reports'],
                    verified_reports=row['verified_reports'],
                    scam_types=scam_types,
                    risk_level=risk_level,
                    last_updated=datetime.fromisoformat(row['last_updated']),
                    trend_direction=trend
                ))
        
        return regional_data
    
    def _extract_country_from_region(self, region: str) -> str:
        """Extract country name from region string"""
        region_lower = region.lower()
        
        # Common country patterns
        countries = {
            'united states': ['usa', 'us', 'america', 'united states'],
            'united kingdom': ['uk', 'britain', 'england', 'scotland', 'wales'],
            'canada': ['canada', 'canadian'],
            'australia': ['australia', 'australian'],
            'germany': ['germany', 'german', 'deutschland'],
            'france': ['france', 'french'],
            'japan': ['japan', 'japanese'],
            'china': ['china', 'chinese'],
            'india': ['india', 'indian'],
            'brazil': ['brazil', 'brazilian'],
            'russia': ['russia', 'russian'],
            'mexico': ['mexico', 'mexican'],
            'italy': ['italy', 'italian'],
            'spain': ['spain', 'spanish'],
            'netherlands': ['netherlands', 'dutch', 'holland'],
            'sweden': ['sweden', 'swedish'],
            'norway': ['norway', 'norwegian'],
            'denmark': ['denmark', 'danish'],
            'finland': ['finland', 'finnish'],
            'poland': ['poland', 'polish']
        }
        
        for country, patterns in countries.items():
            if any(pattern in region_lower for pattern in patterns):
                return country
        
        return region  # Return original if no match
    
    async def get_trending_scams(self, days: int = 7, limit: int = 10) -> List[Dict[str, Any]]:
        """Get trending scam types by region"""
        cutoff_date = datetime.now() - timedelta(days=days)
        
        trending_data = []
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get recent reports grouped by location and scam type
            cursor = conn.execute("""
                SELECT location, analysis_results, COUNT(*) as report_count
                FROM user_reports 
                WHERE timestamp >= ? AND location IS NOT NULL
                GROUP BY location, analysis_results
                HAVING report_count >= 2
                ORDER BY report_count DESC
                LIMIT ?
            """, (cutoff_date.isoformat(), limit * 3))
            
            location_scams = defaultdict(lambda: defaultdict(int))
            
            for row in cursor.fetchall():
                location = row['location']
                try:
                    analysis = json.loads(row['analysis_results'])
                    scam_type = analysis.get('scam_type', 'unknown')
                    location_scams[location][scam_type] += row['report_count']
                except:
                    continue
            
            # Format trending data
            for location, scam_counts in location_scams.items():
                for scam_type, count in scam_counts.items():
                    if count >= 2:  # Minimum threshold for trending
                        lat, lon = self._get_coordinates_from_location(location)
                        
                        trending_data.append({
                            'location': location,
                            'scam_type': scam_type,
                            'report_count': count,
                            'latitude': lat,
                            'longitude': lon,
                            'trend_score': count * (days / 7)  # Adjust for time period
                        })
        
        # Sort by trend score and limit results
        trending_data.sort(key=lambda x: x['trend_score'], reverse=True)
        return trending_data[:limit]
    
    async def get_global_statistics(self) -> Dict[str, Any]:
        """Get global scam statistics"""
        with sqlite3.connect(self.db_path) as conn:
            # Total reports
            cursor = conn.execute("SELECT COUNT(*) FROM user_reports")
            total_reports = cursor.fetchone()[0]
            
            # Verified reports
            cursor = conn.execute("SELECT COUNT(*) FROM user_reports WHERE status = 'verified'")
            verified_reports = cursor.fetchone()[0]
            
            # Recent reports (last 24 hours)
            cutoff_24h = datetime.now() - timedelta(hours=24)
            cursor = conn.execute("""
                SELECT COUNT(*) FROM user_reports WHERE timestamp >= ?
            """, (cutoff_24h.isoformat(),))
            recent_24h = cursor.fetchone()[0]
            
            # Most active regions
            cursor = conn.execute("""
                SELECT location, COUNT(*) as count 
                FROM user_reports 
                WHERE location IS NOT NULL 
                GROUP BY location 
                ORDER BY count DESC 
                LIMIT 5
            """)
            top_regions = [{'region': row[0], 'reports': row[1]} for row in cursor.fetchall()]
            
            # Most common scam types
            scam_type_counts = defaultdict(int)
            cursor = conn.execute("SELECT analysis_results FROM user_reports WHERE status = 'verified'")
            
            for row in cursor.fetchall():
                try:
                    analysis = json.loads(row[0])
                    scam_type = analysis.get('scam_type', 'unknown')
                    scam_type_counts[scam_type] += 1
                except:
                    continue
            
            top_scam_types = sorted(scam_type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            
            return {
                'total_reports': total_reports,
                'verified_reports': verified_reports,
                'verification_rate': (verified_reports / max(total_reports, 1)) * 100,
                'recent_24h': recent_24h,
                'top_regions': top_regions,
                'top_scam_types': [{'type': t[0], 'count': t[1]} for t in top_scam_types],
                'last_updated': datetime.now().isoformat()
            }
    
    async def generate_heatmap_html(self, output_file: Optional[str] = None) -> str:
        """Generate HTML heatmap visualization"""
        heatmap_data = await self.generate_heatmap_data()
        trending_scams = await self.get_trending_scams()
        global_stats = await self.get_global_statistics()
        
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>EagleEye Scam Heatmap</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
    <style>
        body { margin: 0; padding: 0; font-family: Arial, sans-serif; }
        #map { height: 70vh; }
        #stats { padding: 20px; background: #f5f5f5; }
        .stat-box { display: inline-block; margin: 10px; padding: 15px; background: white; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .risk-critical { color: #d32f2f; }
        .risk-high { color: #f57c00; }
        .risk-medium { color: #fbc02d; }
        .risk-low { color: #388e3c; }
        .trend-increasing { color: #d32f2f; }
        .trend-decreasing { color: #388e3c; }
        .trend-stable { color: #757575; }
    </style>
</head>
<body>
    <div id="stats">
        <h1>🛡️ EagleEye Global Scam Intelligence</h1>
        <div class="stat-box">
            <h3>Total Reports</h3>
            <p>{total_reports}</p>
        </div>
        <div class="stat-box">
            <h3>Verified Reports</h3>
            <p>{verified_reports} ({verification_rate:.1f}%)</p>
        </div>
        <div class="stat-box">
            <h3>Last 24 Hours</h3>
            <p>{recent_24h} reports</p>
        </div>
        <div class="stat-box">
            <h3>Top Scam Types</h3>
            <ul>
                {top_scam_types}
            </ul>
        </div>
    </div>
    
    <div id="map"></div>
    
    <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
    <script>
        var map = L.map('map').setView([20, 0], 2);
        
        L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
            attribution: '© OpenStreetMap contributors'
        }}).addTo(map);
        
        var heatmapData = {heatmap_data};
        
        heatmapData.forEach(function(point) {{
            var color = point.risk_level === 'critical' ? '#d32f2f' :
                       point.risk_level === 'high' ? '#f57c00' :
                       point.risk_level === 'medium' ? '#fbc02d' : '#388e3c';
            
            var radius = Math.max(5, Math.min(50, point.total_reports * 2));
            
            var circle = L.circle([point.latitude, point.longitude], {{
                color: color,
                fillColor: color,
                fillOpacity: 0.6,
                radius: radius * 1000
            }}).addTo(map);
            
            var popupContent = '<b>' + point.region + '</b><br>' +
                              'Total Reports: ' + point.total_reports + '<br>' +
                              'Verified: ' + point.verified_reports + '<br>' +
                              'Risk Level: <span class="risk-' + point.risk_level + '">' + point.risk_level.toUpperCase() + '</span><br>' +
                              'Trend: <span class="trend-' + point.trend_direction + '">' + point.trend_direction + '</span><br>' +
                              'Top Scam Types: ' + Object.keys(point.scam_types).slice(0, 3).join(', ');
            
            circle.bindPopup(popupContent);
        }});
        
        // Add trending scams as markers
        var trendingData = {trending_data};
        trendingData.forEach(function(trend) {{
            var marker = L.marker([trend.latitude, trend.longitude]).addTo(map);
            marker.bindPopup('<b>Trending: ' + trend.scam_type + '</b><br>' +
                           'Location: ' + trend.location + '<br>' +
                           'Reports: ' + trend.report_count);
        }});
    </script>
</body>
</html>
        """
        
        # Format data for template
        top_scam_types_html = "".join([
            f"<li>{item['type']}: {item['count']}</li>" 
            for item in global_stats['top_scam_types']
        ])
        
        html_content = html_template.format(
            total_reports=global_stats['total_reports'],
            verified_reports=global_stats['verified_reports'],
            verification_rate=global_stats['verification_rate'],
            recent_24h=global_stats['recent_24h'],
            top_scam_types=top_scam_types_html,
            heatmap_data=json.dumps([data.to_dict() for data in heatmap_data]),
            trending_data=json.dumps(trending_scams)
        )
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
        
        return html_content
