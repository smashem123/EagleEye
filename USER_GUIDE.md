# ScamSwatter CLI User Guide 🛡️

**Complete Guide to Your Personal Scam Radar**

## Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Command Reference](#command-reference)
5. [Advanced Usage](#advanced-usage)
6. [Troubleshooting](#troubleshooting)
7. [API Sources](#api-sources)

---

## Installation

### Prerequisites
- Python 3.11 or higher
- Internet connection for API sources

### Install from Source
```bash
git clone https://github.com/scamswatter/scamswatter.git
cd scamswatter
pip install -r requirements.txt
```

### Verify Installation
```bash
python -m scamswatter --help
```

---

## Quick Start

### 1. First Run - Automatic Setup
```bash
python -m scamswatter config --show
```
**What happens:**
- Creates configuration directory (`~/.scamswatter/` on Linux/Mac, `%LOCALAPPDATA%\ScamSwatter\` on Windows)
- Generates default config file (`config.yml`)
- Initializes SQLite database (`scamswatter.db`)

### 2. Fetch Your First Scam Intelligence
```bash
python -m scamswatter fetch --limit 10
```
**What you'll see:**
- Beautiful ASCII banner with "Your Personal Scam Radar"
- Progress spinner while fetching data
- Rich table with scam intelligence data
- Success message with count of fetched records

### 3. View Database Statistics
```bash
python -m scamswatter stats
```
**Information displayed:**
- Total records in database
- Records from last 24 hours
- Top scam types with counts
- Active sources and their health status

---

## Configuration

### View Current Configuration
```bash
python -m scamswatter config --show
```

### Edit Configuration File
```bash
python -m scamswatter config --edit
```

### Set Individual Configuration Values
```bash
python -m scamswatter config --set refresh_interval=60
python -m scamswatter config --set color_scheme=minimal
python -m scamswatter config --set max_results=100
```

### Reset to Default Configuration
```bash
python -m scamswatter config --reset
```

### Configuration Options

#### API Keys
```yaml
phishtank_api_key: your_api_key_here
urlvoid_api_key: your_api_key_here
```

#### Display Settings
```yaml
color_scheme: security        # Options: security, minimal, colorful
show_timestamps: true         # Show when scams were first seen
show_source: true            # Show which API source provided data
compact_mode: false          # Use compact table layout
```

#### Data Sources
```yaml
preferred_sources:           # Which sources to use by default
  - phishtank
  - urlvoid
  - mock
```

#### Behavior Settings
```yaml
refresh_interval: 30         # Seconds between updates in watch mode
max_results: 50             # Default number of results to fetch
offline_mode: false         # Use only cached data
cache_duration: 3600        # How long to cache data (seconds)
max_cache_size: 10000       # Maximum cached records
```

---

## Command Reference

### `fetch` - Pull Latest Scam Intelligence

**Basic Usage:**
```bash
python -m scamswatter fetch
```

**Options:**
- `--source, -s`: Fetch from specific source only
- `--limit, -l`: Maximum number of scams to fetch (default: 50)
- `--type, -t`: Filter by scam type
- `--save/--no-save`: Save results to database (default: save)
- `--new`: Show only new scams since last fetch

**Examples:**
```bash
# Fetch 100 records from all sources
python -m scamswatter fetch --limit 100

# Fetch only phishing scams from PhishTank
python -m scamswatter fetch --source phishtank --type phishing

# Show only new scams since last check
python -m scamswatter fetch --new

# Fetch without saving to database
python -m scamswatter fetch --no-save
```

**Output Format:**
- Rich table with columns: Type, Title, Description, Source, Severity, First Seen, Location
- Color-coded severity levels (red for high, yellow for medium, gray for low)
- Progress indicators during API calls
- Success/error messages for each source

---

### `watch` - Real-Time Monitoring

**Basic Usage:**
```bash
python -m scamswatter watch
```

**Options:**
- `--interval, -i`: Refresh interval in seconds (default: 30)
- `--source, -s`: Monitor specific source only
- `--limit, -l`: Number of scams to display (default: 25)
- `--compact, -c`: Use compact display mode

**Examples:**
```bash
# Watch with 60-second refresh interval
python -m scamswatter watch --interval 60

# Monitor only PhishTank in compact mode
python -m scamswatter watch --source phishtank --compact

# Watch with more results displayed
python -m scamswatter watch --limit 50
```

**Features:**
- Live-updating terminal display
- Real-time scam feed with automatic refresh
- Statistics panel showing database info
- Press Ctrl+C to exit

**Display Layout:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    ScamSwatter - Live Monitoring                │
├─────────────────────────────────────┬───────────────────────────┤
│           Live Scam Feed            │     Database Stats        │
│  ┌─────┬─────────┬────────┬──────┐  │  Total Records: 1,234     │
│  │Type │ Title   │Severity│ Time │  │  Last 24h: 56             │
│  ├─────┼─────────┼────────┼──────┤  │                           │
│  │...  │ ...     │ ...    │ ...  │  │  Top Types:               │
│  └─────┴─────────┴────────┴──────┘  │  • phishing: 45           │
│                                     │  • fraud: 23              │
├─────────────────────────────────────┴───────────────────────────┤
│          Last updated: 14:30:25 | Press Ctrl+C to exit         │
└─────────────────────────────────────────────────────────────────┘
```

---

### `search` - Query Scam Database

**Basic Usage:**
```bash
python -m scamswatter search "paypal phishing"
```

**Options:**
- `--limit, -l`: Maximum number of results (default: 50)
- `--type, -t`: Filter by scam type
- `--source, -s`: Filter by source
- `--hours, -h`: Search within last N hours
- `--online`: Search online sources instead of local database

**Search Types:**

#### Local Database Search (Default)
```bash
# Search for keywords in title/description
python -m scamswatter search "investment fraud"

# Search with filters
python -m scamswatter search "phishing" --type phishing --hours 24

# Search specific source data
python -m scamswatter search "paypal" --source phishtank
```

#### Online Source Search
```bash
# Search online APIs for specific domain
python -m scamswatter search "suspicious-domain.com" --online

# Search multiple sources online
python -m scamswatter search "bitcoin scam" --online --limit 20
```

**Search Tips:**
- Use quotes for exact phrases: `"fake paypal"`
- Search by domain: `suspicious-site.com`
- Use keywords: `investment`, `phishing`, `robocall`
- Combine with filters for precise results

---

### `stats` - Database Statistics

**Basic Usage:**
```bash
python -m scamswatter stats
```

**Information Displayed:**

#### Database Statistics Panel
- **Total Records**: Complete count of scams in database
- **Last 24h**: New scams added in past day
- **Top Scam Types**: Most common scam categories with counts
- **Active Sources**: Data sources and their record counts

#### Configuration Panel
- Current theme and display settings
- Refresh interval and result limits
- Default location and preferred sources
- Offline mode status

#### Source Status
- **🟢 Healthy**: Source working normally
- **🟡 Not synced yet**: Source hasn't been used
- **🔴 X errors**: Source has connection issues
- Last sync timestamps for each source

**Example Output:**
```
╭─────────────── Database Statistics ───────────────╮
│ Total Records: 1,234                              │
│ Last 24h: 56                                      │
│                                                   │
│ Top Scam Types:                                   │
│   • phishing: 567                                │
│   • fraud: 234                                   │
│   • robocall: 123                                │
│                                                   │
│ Active Sources:                                   │
│   • MOCK: 234                                    │
│   • PHISHTANK: 567                              │
╰───────────────────────────────────────────────────╯
```

---

### `sources` - Manage API Sources

**List Available Sources:**
```bash
python -m scamswatter sources --list
```

**Test Source Connections:**
```bash
python -m scamswatter sources --test
```

**Available Sources:**

#### Mock Source
- **Purpose**: Testing and demonstration
- **Status**: Always available
- **Data**: Realistic fake scam records
- **Configuration**: None required

#### PhishTank
- **Purpose**: Community-driven phishing database
- **Status**: API key optional for basic features
- **Data**: Real phishing URLs and reports
- **Configuration**: Set `phishtank_api_key` in config

#### URLVoid
- **Purpose**: Website reputation checking
- **Status**: API key required
- **Data**: Domain reputation and malware detection
- **Configuration**: Set `urlvoid_api_key` in config

**Test Results:**
```bash
Testing Sources:
✓ MOCK: Connection successful
✓ PHISHTANK: Connection successful  
✗ URLVOID: API key required
```

---

## Advanced Usage

### Batch Operations

#### Fetch from Multiple Sources
```bash
# Fetch from all configured sources
python -m scamswatter fetch --limit 200

# Fetch from specific sources sequentially
python -m scamswatter fetch --source mock --limit 50
python -m scamswatter fetch --source phishtank --limit 50
```

#### Automated Monitoring Script
```bash
#!/bin/bash
# monitor-scams.sh - Run every hour via cron
python -m scamswatter fetch --new --limit 100
if [ $? -eq 0 ]; then
    echo "Scam intelligence updated successfully"
else
    echo "Failed to update scam intelligence"
fi
```

### Data Export and Integration

#### Search and Export Workflow
```bash
# Search for recent high-severity scams
python -m scamswatter search "phishing" --hours 24 --limit 100

# Use with other tools (example with jq for JSON processing)
python -m scamswatter fetch --limit 50 --no-save | grep -E "(phishing|fraud)"
```

### Custom Filtering

#### Complex Search Queries
```bash
# Find high-severity scams from specific timeframe
python -m scamswatter search "investment" --hours 48 --limit 200

# Search for location-specific scams
python -m scamswatter search "US" --type fraud --hours 72

# Find scams from specific sources
python -m scamswatter search "paypal" --source phishtank --online
```

### Performance Optimization

#### Database Maintenance
```bash
# The database automatically cleans old records
# Default retention: 30 days
# Configurable via cache_duration setting

# Monitor database size through stats
python -m scamswatter stats
```

#### Efficient Monitoring
```bash
# Use compact mode for better performance
python -m scamswatter watch --compact --limit 15

# Adjust refresh interval based on needs
python -m scamswatter watch --interval 60  # Less frequent updates
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Command Not Found
**Problem**: `python -m scamswatter` not recognized
**Solution**:
```bash
# Verify Python installation
python --version

# Check if in correct directory
cd /path/to/scamswatter

# Install dependencies
pip install -r requirements.txt
```

#### 2. API Connection Errors
**Problem**: Sources showing connection failures
**Solution**:
```bash
# Test individual sources
python -m scamswatter sources --test

# Check API key configuration
python -m scamswatter config --show

# Verify internet connection
ping google.com
```

#### 3. Database Issues
**Problem**: Database errors or corruption
**Solution**:
```bash
# Check database location
python -m scamswatter config --show

# Reset configuration (recreates database)
python -m scamswatter config --reset

# Manual database location:
# Windows: %LOCALAPPDATA%\ScamSwatter\scamswatter.db
# Linux/Mac: ~/.scamswatter/scamswatter.db
```

#### 4. Display Issues
**Problem**: Terminal output formatting problems
**Solution**:
```bash
# Try different color scheme
python -m scamswatter config --set color_scheme=minimal

# Use compact mode
python -m scamswatter fetch --limit 10
python -m scamswatter watch --compact

# Check terminal compatibility
echo $TERM  # Linux/Mac
```

#### 5. Performance Issues
**Problem**: Slow response or high memory usage
**Solution**:
```bash
# Reduce result limits
python -m scamswatter config --set max_results=25

# Increase cache duration to reduce API calls
python -m scamswatter config --set cache_duration=7200

# Use specific sources only
python -m scamswatter fetch --source mock --limit 20
```

### Debug Mode
```bash
# Enable verbose output (if implemented)
export SCAMSWATTER_DEBUG=1
python -m scamswatter fetch --limit 5

# Check log files (if logging implemented)
# Location: ~/.scamswatter/logs/
```

### Getting Help
```bash
# Command-specific help
python -m scamswatter fetch --help
python -m scamswatter watch --help
python -m scamswatter search --help

# General help
python -m scamswatter --help

# Version information
python -m scamswatter --version
```

---

## API Sources

### PhishTank Integration

#### Getting API Key
1. Visit [PhishTank Developer Portal](https://www.phishtank.com/developer_info.php)
2. Register for free account
3. Generate API key
4. Configure in ScamSwatter:
```bash
python -m scamswatter config --set phishtank_api_key=YOUR_KEY_HERE
```

#### Data Format
- **Phishing URLs**: Community-reported malicious links
- **Verification Status**: Community-verified vs. unverified reports
- **Target Information**: What service/company is being impersonated
- **Submission Time**: When the phishing URL was first reported

#### Rate Limits
- Free tier: 1000 requests per hour
- Automatic retry with exponential backoff
- Rate limiting handled automatically

### URLVoid Integration

#### Getting API Key
1. Visit [URLVoid API](https://www.urlvoid.com/api/)
2. Choose subscription plan
3. Get API key from dashboard
4. Configure in ScamSwatter:
```bash
python -m scamswatter config --set urlvoid_api_key=YOUR_KEY_HERE
```

#### Data Format
- **Domain Reputation**: Aggregated security engine results
- **Malware Detection**: Multiple antivirus engine results
- **Blacklist Status**: Various security blacklists
- **Safety Score**: Composite safety rating

#### Usage Patterns
- Best for checking specific domains/URLs
- Use with search command for domain verification
- Automatic detection count analysis

### Mock Source (Testing)

#### Purpose
- Demonstrates ScamSwatter functionality
- Provides realistic test data
- No API key required
- Always available for testing

#### Data Generation
- Realistic scam scenarios (phishing, fraud, robocalls)
- Random severity scores and locations
- Simulated timestamps and verification status
- Variety of scam types for comprehensive testing

### Adding New Sources

#### Developer Guide
1. Create new source class in `scamswatter/sources/`
2. Inherit from `ScamSource` base class
3. Implement required methods:
   - `fetch_recent_scams()`
   - `search_scams()`
   - `is_configured()`
4. Add to source registry in `__init__.py`
5. Update configuration options

#### Example Source Structure
```python
class NewSource(ScamSource):
    def __init__(self, api_key=None):
        super().__init__("newsource", api_key)
        self.base_url = "https://api.newsource.com"
    
    async def fetch_recent_scams(self, limit=50):
        # Implementation here
        pass
    
    def is_configured(self):
        return self.api_key is not None
```

---

## Best Practices

### Security
- Store API keys in configuration file only
- Never commit API keys to version control
- Use environment variables for sensitive data
- Regularly rotate API keys

### Performance
- Use appropriate refresh intervals for monitoring
- Limit result counts for better performance
- Enable caching for frequently accessed data
- Monitor database size and clean old records

### Workflow Integration
- Use cron jobs for automated monitoring
- Integrate with security incident response tools
- Export data for analysis in other tools
- Set up alerting for high-severity scams

### Data Management
- Regularly review and clean cached data
- Monitor API usage and rate limits
- Backup important scam intelligence data
- Document custom configurations and workflows

---

*This guide covers all ScamSwatter CLI functionality. For additional support, visit the project repository or file an issue.*
