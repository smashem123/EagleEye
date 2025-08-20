# EagleEye CLI User Guide 🛡️

**Complete Guide to Your Personal Scam Radar**

## Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Text Analysis Features](#text-analysis-features)
5. [Machine Learning Models](#machine-learning-models)
6. [Command Reference](#command-reference)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)
9. [API Sources](#api-sources)

---

## Installation & Setup

### Prerequisites
- Python 3.11 or higher
- Internet connection for fetching scam data
- Terminal/command prompt access

### Install Dependencies
```bash
pip install -r requirements.txt

# Install spaCy language model for NLP analysis
python -m spacy download en_core_web_sm

# Optional: Install additional audio dependencies for voice analysis
# pip install pyaudio  # For live audio recording

# Optional: Install GeoIP2 database for enhanced geolocation
# Download GeoLite2-City.mmdb from MaxMind (free account required)
```

### Install from Source
```bash
git clone https://github.com/yourusername/eagleeye.git
cd eagleeye
pip install -r requirements.txt
```

### Verify Installation
```bash
python run_eagleeye.py help
```

---

## Quick Start

### 1. First Run - Automatic Setup
```bash
python run_eagleeye.py config
```
**What happens:**
- Creates configuration directory (`~/.eagleeye/` on Linux/Mac, `%LOCALAPPDATA%\EagleEye\` on Windows)
- Generates default config file (`config.yml`)
- Initializes SQLite database (`eagleeye.db`)

### 2. Fetch Your First Scam Intelligence
```bash
python run_eagleeye.py fetch
```
**What you'll see:**
- Beautiful EagleEye ASCII banner with "Your Personal Scam Radar"
- Progress spinner while fetching data
- Rich table with scam intelligence data including location information
- Success message with count of fetched records from multiple sources

### 3. View Database Statistics
```bash
python run_eagleeye.py stats
```
**Information displayed:**
- Total records in database
- Records from last 24 hours
- Top scam types with counts
- Active sources and their health status
- PyOpenPhishDB local database statistics
- AI-detected vs known database entries

---

## Configuration

## Text Analysis Features

EagleEye now includes advanced **real-time text analysis** capabilities:

### Analyze Text Content
```bash
python run_eagleeye.py analyze --text "Your suspicious text here"
```

### Analyze Website Content
```bash
python run_eagleeye.py analyze --url "https://suspicious-website.com"
```

### Analyze Email Files
```bash
python run_eagleeye.py analyze --email "suspicious_email.txt"
```

### Output Formats
```bash
# Table format (default)
python run_eagleeye.py analyze --text "..." --format table

# JSON format for automation
python run_eagleeye.py analyze --text "..." --format json
```

**What the Analysis Provides:**
- **Scam Type Detection**: Phishing, romance, investment, tech support, etc.
- **Risk Scoring**: 0-10 threat level assessment
- **Confidence Levels**: AI model certainty ratings
- **Sentiment Analysis**: Emotional manipulation detection
- **Entity Extraction**: Credit cards, SSNs, phone numbers, emails
- **Pattern Recognition**: Urgency markers, authority claims
- **Language Analysis**: Grammar issues, suspicious phrases
- **ML Classification**: Machine learning predictions

---

### View Current Configuration
```bash
python run_eagleeye.py config --show
```

### Edit Configuration File
```bash
python -m eagleeye config --edit
```

### Set Individual Configuration Values
```bash
python -m eagleeye config --set refresh_interval=60
python -m eagleeye config --set color_scheme=minimal
python -m eagleeye config --set max_results=100
```

### Reset to Default Configuration
```bash
python -m eagleeye config --reset
```

### Configuration Options

#### API Keys
```yaml
openphish_api_key: your_api_key_here
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
  - openphish
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

## Machine Learning Models

EagleEye includes advanced machine learning capabilities for automated scam detection. The ML system uses sophisticated feature engineering and multiple algorithms to identify scam patterns.

### Overview

The ML system analyzes:
- **Text Content**: Language patterns, urgency indicators, threat words, money-related terms
- **URLs**: Domain characteristics, security indicators, suspicious patterns
- **Phone Numbers**: Validation, geographic info, carrier analysis, pattern detection

### Supported Algorithms

- **Random Forest** - Ensemble method, good for mixed data types
- **Gradient Boosting** - Strong performance on structured features
- **Logistic Regression** - Fast, interpretable linear model
- **Support Vector Machine (SVM)** - Effective for high-dimensional data
- **Naive Bayes** - Good baseline for text classification

### Training Models

**Basic Training:**
```bash
# Train a Random Forest model (default)
python run_eagleeye.py train

# Train with specific algorithm
python run_eagleeye.py train --model gradient_boost

# Enable hyperparameter optimization (slower but better performance)
python run_eagleeye.py train --model random_forest --optimize
```

**Advanced Training:**
```bash
# Train with custom parameters
python run_eagleeye.py train \
  --model gradient_boost \
  --optimize \
  --min-samples 200 \
  --description "Production model v2.1" \
  --tags "production,optimized"
```

### Making Predictions

**Basic Prediction:**
```bash
# Analyze text content
python run_eagleeye.py predict --text "Congratulations! You've won $10,000!"

# Analyze URLs
python run_eagleeye.py predict --url "https://suspicious-domain.com/login"

# Analyze phone numbers
python run_eagleeye.py predict --phone "+1-800-555-SCAM"

# Combined analysis
python run_eagleeye.py predict \
  --text "Call now to claim your prize!" \
  --phone "8005551234" \
  --url "https://claim-prize.net"
```

**Using Specific Models:**
```bash
# Use a specific model version
python run_eagleeye.py predict \
  --text "Your account will be suspended" \
  --model-id random_forest_20241220_143015
```

### Model Management

**List Models:**
```bash
# List all models
python run_eagleeye.py models

# Filter by type
python run_eagleeye.py models --type random_forest

# Show detailed statistics
python run_eagleeye.py models --stats
```

**Model Operations:**
```bash
# Set active model for predictions
python run_eagleeye.py models --set-active model_id_here

# Compare two models
python run_eagleeye.py models --compare model1_id,model2_id

# Delete old model
python run_eagleeye.py models --delete old_model_id

# Clean up old models (keeps recent and best performing)
python run_eagleeye.py models --cleanup
```

### Model Performance Metrics

Models are evaluated using:
- **Accuracy**: Overall correctness percentage
- **Precision**: True positive rate (avoiding false alarms)
- **Recall**: Detection rate (catching actual scams)
- **F1 Score**: Balanced measure of precision and recall
- **AUC Score**: Area under ROC curve (binary classification performance)

### Feature Engineering

The ML system extracts comprehensive features:

**Text Features:**
- Character, word, and sentence counts
- Language patterns (uppercase ratio, punctuation density)
- Scam indicators (urgency words, money terms, threats)
- Communication patterns (exclamations, questions, caps sequences)
- Contact extraction (phone numbers, emails, URLs)

**URL Features:**
- Structural analysis (length, subdomains, path complexity)
- Security indicators (HTTPS usage, suspicious TLDs)
- Domain characteristics (IP addresses, suspicious keywords)
- Reputation signals (shortened URLs, known bad domains)

**Phone Features:**
- Number validation and formatting
- Geographic and carrier information
- Number type classification (mobile, VoIP, toll-free)
- Pattern analysis (repetitive digits, unusual sequences)

### Best Practices

1. **Training Data**: Ensure you have sufficient scam records in your database (minimum 100 samples)
2. **Model Selection**: Start with Random Forest for balanced performance
3. **Hyperparameter Optimization**: Use `--optimize` for production models
4. **Regular Retraining**: Retrain models as new scam patterns emerge
5. **Model Comparison**: Compare different algorithms to find the best performer
6. **Version Management**: Use descriptive tags and maintain model history

### Troubleshooting ML Issues

**Common Issues:**

```bash
# Insufficient training data
# Solution: Fetch more scam data first
python run_eagleeye.py fetch --limit 1000

# Model not found
# Solution: Check available models
python run_eagleeye.py models --list

# Poor performance
# Solution: Try hyperparameter optimization
python run_eagleeye.py train --optimize

# Memory issues with large datasets
# Solution: Reduce training samples
python run_eagleeye.py train --min-samples 500
```

---

## Command Reference

### `analyze` - Real-Time Text Analysis

**Basic Usage:**
```bash
python run_eagleeye.py analyze --text "Your suspicious text here"
```

**Options:**
- `--text, -t`: Analyze text content directly
- `--url, -u`: Analyze website content
- `--email, -e`: Analyze email file content
- `--voice, -v`: Analyze voice/audio file
- `--format, -f`: Output format (table/json, default: table)

**Examples:**
```bash
# Analyze suspicious text
python run_eagleeye.py analyze --text "Congratulations! You've won $1000000!"

# Analyze website content
python run_eagleeye.py analyze --url "https://suspicious-site.com"

# Analyze email file
python run_eagleeye.py analyze --email "phishing_email.txt"

# Analyze voice recording
python run_eagleeye.py analyze --voice "robocall.wav"

# Get JSON output for automation
python run_eagleeye.py analyze --text "..." --format json
```

**Analysis Features:**
- **Scam Type Detection**: Phishing, romance, investment, tech support, etc.
- **Risk Scoring**: 0-10 threat level assessment
- **Confidence Levels**: AI model certainty ratings
- **Sentiment Analysis**: Emotional manipulation detection
- **Entity Extraction**: Credit cards, SSNs, phone numbers, emails
- **Pattern Recognition**: Urgency markers, authority claims
- **Voice Analysis**: Robocall detection, voice features, transcription

---

### `report` - Submit Scam Reports

**Basic Usage:**
```bash
python run_eagleeye.py report --text "Scam content here"
```

**Options:**
- `--text, -t`: Report text-based scam
- `--voice, -v`: Report voice/audio scam
- `--email, -e`: Report email scam
- `--url, -u`: Report website scam
- `--location, -l`: Your location (city, state/country)
- `--phone`: Phone number associated with scam
- `--description, -d`: Additional description

**Examples:**
```bash
# Report phishing text
python run_eagleeye.py report --text "Fake bank alert" --location "New York, NY"

# Report robocall
python run_eagleeye.py report --voice "robocall.wav" --phone "+1234567890"

# Report phishing email
python run_eagleeye.py report --email "phishing.eml" --description "Fake PayPal alert"

# Report suspicious website
python run_eagleeye.py report --url "https://fake-bank.com" --location "California, USA"
```

**Community Features:**
- Reports are analyzed automatically using AI
- Community can verify/reject reports
- Contributes to regional scam statistics
- Helps improve detection models

---

### `heatmap` - Scam Trend Visualization

**Basic Usage:**
```bash
python run_eagleeye.py heatmap
```

**Options:**
- `--trending, -t`: Show only trending scam areas
- `--output, -o`: Save heatmap to HTML file
- `--region, -r`: Focus on specific region

**Examples:**
```bash
# Generate interactive heatmap
python run_eagleeye.py heatmap

# Show only trending areas
python run_eagleeye.py heatmap --trending

# Save heatmap to file
python run_eagleeye.py heatmap --output scam_heatmap.html

# Focus on specific region
python run_eagleeye.py heatmap --region "California"
```

**Heatmap Features:**
- **Regional Risk Levels**: Color-coded scam intensity
- **Trend Analysis**: Increasing/decreasing scam activity
- **Interactive Map**: Click regions for detailed stats
- **Real-time Data**: Based on community reports
- **Export Options**: Save as HTML for sharing

---

### `community` - Community Moderation

**Basic Usage:**
```bash
python run_eagleeye.py community stats
```

**Commands:**
- `stats`: Show community statistics
- `validate`: Validate pending reports
- `reputation`: Check your reputation score

**Examples:**
```bash
# View community stats
python run_eagleeye.py community stats

# Validate pending reports
python run_eagleeye.py community validate

# Check your reputation
python run_eagleeye.py community reputation
```

**Community System:**
- **User Reputation**: Earn trust through accurate validations
- **Report Validation**: Community verifies scam reports
- **Moderation Levels**: Trusted users get moderation privileges
- **Quality Control**: Prevents false reports and spam

---

### `verify` - Phone & URL Verification

**Basic Usage:**
```bash
python run_eagleeye.py verify --phone "+1-555-123-4567"
python run_eagleeye.py verify --url "https://suspicious-site.com"
```

**Options:**
- `--phone, -p`: Phone number to verify against scam databases
- `--url, -u`: URL to scan for phishing/malware threats
- `--deep`: Perform deep content analysis on URLs
- `--format, -f`: Output format (table/json, default: table)

**Examples:**
```bash
# Verify suspicious phone number
python run_eagleeye.py verify --phone "8005551234"

# Scan URL for threats
python run_eagleeye.py verify --url "https://fake-bank.com" --deep

# Get JSON output for automation
python run_eagleeye.py verify --phone "5551234567" --format json

# Verify both phone and URL
python run_eagleeye.py verify --phone "8005551234" --url "https://scam-site.com"
```

**Verification Features:**
- **Phone Number Validation**: Format validation and carrier lookup
- **Scam Database Cross-Reference**: Check against known scam numbers
- **Robocall Detection**: Identify automated calling patterns
- **URL Threat Scanning**: Phishing, malware, and reputation analysis
- **Deep Content Analysis**: Examine webpage content for threats
- **Risk Scoring**: 0-10 threat assessment with confidence levels

---

### `trends` - Scam Trend Analysis

**Basic Usage:**
```bash
python run_eagleeye.py trends
```

**Options:**
- `--location, -l`: Focus on specific location (City, State)
- `--days, -d`: Number of days to analyze (default: 7)
- `--hotspots`: Show scam hotspots with high activity
- `--forecast`: Show predictive insights and recommendations

**Examples:**
```bash
# Show trending locations
python run_eagleeye.py trends --days 14

# Focus on specific location
python run_eagleeye.py trends --location "New York, NY" --days 30

# Detect scam hotspots
python run_eagleeye.py trends --hotspots

# Get predictive insights
python run_eagleeye.py trends --forecast

# Comprehensive analysis
python run_eagleeye.py trends --hotspots --forecast --days 30
```

**Trend Analysis Features:**
- **Geographic Trends**: Track scam activity by location
- **Hotspot Detection**: Identify high-intensity scam areas
- **Trend Direction**: Increasing, decreasing, or stable activity
- **Risk Assessment**: Overall threat level evaluation
- **Predictive Insights**: Forecast future scam trends
- **Actionable Recommendations**: Suggested preventive measures

---

### `government` - FTC & FCC Data Access

**Basic Usage:**
```bash
python run_eagleeye.py government --source ftc --state CA
```

**Options:**
- `--source, -s`: Data source (ftc, fcc, both, default: both)
- `--state`: State abbreviation (e.g., CA, NY, TX)
- `--city`: City name filter
- `--days, -d`: Number of days back to fetch (default: 7)
- `--trending`: Show trending numbers and issues

**Examples:**
```bash
# Get FTC complaints for California
python run_eagleeye.py government --source ftc --state CA --days 14

# Show FCC complaints nationwide
python run_eagleeye.py government --source fcc --days 30

# Get trending scam numbers
python run_eagleeye.py government --source ftc --trending --state NY

# Focus on specific city
python run_eagleeye.py government --city "Miami" --state FL --days 7

# Comprehensive government data
python run_eagleeye.py government --source both --trending --days 30
```

**Government Data Features:**
- **FTC Do Not Call Registry**: Consumer robocall complaints
- **FCC Consumer Complaints**: Telecom and unwanted call reports
- **Geographic Filtering**: State and city-specific data
- **Trending Analysis**: Most reported numbers and issues
- **Real-time Updates**: Fresh complaint data with caching
- **Complaint Statistics**: Volume, types, and patterns

---

### `train` - Train Machine Learning Models

**Basic Usage:**
```bash
python run_eagleeye.py train
```

**Options:**
- `--model, -m`: Model type (random_forest, gradient_boost, logistic_regression, svm)
- `--optimize`: Enable hyperparameter optimization
- `--min-samples`: Minimum training samples required (default: 100)
- `--description`: Model description for registry
- `--tags`: Comma-separated tags for organization

**Examples:**
```bash
# Train default Random Forest model
python run_eagleeye.py train

# Train optimized Gradient Boosting model
python run_eagleeye.py train --model gradient_boost --optimize

# Train with metadata
python run_eagleeye.py train \
  --model random_forest \
  --optimize \
  --description "Production model v2.1" \
  --tags "production,optimized"

# Train with more data
python run_eagleeye.py train --min-samples 500
```

**Training Features:**
- **Multiple Algorithms**: Random Forest, Gradient Boosting, SVM, Logistic Regression
- **Hyperparameter Optimization**: GridSearchCV for best performance
- **Cross-Validation**: 5-fold CV for robust evaluation
- **Automatic Registration**: Models saved with metadata and performance metrics
- **Feature Engineering**: Advanced text, URL, and phone analysis

---

### `predict` - AI-Powered Scam Prediction

**Basic Usage:**
```bash
python run_eagleeye.py predict --text "Your suspicious content here"
```

**Options:**
- `--text, -t`: Text content to analyze
- `--url, -u`: URL to analyze
- `--phone, -p`: Phone number to analyze
- `--model-id`: Specific model ID to use (uses active model if not specified)

**Examples:**
```bash
# Analyze suspicious text
python run_eagleeye.py predict --text "Congratulations! You've won $10,000!"

# Analyze suspicious URL
python run_eagleeye.py predict --url "https://fake-bank-login.com"

# Analyze phone number
python run_eagleeye.py predict --phone "+1-800-555-SCAM"

# Combined analysis
python run_eagleeye.py predict \
  --text "Call now to claim your prize!" \
  --phone "8005551234" \
  --url "https://claim-prize.net"

# Use specific model
python run_eagleeye.py predict \
  --text "Your account will be suspended" \
  --model-id random_forest_20241220_143015
```

**Prediction Features:**
- **Risk Scoring**: 0-10 threat assessment scale
- **Confidence Levels**: Prediction confidence percentages
- **Class Probabilities**: Breakdown of all possible classifications
- **Multi-Input Analysis**: Combine text, URL, and phone analysis
- **Model Versioning**: Use specific trained models

---

### `models` - ML Model Management

**Basic Usage:**
```bash
python run_eagleeye.py models
```

**Options:**
- `--list/--no-list`: List registered models (default: true)
- `--type`: Filter models by type
- `--set-active`: Set active model by ID
- `--compare`: Compare two models (comma-separated IDs)
- `--delete`: Delete model by ID
- `--cleanup`: Clean up old models
- `--stats`: Show detailed model statistics

**Examples:**
```bash
# List all models
python run_eagleeye.py models

# Filter by model type
python run_eagleeye.py models --type random_forest

# Show detailed statistics
python run_eagleeye.py models --stats

# Set active model
python run_eagleeye.py models --set-active random_forest_20241220_143015

# Compare two models
python run_eagleeye.py models --compare model1_id,model2_id

# Delete old model
python run_eagleeye.py models --delete old_model_id

# Clean up old models (keeps recent and best performing)
python run_eagleeye.py models --cleanup
```

**Model Management Features:**
- **Version Control**: Track model versions with timestamps
- **Performance Comparison**: Compare accuracy, F1 scores, and other metrics
- **Active Model Management**: Set which model to use for predictions
- **Metadata Tracking**: Store descriptions, tags, and training info
- **Automatic Cleanup**: Remove old models while preserving best performers
- **Storage Management**: Track model file sizes and disk usage

---

### `fetch` - Pull Latest Scam Intelligence

**Basic Usage:**
```bash
python -m eagleeye fetch
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
python -m eagleeye fetch --limit 100

# Fetch only phishing scams from PhishTank
python -m eagleeye fetch --source openphish --type phishing

# Show only new scams since last check
python -m eagleeye fetch --new

# Fetch without saving to database
python -m eagleeye fetch --no-save
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
python -m eagleeye watch
```

**Options:**
- `--interval, -i`: Refresh interval in seconds (default: 30)
- `--source, -s`: Monitor specific source only
- `--limit, -l`: Number of scams to display (default: 25)
- `--compact, -c`: Use compact display mode

**Examples:**
```bash
# Watch with 60-second refresh interval
python -m eagleeye watch --interval 60

# Monitor only PhishTank in compact mode
python -m eagleeye watch --source openphish --compact

# Watch with more results displayed
python -m eagleeye watch --limit 50
```

**Features:**
- Live-updating terminal display
- Real-time scam feed with automatic refresh
- Statistics panel showing database info
- Press Ctrl+C to exit

**Display Layout:**
```
┌─────────────────────────────────────────────────────────────────┐
│                    EagleEye - Live Monitoring                │
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
python -m eagleeye search "paypal phishing"
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
python -m eagleeye search "investment fraud"

# Search with filters
python -m eagleeye search "phishing" --type phishing --hours 24

# Search specific source data
python -m eagleeye search "paypal" --source openphish
```

#### Online Source Search
```bash
# Search online APIs for specific domain
python -m eagleeye search "suspicious-domain.com" --online

# Search multiple sources online
python -m eagleeye search "bitcoin scam" --online --limit 20
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
python -m eagleeye stats
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
python -m eagleeye sources --list
```

**Test Source Connections:**
```bash
python -m eagleeye sources --test
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
- **Configuration**: Set `openphish_api_key` in config

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

### Crowdsourced Intelligence Workflow

#### Complete Scam Analysis and Reporting Workflow
```bash
# 1. Analyze suspicious content
python run_eagleeye.py analyze --text "Suspicious message here"

# 2. If confirmed as scam, report it to community
python run_eagleeye.py report --text "Suspicious message here" --location "Your City, State"

# 3. Help validate other community reports
python run_eagleeye.py community validate

# 4. View regional scam trends
python run_eagleeye.py heatmap --trending
```

#### Voice Scam Detection Workflow
```bash
# Analyze robocall recording
python run_eagleeye.py analyze --voice "robocall.wav"

# Report confirmed voice scam
python run_eagleeye.py report --voice "robocall.wav" --phone "+1234567890" --location "Your Location"

# Check community reputation
python run_eagleeye.py community reputation
```

#### Government Data Analysis Workflow
```bash
# Check FTC complaints for your area
python run_eagleeye.py government --source ftc --state YOUR_STATE --days 30

# Verify suspicious phone numbers
python run_eagleeye.py verify --phone "SUSPICIOUS_NUMBER"

# Analyze trends and hotspots
python run_eagleeye.py trends --hotspots --forecast

# Cross-reference with government data
python run_eagleeye.py government --trending --state YOUR_STATE
```

#### URL and Link Verification Workflow
```bash
# Scan suspicious URLs
python run_eagleeye.py verify --url "https://suspicious-site.com" --deep

# Report confirmed phishing sites
python run_eagleeye.py report --url "https://phishing-site.com" --description "Fake bank login"

# Check trends for link-based scams
python run_eagleeye.py trends --days 14
```

### Batch Operations

#### Fetch from Multiple Sources
```bash
# Fetch from all configured sources
python -m eagleeye fetch --limit 200

# Fetch from specific sources sequentially
python -m eagleeye fetch --source mock --limit 50
python -m eagleeye fetch --source openphish --limit 50
```

#### Automated Monitoring Script
```bash
#!/bin/bash
# monitor-scams.sh - Run every hour via cron
python -m eagleeye fetch --new --limit 100
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
python -m eagleeye search "phishing" --hours 24 --limit 100

# Use with other tools (example with jq for JSON processing)
python -m eagleeye fetch --limit 50 --no-save | grep -E "(phishing|fraud)"
```

### Custom Filtering

#### Complex Search Queries
```bash
# Find high-severity scams from specific timeframe
python -m eagleeye search "investment" --hours 48 --limit 200

# Search for location-specific scams
python -m eagleeye search "US" --type fraud --hours 72

# Find scams from specific sources
python -m eagleeye search "paypal" --source openphish --online
```

### Performance Optimization

#### Database Maintenance
```bash
# The database automatically cleans old records
# Default retention: 30 days
# Configurable via cache_duration setting

# Monitor database size through stats
python -m eagleeye stats
```

#### Efficient Monitoring
```bash
# Use compact mode for better performance
python -m eagleeye watch --compact --limit 15

# Adjust refresh interval based on needs
python -m eagleeye watch --interval 60  # Less frequent updates
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Command Not Found
**Problem**: `python -m eagleeye` not recognized
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
python -m eagleeye sources --test

# Check API key configuration
python -m eagleeye config --show

# Verify internet connection
ping google.com
```

#### 3. Database Issues
**Problem**: Database errors or corruption
**Solution**:
```bash
# Check database location
python -m eagleeye config --show

# Reset configuration (recreates database)
python -m eagleeye config --reset

# Manual database location:
# Windows: %LOCALAPPDATA%\EagleEye\eagleeye.db
# Linux/Mac: ~/.eagleeye/eagleeye.db
```

#### 4. Display Issues
**Problem**: Terminal output formatting problems
**Solution**:
```bash
# Try different color scheme
python -m eagleeye config --set color_scheme=minimal

# Use compact mode
python -m eagleeye fetch --limit 10
python -m eagleeye watch --compact

# Check terminal compatibility
echo $TERM  # Linux/Mac
```

#### 5. Performance Issues
**Problem**: Slow response or high memory usage
**Solution**:
```bash
# Reduce result limits
python -m eagleeye config --set max_results=25

# Increase cache duration to reduce API calls
python -m eagleeye config --set cache_duration=7200

# Use specific sources only
python -m eagleeye fetch --source mock --limit 20
```

### Debug Mode
```bash
# Enable verbose output (if implemented)
export SCAMSWATTER_DEBUG=1
python -m eagleeye fetch --limit 5

# Check log files (if logging implemented)
# Location: ~/.scamswatter/logs/
```

### Getting Help
```bash
# Command-specific help
python -m eagleeye fetch --help
python -m eagleeye watch --help
python -m eagleeye search --help

# General help
python -m eagleeye --help

# Version information
python -m eagleeye --version
```

---

## API Sources

### OpenPhish Integration

#### Getting API Key
1. Visit [OpenPhish Developer Portal](https://www.openphish.com/api.html)
2. Register for free account
3. Generate API key
4. Configure in EagleEye:
```bash
python -m eagleeye config --set openphish_api_key=YOUR_KEY_HERE
```

#### Data Format
- **Phishing URLs**: Real-time phishing URL feeds
- **Live Threat Intelligence**: Active phishing campaigns
- **URL Classification**: Categorized threat types
- **Detection Time**: When the phishing URL was first detected

#### Rate Limits
- Free tier: Unlimited requests with reasonable usage
- Automatic retry with exponential backoff
- Rate limiting handled automatically

### URLVoid Integration

#### Getting API Key
1. Visit [URLVoid API](https://www.urlvoid.com/api/)
2. Choose subscription plan
3. Get API key from dashboard
4. Configure in EagleEye:
```bash
python -m eagleeye config --set urlvoid_api_key=YOUR_KEY_HERE
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
- Demonstrates **EagleEye** is a powerful command-line tool that provides real-time scam intelligence from multiple threat feeds.
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

*This guide covers all EagleEye CLI functionality. For additional support, visit the project repository or file an issue.*
