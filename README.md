# EagleEye
Real-Time Scam Intelligence at Your Fingertips

🛡️ About the Project

EagleEye is a next-generation, open-source intelligence platform that tracks, analyzes, and alerts you about scam activity in real time — whether it’s phishing emails, fake websites, robocalls, or local fraud attempts.

Leveraging public threat intelligence APIs, location-aware reporting, and AI-powered scam pattern recognition, EagleEye empowers individuals, businesses, and security teams to detect and stop scams before they cause harm.

Think of it as a personal scam radar — always on, always learning.

🚀 Key Features

Live Scam Feed – Pulls data from multiple public APIs to provide near real-time scam alerts.

Location-Aware Alerts – See scams happening in your area right now.

AI Pattern Detection – Automatically detects emerging scam trends and suspicious patterns.

Community Reporting – Crowdsource scam sightings for better coverage and accuracy.

Developer-Friendly API – Access scam data programmatically for custom tools or dashboards.

🛠️ Tech Stack

Backend: Python (FastAPI / Flask)

Frontend: React.js / TailwindCSS

Database: PostgreSQL / Redis (for real-time caching)

APIs: Multiple public scam intelligence sources

Deployment: Docker + GitHub Actions

📢 Why EagleEye?

Fraud is evolving at internet speed. Government bulletins and press releases are too slow — by the time they warn you, the scammers have already moved on. EagleEye changes that by giving you live, actionable intelligence in the palm of your hand.

If you’re ready to fight back against scams, join us — fork the repo, submit your ideas, and help make EagleEye the internet’s most trusted scam radar.

# 🦅 EagleEye CLI 🛡️
**Your Personal Scam Radar**

**EagleEye** is a powerful command-line tool that provides real-time scam intelligence from multiple threat feeds. Built with Python and featuring a beautiful Rich terminal interface, it helps security professionals, researchers, and everyday users stay ahead of the latest scams and phishing attempts.

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/eagleeye.git
cd eagleeye

# Install dependencies
pip install -r requirements.txt

# Install NLP model for text analysis
python -m spacy download en_core_web_sm
```

### Basic Usage
```bash
# Fetch latest scam intelligence
python run_eagleeye.py fetch

# Analyze suspicious content
python run_eagleeye.py analyze --text "Congratulations! You've won $1,000,000!"

# Verify phone numbers and URLs
python run_eagleeye.py verify --phone "8005551234"
python run_eagleeye.py verify --url "https://suspicious-site.com"

# Access government complaint data
python run_eagleeye.py government --source ftc --state CA

# Analyze scam trends and hotspots
python run_eagleeye.py trends --hotspots --forecast

# Search for specific threats
python run_eagleeye.py search "paypal phishing"

# Monitor in real-time
python run_eagleeye.py watch

# View statistics
python run_eagleeye.py stats

# Train ML models for better detection
python run_eagleeye.py train --model random_forest --optimize

# Predict scam probability with AI
python run_eagleeye.py predict --text "Congratulations! You've won $10,000!"

# Manage ML models
python run_eagleeye.py models --list --stats
```

## ✨ Key Features

### Core Intelligence
- **🔍 Live Scam Feed** - Pull latest threats from multiple public APIs
- **👁️ Real-Time Monitoring** - Watch for new scams with live-updating terminal display
- **🔎 Intelligent Search** - Query local database or search online sources
- **📊 Rich Terminal UI** - Beautiful tables, colors, and progress indicators
- **🗄️ Local Database** - SQLite storage for offline access and history
- **⚡ Async Operations** - Fast parallel API calls and data processing

### Advanced Analysis
- **📞 Caller ID Verification** - Cross-reference phone numbers with scam databases
- **🔗 Link Scanning** - Detect phishing URLs and malware threats
- **🧠 NLP Text Analysis** - Identify scam language patterns and impersonation attempts
- **🎤 Voice Analysis** - Analyze robocall recordings for scam indicators
- **🏛️ Government Data** - Access FTC Do Not Call and FCC complaint databases
- **🌍 Geolocation Intelligence** - Map scam activity by location with geofencing
- **🤖 Machine Learning Models** - AI-powered scam detection with multiple algorithms
- **⚡ Feature Engineering** - Advanced text, URL, and phone number analysis

### Trend Analysis & Insights
- **📈 Scam Hotspots** - Identify high-risk geographic areas
- **🔮 Predictive Analytics** - Forecast emerging scam trends
- **📊 Risk Assessment** - 0-10 threat scoring with confidence levels
- **🎯 Smart Filtering** - Filter by type, date, source, location, and keywords
- **📈 Statistics & Analytics** - Track trends and source reliability

### Community & Privacy
- **👥 Crowdsourced Intelligence** - Community-driven scam reporting and validation
- **🏆 Reputation System** - Earn trust through accurate scam validations
- **🛡️ Privacy-First** - No tracking, all data stored locally
- **🔧 Configurable** - Customize sources, limits, and display preferences, no tracking

## 📋 Commands Overview

| Command | Purpose | Example |
|---------|---------|---------|
| `fetch` | Pull latest scam intelligence | `python run_eagleeye.py fetch --limit 50` |
| `watch` | Real-time monitoring with live updates | `python run_eagleeye.py watch --interval 30` |
| `search` | Query database or online sources | `python run_eagleeye.py search "investment fraud"` |
| `stats` | View database statistics and source status | `python run_eagleeye.py stats` |
| `config` | Manage configuration settings | `python run_eagleeye.py config --show` |
| `analyze` | Analyze text/voice for scam patterns | `python run_eagleeye.py analyze --text "Suspicious message"` |
| `verify` | Verify phone numbers and URLs | `python run_eagleeye.py verify --phone "8005551234"` |
| `trends` | Analyze scam trends and hotspots | `python run_eagleeye.py trends --hotspots --forecast` |
| `government` | Access FTC/FCC complaint data | `python run_eagleeye.py government --source ftc --state CA` |
| `report` | Report scams to community database | `python run_eagleeye.py report --text "Scam message"` |
| `heatmap` | View geographic scam activity | `python run_eagleeye.py heatmap --trending` |
| `community` | Community moderation and stats | `python run_eagleeye.py community stats` |
| `sources` | Test and manage API sources | `python -m eagleeye sources --test` |
| `train` | Train ML models for scam detection | `python run_eagleeye.py train --model random_forest --optimize` |
| `predict` | AI-powered scam prediction | `python run_eagleeye.py predict --text "Suspicious content"` |
| `models` | Manage ML models and versions | `python run_eagleeye.py models --list --stats` |

## 🎨 Sample Output

```
 ███████╗ ██████╗ █████╗ ███╗   ███╗███████╗██╗    ██╗ █████╗ ████████╗████████╗███████╗██████╗ 
 ██╔════╝██╔════╝██╔══██╗████╗ ████║██╔════╝██║    ██║██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝██╔══██╗
 ███████╗██║     ███████║██╔████╔██║███████╗██║ █╗ ██║███████║   ██║      ██║   █████╗  ██████╔╝
 ╚════██║██║     ██╔══██║██║╚██╔╝██║╚════██║██║███╗██║██╔══██║   ██║      ██║   ██╔══╝  ██╔══██╗
 ███████║╚██████╗██║  ██║██║ ╚═╝ ██║███████║╚███╔███╔╝██║  ██║   ██║      ██║   ███████╗██║  ██║
 ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═╝

╭─────────────────────── Latest Scam Intelligence (10 records) ───────────────────────╮
│ Type      │ Title                    │ Source    │ Severity │ First Seen    │ Location │
├───────────┼──────────────────────────┼───────────┼──────────┼───────────────┼──────────┤
│ phishing  │ Fake PayPal Security...  │ OPENPHISH │    8.5   │ 2m ago        │ US       │
│ fraud     │ IRS Tax Refund Scam      │ MOCK      │    7.0   │ 15m ago       │ UK       │
│ robocall  │ Tech Support Scam        │ MOCK      │    6.5   │ 1h ago        │ CA       │
╰───────────┴──────────────────────────┴───────────┴──────────┴───────────────┴──────────╯

✅ Success: Fetched 10 scams from MOCK
```

## 🛠️ Tech Stack

- **Language**: Python 3.11+
- **CLI Framework**: Typer with Rich terminal UI
- **Database**: SQLite (local, zero-config)
- **HTTP Client**: httpx for async API calls
- **Machine Learning**: scikit-learn, spaCy, pandas, numpy
- **Feature Engineering**: Custom text, URL, and phone analysis
- **Configuration**: YAML-based config files
- **Packaging**: Poetry for dependency management

## 📖 Documentation

- **[Complete User Guide](USER_GUIDE.md)** - Detailed step-by-step instructions for all commands
- **[API Sources Guide](USER_GUIDE.md#api-sources)** - How to configure PhishTank, URLVoid, and other sources
- **[Configuration Reference](USER_GUIDE.md#configuration)** - All configuration options explained
- **[Troubleshooting Guide](USER_GUIDE.md#troubleshooting)** - Common issues and solutions

## 🛠️ Tech Stack

- **Language**: Python 3.11+
- **CLI Framework**: Typer with Rich terminal UI
- **Database**: SQLite (local, zero-config)
- **HTTP**: httpx for async API calls
- **Packaging**: Poetry for dependency management

## 📋 Commands

### Core Commands

```bash
# Fetch latest scam data
eagleeye fetch --limit 100 --source openphish

# Live monitoring with auto-refresh
eagleeye watch --interval 30 --compact

# Search local database
eagleeye search "investment fraud" --hours 24

# Search online sources
eagleeye search suspicious-domain.com --online

# View statistics
eagleeye stats

# Manage configuration
eagleeye config --show
eagleeye config --edit
```

### Advanced Usage

```bash
# Filter by scam type
eagleeye fetch --type phishing --save

# Show only new scams since last check
eagleeye fetch --new

# Test API connections
eagleeye sources --test

# Compact watch mode for smaller terminals
eagleeye watch --compact --limit 15

# Train different ML models
eagleeye train --model gradient_boost --optimize --description "Production model"

# Make predictions with specific model
eagleeye predict --text "Click here to claim your prize!" --model-id model_20241220_143015

# Compare model performance
eagleeye models --compare model1_id,model2_id

# Clean up old models
eagleeye models --cleanup
```

## ⚙️ Configuration

EagleEye stores its configuration in `~/.eagleeye/config.yml`:

```yaml
# API Keys (optional for some sources)
openphish_api_key: your_api_key_here
urlvoid_api_key: your_api_key_here

# Display Preferences
color_scheme: security  # security, minimal, colorful
show_timestamps: true
compact_mode: false

# Data Sources
preferred_sources:
  - openphish
  - urlvoid
  - mock

# Behavior
refresh_interval: 30
max_results: 50
offline_mode: false
```

## 🔌 Supported Sources

- **OpenPhish** - Community-driven phishing database with live threat feeds
- **URLVoid** - Website reputation and safety checker
- **Mock Source** - For testing and demonstration

*More sources coming soon: FTC Consumer Sentinel, Scammer.info, and others*

## 📊 Sample Output

```
╭─────────────────────── Latest Scam Intelligence (25 records) ───────────────────────╮
│ Type      │ Title                    │ Source    │ Severity │ First Seen    │ Location │
├───────────┼──────────────────────────┼───────────┼──────────┼───────────────┼──────────┤
│ phishing  │ Fake PayPal Security...  │ OPENPHISH │    8.5   │ 2m ago        │ US       │
│ fraud     │ IRS Tax Refund Scam      │ MOCK      │    7.0   │ 15m ago       │ UK       │
│ robocall  │ Tech Support Scam        │ MOCK      │    6.5   │ 1h ago        │ CA       │
╰───────────┴──────────────────────────┴───────────┴──────────┴───────────────┴──────────╯
```

## 🚀 Installation

### From PyPI (Coming Soon)
```bash
pip install eagleeye
```

### From Source
```bash
git clone https://github.com/eagleeye/eagleeye.git
cd eagleeye
poetry install
poetry run eagleeye --help
```

### Development Setup
```bash
git clone https://github.com/eagleeye/eagleeye.git
cd eagleeye
poetry install --with dev
poetry run pre-commit install
```

## 🔒 Privacy & Security

- **Local-First**: All data stored locally in SQLite database
- **No Tracking**: EagleEye doesn't collect or transmit personal data
- **API Keys**: Stored locally in config file (never transmitted to us)
- **Open Source**: Full transparency - audit the code yourself

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests if applicable
5. Run the test suite (`poetry run pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs.eagleeye.dev](https://docs.eagleeye.dev)
- **Issues**: [GitHub Issues](https://github.com/eagleeye/eagleeye/issues)
- **Discussions**: [GitHub Discussions](https://github.com/eagleeye/eagleeye/discussions)

---

**Fight back against scams with intelligence.** 🛡️
