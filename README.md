# EagleEye
Real-Time Scam Intelligence at Your Fingertips

🛡️ About the Project

ScamSwatter is a next-generation, open-source intelligence platform that tracks, analyzes, and alerts you about scam activity in real time — whether it’s phishing emails, fake websites, robocalls, or local fraud attempts.

Leveraging public threat intelligence APIs, location-aware reporting, and AI-powered scam pattern recognition, ScamSwatter empowers individuals, businesses, and security teams to detect and stop scams before they cause harm.

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

📢 Why ScamSwatter?

Fraud is evolving at internet speed. Government bulletins and press releases are too slow — by the time they warn you, the scammers have already moved on. ScamSwatter changes that by giving you live, actionable intelligence in the palm of your hand.

If you’re ready to fight back against scams, join us — fork the repo, submit your ideas, and help make ScamSwatter the internet’s most trusted scam radar.

# ScamSwatter CLI 🛡️
**Your Personal Scam Radar**

A powerful Python command-line tool that delivers real-time scam intelligence directly to your terminal. ScamSwatter pulls data from multiple public threat intelligence APIs, processes it locally, and presents it in a clean, color-coded format perfect for security professionals and everyday users.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/scamswatter/scamswatter.git
cd scamswatter

# Install dependencies
pip install typer[all] rich httpx pydantic pydantic-settings pyyaml aiofiles

# Run ScamSwatter
python -m scamswatter --help

# Fetch latest scam intelligence
python -m scamswatter fetch --limit 10

# Watch for new scams in real-time
python -m scamswatter watch

# Search for specific threats
python -m scamswatter search "paypal phishing"
```

## ✨ Key Features

- **🔍 Live Scam Feed** - Pull latest threats from multiple public APIs
- **👁️ Real-Time Monitoring** - Watch for new scams with live-updating terminal display
- **🔎 Intelligent Search** - Query local database or search online sources
- **📊 Rich Terminal UI** - Beautiful tables, colors, and progress indicators
- **💾 Local Storage** - SQLite database for offline access and history
- **⚙️ Configurable** - Customize sources, display, and behavior
- **🔌 Modular Design** - Easy to add new threat intelligence sources
- **🔒 Privacy-First** - All data stored locally, no tracking

## 📋 Commands Overview

| Command | Purpose | Example |
|---------|---------|---------|
| `fetch` | Pull latest scam intelligence | `python -m scamswatter fetch --limit 50` |
| `watch` | Real-time monitoring with live updates | `python -m scamswatter watch --interval 30` |
| `search` | Query database or online sources | `python -m scamswatter search "investment fraud"` |
| `stats` | View database statistics and source status | `python -m scamswatter stats` |
| `config` | Manage configuration settings | `python -m scamswatter config --show` |
| `sources` | Test and manage API sources | `python -m scamswatter sources --test` |

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
│ phishing  │ Fake PayPal Security...  │ PHISHTANK │    8.5   │ 2m ago        │ US       │
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
scamswatter fetch --limit 100 --source phishtank

# Live monitoring with auto-refresh
scamswatter watch --interval 30 --compact

# Search local database
scamswatter search "investment fraud" --hours 24

# Search online sources
scamswatter search suspicious-domain.com --online

# View statistics
scamswatter stats

# Manage configuration
scamswatter config --show
scamswatter config --edit
```

### Advanced Usage

```bash
# Filter by scam type
scamswatter fetch --type phishing --save

# Show only new scams since last check
scamswatter fetch --new

# Test API connections
scamswatter sources --test

# Compact watch mode for smaller terminals
scamswatter watch --compact --limit 15
```

## ⚙️ Configuration

ScamSwatter stores its configuration in `~/.scamswatter/config.yml`:

```yaml
# API Keys (optional for some sources)
phishtank_api_key: your_api_key_here
urlvoid_api_key: your_api_key_here

# Display Preferences
color_scheme: security  # security, minimal, colorful
show_timestamps: true
compact_mode: false

# Data Sources
preferred_sources:
  - phishtank
  - urlvoid
  - mock

# Behavior
refresh_interval: 30
max_results: 50
offline_mode: false
```

## 🔌 Supported Sources

- **PhishTank** - Community-driven phishing database
- **URLVoid** - Website reputation and safety checker
- **Mock Source** - For testing and demonstration

*More sources coming soon: FTC Consumer Sentinel, Scammer.info, and others*

## 📊 Sample Output

```
╭─────────────────────── Latest Scam Intelligence (25 records) ───────────────────────╮
│ Type      │ Title                    │ Source    │ Severity │ First Seen    │ Location │
├───────────┼──────────────────────────┼───────────┼──────────┼───────────────┼──────────┤
│ phishing  │ Fake PayPal Security...  │ PHISHTANK │    8.5   │ 2m ago        │ US       │
│ fraud     │ IRS Tax Refund Scam      │ MOCK      │    7.0   │ 15m ago       │ UK       │
│ robocall  │ Tech Support Scam        │ MOCK      │    6.5   │ 1h ago        │ CA       │
╰───────────┴──────────────────────────┴───────────┴──────────┴───────────────┴──────────╯
```

## 🚀 Installation

### From PyPI (Coming Soon)
```bash
pip install scamswatter
```

### From Source
```bash
git clone https://github.com/scamswatter/scamswatter.git
cd scamswatter
poetry install
poetry run scamswatter --help
```

### Development Setup
```bash
git clone https://github.com/scamswatter/scamswatter.git
cd scamswatter
poetry install --with dev
poetry run pre-commit install
```

## 🔒 Privacy & Security

- **Local-First**: All data stored locally in SQLite database
- **No Tracking**: ScamSwatter doesn't collect or transmit personal data
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

- **Documentation**: [docs.scamswatter.dev](https://docs.scamswatter.dev)
- **Issues**: [GitHub Issues](https://github.com/scamswatter/scamswatter/issues)
- **Discussions**: [GitHub Discussions](https://github.com/scamswatter/scamswatter/discussions)

---

**Fight back against scams with intelligence.** 🛡️
