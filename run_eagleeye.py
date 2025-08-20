#!/usr/bin/env python3
"""
EagleEye CLI - Your Personal Scam Radar
Optimized runner with fallback support
"""
import sys
import os
import asyncio
from datetime import datetime

# Add current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

def show_help():
    """Show help information"""
    print("""
🦅 EagleEye CLI - Your Personal Scam Radar

Usage: python run_eagleeye.py [COMMAND] [OPTIONS]

Commands:
  help         Show this help message
  config       Show/manage configuration
  fetch        Fetch latest scam intelligence
  sources      List available API sources
  stats        Show database statistics

Examples:
  python run_eagleeye.py config
  python run_eagleeye.py fetch
  python run_eagleeye.py stats
  python run_eagleeye.py sources

For detailed usage, see USER_GUIDE.md
""")

def run_config():
    """Show configuration"""
    try:
        from eagleeye.config import get_config, get_config_dir, create_default_config
        
        print("🦅 EagleEye Configuration")
        print("=" * 50)
        
        config_dir = get_config_dir()
        print(f"Config Directory: {config_dir}")
        
        if not config_dir.exists():
            print("Creating configuration directory...")
            create_default_config()
        
        config = get_config()
        print(f"Color Scheme: {config.color_scheme}")
        print(f"Max Results: {config.max_results}")
        print(f"Refresh Interval: {config.refresh_interval}s")
        print(f"Preferred Sources: {', '.join(config.preferred_sources)}")
        print(f"\n✅ Configuration loaded successfully")
        
    except Exception as e:
        print(f"❌ Config error: {e}")

def run_fetch():
    """Fetch latest scam intelligence"""
    try:
        from eagleeye.sources import MockSource
        from eagleeye.database import get_database
        from eagleeye.ui import get_ui
        
        print("🦅 EagleEye - Fetching Scam Intelligence")
        print("=" * 50)
        
        # Initialize components
        db = get_database()
        ui = get_ui()
        mock = MockSource()
        
        # Show banner
        ui.print_banner()
        
        async def fetch_data():
            print("Fetching data from sources...")
            scams = await mock.fetch_recent_scams(10)
            
            # Save to database
            for scam in scams:
                db.insert_scam(scam)
            
            # Display results
            if scams:
                table = ui.create_scam_table(scams, "Latest Scam Intelligence")
                print(table)
                print(f"\n✅ Fetched {len(scams)} scam records")
            else:
                print("No scam records found")
        
        asyncio.run(fetch_data())
        
    except Exception as e:
        print(f"❌ Fetch error: {e}")

def run_stats():
    """Show database statistics"""
    try:
        from eagleeye.database import get_database
        
        print("🦅 EagleEye Database Statistics")
        print("=" * 50)
        
        db = get_database()
        stats = db.get_stats()
        
        print(f"Total Records: {stats['total_records']}")
        print(f"Recent (24h): {stats['recent_records_24h']}")
        
        if stats['top_scam_types']:
            print("\nTop Scam Types:")
            for scam_type, count in stats['top_scam_types']:
                print(f"  {scam_type}: {count}")
        
        if stats['top_sources']:
            print("\nTop Sources:")
            for source, count in stats['top_sources']:
                print(f"  {source}: {count}")
                
    except Exception as e:
        print(f"❌ Stats error: {e}")

def run_sources():
    """List available sources"""
    try:
        from eagleeye.sources import MockSource, OpenPhishSource, URLVoidSource
        
        print("🦅 EagleEye Available Sources")
        print("=" * 50)
        
        sources = [
            ("MockSource", "Test source for development", "✅ Available"),
            ("OpenPhishSource", "OpenPhish threat feed", "✅ Available"),
            ("URLVoidSource", "URLVoid API (requires key)", "⚠️ Requires API key")
        ]
        
        for name, desc, status in sources:
            print(f"{name}: {desc} - {status}")
            
    except Exception as e:
        print(f"❌ Sources error: {e}")

def main():
    """Main entry point with Typer fallback"""
    # Try Typer first, fallback to simple commands
    try:
        from eagleeye.cli import app
        app()
        return
    except Exception:
        # Fallback to simple command parsing
        pass
    
    if len(sys.argv) < 2:
        show_help()
        return
    
    command = sys.argv[1].lower()
    
    if command in ['help', '--help', '-h']:
        show_help()
    elif command == 'config':
        run_config()
    elif command == 'fetch':
        run_fetch()
    elif command == 'stats':
        run_stats()
    elif command == 'sources':
        run_sources()
    else:
        print(f"Unknown command: {command}")
        show_help()

if __name__ == "__main__":
    main()
