"""
Main CLI application for EagleEye
"""
import asyncio
from typing import Optional, List
from pathlib import Path
import typer
from rich.console import Console
from rich.live import Live
from rich.prompt import Confirm
import time
import sys

from .config import get_config, create_default_config, get_config_file, save_config
from .database import get_database, ScamRecord
from .ui import get_ui
from .sources import MockSource, OpenPhishSource, URLVoidSource, ScamSourceError
from .logging_config import setup_logging, get_logger, log_performance, log_async_performance
from .exceptions import (
    EagleEyeException, ConfigurationError, ValidationError, 
    handle_exception, ErrorHandler
)

# Create the main Typer app
app = typer.Typer(
    name="eagleeye",
    help="EagleEye - Your personal scam radar",
    add_completion=False,
    rich_markup_mode="rich"
)

# Global instances
console = Console()
logger = None  # Will be initialized in main


@app.command()
def fetch(
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Specific source to fetch from"),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of scams to fetch"),
    scam_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by scam type"),
    save_to_db: bool = typer.Option(True, "--save/--no-save", help="Save results to local database"),
    show_new: bool = typer.Option(False, "--new", help="Only show new scams since last fetch")
):
    """
    Fetch the latest scam intelligence from configured sources
    """
    cmd_logger = get_logger('cli.fetch')
    
    try:
        cmd_logger.info(f"Starting fetch command", extra={
            'source': source,
            'limit': limit,
            'scam_type': scam_type,
            'save_to_db': save_to_db,
            'show_new': show_new
        })
        
        # Validate parameters
        if limit <= 0:
            raise ValidationError("Limit must be greater than 0", field="limit", value=limit)
        if limit > 10000:
            raise ValidationError("Limit too large (max 10000)", field="limit", value=limit)
        
        asyncio.run(_fetch_command(source, limit, scam_type, save_to_db, show_new))
        cmd_logger.info("Fetch command completed successfully")
        
    except EagleEyeException:
        raise  # Re-raise EagleEye exceptions
    except Exception as e:
        handle_exception("fetch", e, cmd_logger)


@app.command()
def watch(
    interval: int = typer.Option(30, "--interval", "-i", help="Refresh interval in seconds"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Specific source to monitor"),
    limit: int = typer.Option(25, "--limit", "-l", help="Number of scams to display"),
    compact: bool = typer.Option(False, "--compact", "-c", help="Use compact display mode")
):
    """
    Watch for new scams in real-time with live updates
    """
    asyncio.run(_watch_command(interval, source, limit, compact))


@app.command()
def search(
    query: str = typer.Argument(..., help="Search query (keywords, URL, or domain)"),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of results"),
    scam_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by scam type"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Filter by source"),
    hours: Optional[int] = typer.Option(None, "--hours", "-h", help="Search within last N hours"),
    online: bool = typer.Option(False, "--online", help="Search online sources instead of local DB")
):
    """
    Search scam database or online sources for specific threats
    """
    asyncio.run(_search_command(query, limit, scam_type, source, hours, online))


@app.command()
def stats():
    """
    Show database statistics and source information
    """
    _stats_command()


@app.command()
def config(
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
    edit: bool = typer.Option(False, "--edit", help="Open config file for editing"),
    reset: bool = typer.Option(False, "--reset", help="Reset to default configuration"),
    set_key: Optional[str] = typer.Option(None, "--set", help="Set configuration key=value")
):
    """
    Manage EagleEye configuration
    """
    _config_command(show, edit, reset, set_key)


@app.command()
def analyze(
    text: Optional[str] = typer.Option(None, "--text", "-t", help="Text content to analyze"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL to scrape and analyze"),
    email_file: Optional[str] = typer.Option(None, "--email", "-e", help="Email file to analyze"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json")
):
    """Analyze text content for scam indicators using AI/NLP"""
    from .analysis import TextAnalyzer, ContentScraper, NLPPipeline
    
    ui = get_ui()
    ui.print_banner()
    
    if not any([text, url, email_file]):
        ui.print_error("Please provide text content, URL, or email file to analyze")
        return
    
    from .cli_helpers import _run_text_analysis
    asyncio.run(_run_text_analysis(text, url, email_file, output_format, ui))


@app.command()
def report(
    text: Optional[str] = typer.Option(None, "--text", "-t", help="Report text-based scam"),
    voice: Optional[str] = typer.Option(None, "--voice", "-v", help="Report voice scam (audio file path)"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Report website scam"),
    email: Optional[str] = typer.Option(None, "--email", "-e", help="Report email scam (file path)"),
    location: Optional[str] = typer.Option(None, "--location", "-l", help="Your location (country/region)"),
    description: str = typer.Option("", "--description", "-d", help="Additional description")
):
    """Report new scams to help improve community detection"""
    from .crowdsource import ScamReporter
    from .cli_helpers import _run_report_submission
    
    ui = get_ui()
    ui.print_banner()
    
    if not any([text, voice, url, email]):
        ui.print_error("Please provide content to report: --text, --voice, --url, or --email")
        return
    
    asyncio.run(_run_report_submission(text, voice, url, email, location, description, ui))


@app.command()
def heatmap(
    days: int = typer.Option(30, "--days", "-d", help="Days of data to include"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save HTML heatmap to file"),
    trending: bool = typer.Option(False, "--trending", help="Show trending scams only")
):
    """Generate real-time scam heatmap with regional trends"""
    from .crowdsource import ScamHeatmap
    from .cli_helpers import _run_heatmap_generation
    
    ui = get_ui()
    ui.print_banner()
    
    asyncio.run(_run_heatmap_generation(days, output, trending, ui))


@app.command()
def community(
    action: str = typer.Argument(..., help="Action: stats, validate, reputation"),
) -> None:
    """Community moderation and validation commands."""
    asyncio.run(handle_community_command(action))


@app.command()
def verify(
    phone: Optional[str] = typer.Option(None, "--phone", "-p", help="Phone number to verify"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL to scan for threats"),
    deep_scan: bool = typer.Option(False, "--deep", help="Perform deep content analysis"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json")
) -> None:
    """Verify phone numbers and scan URLs for threats."""
    asyncio.run(handle_verify_command(phone, url, deep_scan, output_format))


@app.command()
def trends(
    location: Optional[str] = typer.Option(None, "--location", "-l", help="Location (City, State)"),
    days: int = typer.Option(7, "--days", "-d", help="Number of days to analyze"),
    hotspots: bool = typer.Option(False, "--hotspots", help="Show scam hotspots"),
    forecast: bool = typer.Option(False, "--forecast", help="Show predictive insights")
) -> None:
    """Analyze scam trends and hotspots by location."""
    asyncio.run(handle_trends_command(location, days, hotspots, forecast))


@app.command()
def government(
    source: str = typer.Option("both", "--source", "-s", help="Data source: ftc, fcc, both"),
    state: Optional[str] = typer.Option(None, "--state", help="State abbreviation (e.g., CA, NY)"),
    city: Optional[str] = typer.Option(None, "--city", help="City name"),
    days: int = typer.Option(7, "--days", "-d", help="Number of days back to fetch"),
    trending: bool = typer.Option(False, "--trending", help="Show trending numbers/issues")
) -> None:
    """Access FTC and FCC government complaint data."""
    asyncio.run(handle_government_command(source, state, city, days, trending))


@app.command()
def sources(
    test: bool = typer.Option(False, "--test", help="Test all configured sources"),
    list_sources: bool = typer.Option(False, "--list", help="List available sources")
):
    """Manage and test scam intelligence sources"""
    asyncio.run(_sources_command(test, list_sources))


@log_async_performance
async def _fetch_command(
    source: Optional[str],
    limit: int,
    scam_type: Optional[str],
    save_to_db: bool,
    show_new: bool
):
    """Implementation of fetch command"""
    fetch_logger = get_logger('fetch')
    
    try:
        with ErrorHandler("fetch_initialization", fetch_logger):
            ui = get_ui()
            config = get_config()
            db = get_database()
            
            ui.print_banner()
            fetch_logger.debug("Fetch command initialized successfully")
        
        # Get available sources
        with ErrorHandler("source_configuration", fetch_logger):
            sources = get_configured_sources()
            
            if not sources:
                error_msg = "No sources configured. Please check your configuration."
                fetch_logger.error(error_msg)
                ui.print_error(error_msg)
                raise ConfigurationError(error_msg, config_key="sources")
            
            fetch_logger.info(f"Found {len(sources)} configured sources")
    
    # Filter sources if specified
    if source:
        sources = [s for s in sources if s.name.lower() == source.lower()]
        if not sources:
            ui.print_error(f"Source '{source}' not found or not configured.")
            return
    
    all_scams = []
    
    # Fetch from each source
    for src in sources:
        with ui.create_progress_spinner(f"Fetching from {src.name.upper()}..."):
            try:
                scams = await src.fetch_recent_scams(limit)
                
                # Filter by type if specified
                if scam_type:
                    scams = [
                        s for s in scams 
                        if scam_type.lower() in s.scam_type.lower()
                    ]
                
                # Filter new scams if requested
                if show_new:
                    new_scams = []
                    for scam in scams:
                        existing = db.get_scam_by_source(
                            scam.source, scam.source_id
                        )
                        if not existing:
                            new_scams.append(scam)
                    scams = new_scams
                
                all_scams.extend(scams)
                
                # Save to database if requested
                if save_to_db:
                    for scam in scams:
                        db.insert_scam(scam)
                
                db.update_source_sync(src.name, True)
                ui.print_success(f"Fetched {len(scams)} scams from {src.name.upper()}")
                
            except ScamSourceError as e:
                db.update_source_sync(src.name, False, str(e))
                ui.print_error(f"Failed to fetch from {src.name.upper()}: {e}")
            except Exception as e:
                db.update_source_sync(src.name, False, str(e))
                ui.print_error(f"Unexpected error with {src.name.upper()}: {e}")
    
    if all_scams:
        # Sort by severity and recency
        all_scams.sort(key=lambda x: (x.severity, x.first_seen), reverse=True)
        all_scams = all_scams[:limit]
        
        # Display results
        table = ui.create_scam_table(all_scams, title=f"Latest Scam Intelligence ({len(all_scams)} records)")
        console.print(table)
        
        if show_new and len(all_scams) > 0:
            ui.print_info(f"Found {len(all_scams)} new scams since last check")
    else:
        ui.print_warning("No scams found matching your criteria")


async def _watch_command(interval: int, source: Optional[str], limit: int, compact: bool):
    """Implementation of watch command"""
    ui = get_ui()
    db = get_database()
    
    ui.print_banner()
    ui.print_info(f"Starting live monitoring (refresh every {interval}s). Press Ctrl+C to exit.")
    
    # Get sources
    sources = get_configured_sources()
    if source:
        sources = [s for s in sources if s.name.lower() == source.lower()]
    
    if not sources:
        ui.print_error("No sources available for monitoring.")
        return
    
    layout = ui.create_live_layout()
    
    try:
        with Live(layout, refresh_per_second=1, screen=True):
            while True:
                # Fetch latest data
                all_scams = []
                for src in sources:
                    try:
                        scams = await src.fetch_recent_scams(limit)
                        all_scams.extend(scams)
                    except:
                        pass  # Silently continue on errors in watch mode
                
                # Sort and limit
                all_scams.sort(key=lambda x: (x.severity, x.first_seen), reverse=True)
                all_scams = all_scams[:limit]
                
                # Get stats
                stats = db.get_stats()
                
                # Update layout
                ui.update_live_layout(layout, all_scams, stats)
                
                # Wait for next refresh
                await asyncio.sleep(interval)
                
    except KeyboardInterrupt:
        ui.print_info("Monitoring stopped.")


async def _search_command(query: str, limit: int, scam_type: Optional[str], source: Optional[str], hours: Optional[int], online: bool):
    """Implementation of search command"""
    ui = get_ui()
    db = get_database()
    
    if online:
        # Search online sources
        ui.print_info(f"Searching online sources for: '{query}'")
        
        sources = get_configured_sources()
        if source:
            sources = [s for s in sources if s.name.lower() == source.lower()]
        
        all_scams = []
        for src in sources:
            with ui.create_progress_spinner(f"Searching {src.name.upper()}..."):
                try:
                    scams = await src.search_scams(query, limit)
                    all_scams.extend(scams)
                except ScamSourceError as e:
                    ui.print_warning(f"Search failed for {src.name.upper()}: {e}")
                except Exception as e:
                    ui.print_warning(f"Unexpected error searching {src.name.upper()}: {e}")
    else:
        # Search local database
        ui.print_info(f"Searching local database for: '{query}'")
        all_scams = db.search_scams(
            query=query,
            scam_type=scam_type,
            source=source,
            hours_back=hours,
            limit=limit
        )
    
    if all_scams:
        # Sort by relevance (severity + recency)
        all_scams.sort(key=lambda x: (x.severity, x.first_seen), reverse=True)
        
        table = ui.create_scam_table(
            all_scams, 
            title=f"Search Results for '{query}' ({len(all_scams)} found)"
        )
        console.print(table)
    else:
        ui.print_warning(f"No scams found matching '{query}'")


def _stats_command():
    """Implementation of stats command"""
    ui = get_ui()
    db = get_database()
    
    ui.print_banner()
    
    # Get database stats
    stats = db.get_stats()
    stats_panel = ui.create_stats_panel(stats)
    console.print(stats_panel)
    
    # Show configuration
    config_panel = ui.create_config_panel()
    console.print(config_panel)
    
    # Show source status
    console.print("\n[bold]Source Status:[/bold]")
    sources = get_configured_sources()
    for src in sources:
        status = db.get_source_sync_status(src.name)
        if status:
            last_sync = status.get('last_sync', 'Never')
            error_count = status.get('error_count', 0)
            health = "Healthy" if error_count == 0 else f"{error_count} errors"
            console.print(f"  • {src.name.upper()}: {health} (Last sync: {last_sync})")
        else:
            console.print(f"  • {src.name.upper()}: Not synced yet")


def _config_command(show: bool, edit: bool, reset: bool, set_key: Optional[str]):
    """Implementation of config command"""
    ui = get_ui()
    config_file = get_config_file()
    
    if reset:
        if Confirm.ask("Reset configuration to defaults?"):
            create_default_config()
            ui.print_success(f"Configuration reset to defaults: {config_file}")
        return
    
    if not config_file.exists():
        create_default_config()
        ui.print_info(f"Created default configuration: {config_file}")
    
    if show:
        config_panel = ui.create_config_panel()
        console.print(config_panel)
        console.print(f"\n[bold]Config file location:[/bold] {config_file}")
    
    if edit:
        import os
        try:
            if os.name == 'nt':  # Windows
                os.system(f'notepad "{config_file}"')
            else:  # Unix-like
                editor = os.environ.get('EDITOR', 'nano')
                os.system(f'{editor} "{config_file}"')
        except Exception as e:
            ui.print_error(f"Failed to open editor: {e}")
            ui.print_info(f"Please manually edit: {config_file}")
    
    if set_key:
        if '=' not in set_key:
            ui.print_error("Use format: --set key=value")
            return
        
        key, value = set_key.split('=', 1)
        config = get_config()
        
        # Simple type conversion
        if value.lower() in ['true', 'false']:
            value = value.lower() == 'true'
        elif value.isdigit():
            value = int(value)
        elif value.replace('.', '').isdigit():
            value = float(value)
        
        try:
            setattr(config, key, value)
            save_config(config)
            ui.print_success(f"Set {key} = {value}")
        except Exception as e:
            ui.print_error(f"Failed to set configuration: {e}")


async def _sources_command(test: bool, list_sources: bool):
    """Implementation of sources command"""
    ui = get_ui()
    
    if list_sources:
        console.print("[bold]Available Sources:[/bold]")
        console.print("  • [green]mock[/green] - Mock source for testing (always available)")
        console.print("  • [yellow]phishtank[/yellow] - PhishTank phishing database (API key optional)")
        console.print("  • [red]urlvoid[/red] - URLVoid website reputation (API key required)")
        return
    
    if test:
        sources = get_configured_sources()
        console.print("[bold]Testing Sources:[/bold]")
        
        for src in sources:
            with ui.create_progress_spinner(f"Testing {src.name.upper()}..."):
                try:
                    is_working = await src.test_connection()
                    if is_working:
                        ui.print_success(f"{src.name.upper()}: Connection successful")
                    else:
                        ui.print_error(f"{src.name.upper()}: Connection failed")
                except Exception as e:
                    ui.print_error(f"{src.name.upper()}: {e}")


def get_configured_sources():
    """Get list of configured scam sources"""
    from .sources import MockSource, OpenPhishSource, PyOpenPhishDB
    
    sources = []
    
    # Always add PyOpenPhishDB (local offline database)
    pyopdb = PyOpenPhishDB()
    sources.append(pyopdb)
    
    # Add mock source for testing
    sources.append(MockSource())
    
    # Add OpenPhish if available
    config = get_config()
    openphish_key = getattr(config, 'openphish_api_key', None)
    openphish = OpenPhishSource(openphish_key)
    if openphish.is_configured():
        sources.append(openphish)
    
    return sources


async def handle_community_command(action: str):
    """Community moderation and validation commands."""
    from .cli_helpers import _run_community_commands
    
    ui = get_ui()
    ui.print_banner()
    
    if action == "stats":
        await _run_community_commands(stats=True, validate=False, reputation=None, ui=ui)
    elif action == "validate":
        await _run_community_commands(stats=False, validate=True, reputation=None, ui=ui)
    else:
        ui.print_error(f"Unknown community action: {action}")
        ui.print_info("Available actions: stats, validate")


async def handle_verify_command(phone: Optional[str], url: Optional[str], deep_scan: bool, format: str):
    """Verify phone numbers and scan URLs for threats."""
    from .analysis import CallerIDVerifier, LinkScanner
    import json
    
    ui = get_ui()
    ui.print_banner()
    
    results = []
    
    try:
        if phone:
            with ui.console.status(f"[bold green]Verifying phone number: {phone}"):
                verifier = CallerIDVerifier()
                result = await verifier.verify_phone_number(phone)
                results.append({'type': 'phone', 'data': result.to_dict()})
        
        if url:
            with ui.console.status(f"[bold green]Scanning URL: {url}"):
                scanner = LinkScanner()
                result = await scanner.scan_url(url, deep_scan=deep_scan)
                results.append({'type': 'url', 'data': result.to_dict()})
        
        if not results:
            ui.print_error("Please specify either --phone or --url to verify")
            return
        
        # Display results
        if format.lower() == 'json':
            ui.console.print_json(json.dumps(results, indent=2, default=str))
        else:
            _display_verify_results(results, ui)
            
    except Exception as e:
        ui.print_error(f"Verification failed: {e}")


async def handle_trends_command(location: Optional[str], days: int, hotspots: bool, forecast: bool):
    """Analyze scam trends and hotspots by location."""
    from .analysis import TrendAnalyzer, GeolocationService
    from .database import get_database
    from dataclasses import asdict
    
    ui = get_ui()
    db = get_database()
    ui.print_banner()
    
    try:
        # Get scam data for analysis
        scam_records = db.get_recent_scams(days * 24)  # Get records for specified days
        scam_data = [asdict(record) for record in scam_records]
        
        analyzer = TrendAnalyzer()
        
        if hotspots:
            with ui.console.status("[bold green]Detecting scam hotspots..."):
                hotspots_data = await analyzer.detect_hotspots(scam_data)
            
            ui.console.print(f"\n[bold cyan]🔥 Scam Hotspots (Last {days} days)[/bold cyan]\n")
            _display_hotspots(hotspots_data, ui)
        
        elif forecast:
            with ui.console.status("[bold green]Generating threat predictions..."):
                predictions = await analyzer.predict_emerging_threats(scam_data, days_ahead=30)
            
            ui.console.print(f"\n[bold cyan]🔮 Emerging Threat Forecast[/bold cyan]\n")
            _display_predictions(predictions, ui)
        
        else:
            with ui.console.status("[bold green]Analyzing scam trends..."):
                trends = await analyzer.analyze_scam_trends(scam_data, time_period="7d")
            
            ui.console.print(f"\n[bold cyan]📈 Scam Trends (Last {days} days)[/bold cyan]\n")
            _display_trends(trends, ui)
        
        if location:
            with ui.console.status(f"[bold green]Analyzing location: {location}"):
                geo_service = GeolocationService()
                location_data = await geo_service.analyze_location(location)
            
            ui.console.print(f"\n[bold cyan]📍 Location Analysis: {location}[/bold cyan]\n")
            _display_location_analysis(location_data, ui)
            
    except Exception as e:
        ui.print_error(f"Trends analysis failed: {e}")


async def handle_government_command(source: str, state: Optional[str], city: Optional[str], days: int, trending: bool):
    """Access FTC and FCC government complaint data."""
    from .sources import FTCDNCClient, FCCComplaintsClient
    
    ui = get_ui()
    ui.print_banner()
    
    try:
        results = {}
        
        if source in ["ftc", "both"]:
            with ui.console.status("[bold green]Fetching FTC Do Not Call data..."):
                ftc_client = FTCDNCClient()
                
                if trending:
                    trending_numbers = await ftc_client.get_trending_numbers(limit=15)
                    results['ftc_trending'] = trending_numbers
                else:
                    if state:
                        complaints = await ftc_client.get_complaints_by_state(state, days)
                        results['ftc_complaints'] = [complaint.to_scam_record().to_dict() for complaint in complaints]
                    else:
                        stats = await ftc_client.get_complaint_statistics(days)
                        results['ftc_stats'] = stats
        
        if source in ["fcc", "both"]:
            with ui.console.status("[bold green]Fetching FCC complaint data..."):
                fcc_client = FCCComplaintsClient()
                
                if trending:
                    trending_issues = await fcc_client.get_trending_issues(days)
                    results['fcc_trending'] = trending_issues
                else:
                    if state:
                        complaints = await fcc_client.get_complaints_by_state(state, days)
                        results['fcc_complaints'] = [complaint.to_scam_record().to_dict() for complaint in complaints]
                    else:
                        stats = await fcc_client.get_complaint_statistics(days)
                        results['fcc_stats'] = stats
        
        # Display results
        ui.console.print(f"\n[bold cyan]🏛️ Government Complaint Data ({source.upper()})[/bold cyan]\n")
        _display_government_data(results, source, state, city, trending, ui)
        
    except Exception as e:
        ui.print_error(f"Government data fetch failed: {e}")


def _display_verify_results(results: list, ui):
    """Display verification results"""
    from rich.table import Table
    from rich import box
    
    for result in results:
        if result['type'] == 'phone':
            data = result['data']
            table = Table(title="📞 Phone Number Verification", border_style="cyan", box=box.ROUNDED)
            table.add_column("Attribute", style="bold white")
            table.add_column("Value", style="green")
            
            table.add_row("Phone Number", data['formatted_number'])
            table.add_row("Carrier", data.get('carrier', 'Unknown'))
            table.add_row("Number Type", data['number_type'].title())
            table.add_row("Risk Level", f"[bold red]{data['risk_level'].upper()}[/bold red]" if data['risk_level'] in ['high', 'critical'] else data['risk_level'].title())
            table.add_row("Risk Score", f"{data['risk_score']:.1f}/10")
            table.add_row("Scam Reports", str(data['scam_reports']))
            
            ui.console.print(table)
        
        elif result['type'] == 'url':
            data = result['data']
            table = Table(title="URL Security Scan", border_style="cyan", box=box.ROUNDED)
            table.add_column("Attribute", style="bold white")
            table.add_column("Value", style="green")
            
            table.add_row("URL", data['normalized_url'])
            table.add_row("Domain", data['domain'])
            table.add_row("Threat Type", data['threat_type'].title())
            table.add_row("Risk Level", f"[bold red]{data['risk_level'].upper()}[/bold red]" if data['risk_level'] in ['high', 'critical'] else data['risk_level'].title())
            table.add_row("Risk Score", f"{data['risk_score']:.1f}/10")
            table.add_row("SSL Valid", "✅" if data['ssl_valid'] else "❌")
            table.add_row("Is Malicious", "⚠️ YES" if data['is_malicious'] else "✅ NO")
            
            ui.console.print(table)


def _display_hotspots(hotspots_data: list, ui):
    """Display scam hotspots"""
    from rich.table import Table
    from rich import box
    
    if not hotspots_data:
        ui.print_warning("No scam hotspots detected")
        return
    
    table = Table(title="Scam Hotspots", border_style="red", box=box.ROUNDED)
    table.add_column("Location", style="bold white")
    table.add_column("Risk Score", style="red", justify="center")
    table.add_column("Scam Count", style="cyan", justify="center")
    table.add_column("Trend", style="yellow")
    table.add_column("Dominant Types", style="orange")
    
    for hotspot in hotspots_data:
        table.add_row(
            hotspot.location,
            f"{hotspot.risk_score:.1f}",
            str(hotspot.scam_count),
            hotspot.trend_direction.value.title(),
            ", ".join(hotspot.dominant_scam_types[:2])
        )
    
    ui.console.print(table)


def _display_predictions(predictions: dict, ui):
    """Display threat predictions"""
    from rich.panel import Panel
    
    volume_pred = predictions.get('volume_prediction', {})
    type_preds = predictions.get('type_predictions', {})
    
    pred_text = f"""
[bold]Predicted Volume (Next 30 days):[/bold] {volume_pred.get('predicted_volume', 0)} scams
[bold]Current Daily Average:[/bold] {volume_pred.get('current_daily_average', 0):.1f} scams/day

[bold]Type Predictions:[/bold]
"""
    
    for scam_type, pred_data in list(type_preds.items())[:5]:
        pred_text += f"• {scam_type.title()}: {pred_data.get('predicted_growth', 0):.1f}% growth\n"
    
    pred_panel = Panel(pred_text, title="🔮 Threat Predictions", border_style="magenta")
    ui.console.print(pred_panel)


def _display_trends(trends: list, ui):
    """Display trend analysis"""
    from rich.table import Table
    from rich import box
    
    if not trends:
        ui.print_warning("No trend data available")
        return
    
    table = Table(title="Scam Trends", border_style="cyan", box=box.ROUNDED)
    table.add_column("Metric", style="bold white")
    table.add_column("Current", style="green", justify="center")
    table.add_column("Previous", style="yellow", justify="center")
    table.add_column("Change", style="red", justify="center")
    table.add_column("Trend", style="cyan")
    
    for trend in trends:
        change_color = "red" if trend.change_percentage > 0 else "green"
        table.add_row(
            trend.metric_name.replace("_", " ").title(),
            f"{trend.current_value:.1f}",
            f"{trend.previous_value:.1f}",
            f"[{change_color}]{trend.change_percentage:+.1f}%[/{change_color}]",
            trend.trend_direction.value.title()
        )
    
    ui.console.print(table)


def _display_location_analysis(location_data, ui):
    """Display location analysis"""
    from rich.panel import Panel
    
    loc_text = f"""
[bold]Location:[/bold] {location_data.location_string}
[bold]Country:[/bold] {location_data.country}
[bold]Threat Level:[/bold] {location_data.threat_level.value.upper()}
[bold]Scam Density:[/bold] {location_data.scam_density:.1f} per 100k
[bold]Recent Scams:[/bold] {location_data.recent_scam_count}

[bold]Common Scam Types:[/bold]
""" + "\n".join([f"• {scam_type.title()}" for scam_type in location_data.scam_types[:3]])
    
    color = {
        'minimal': 'green',
        'low': 'green', 
        'moderate': 'yellow',
        'high': 'red',
        'critical': 'red'
    }.get(location_data.threat_level.value, 'white')
    
    loc_panel = Panel(loc_text, title="📍 Location Analysis", border_style=color)
    ui.console.print(loc_panel)


def _display_government_data(results: dict, source: str, state: Optional[str], city: Optional[str], trending: bool, ui):
    """Display government complaint data"""
    from rich.table import Table
    from rich import box
    from rich.panel import Panel
    
    if 'ftc_stats' in results:
        stats = results['ftc_stats']
        ui.console.print("[bold green]FTC Statistics:[/bold green]")
        ui.console.print(f"Total Complaints: {stats['total_complaints']}")
        ui.console.print(f"Daily Average: {stats['daily_average']:.1f}")
        ui.console.print(f"Robocall %: {stats['robocall_percentage']:.1f}%")
        ui.console.print()
    
    if 'fcc_stats' in results:
        stats = results['fcc_stats']
        ui.console.print("[bold green]FCC Statistics:[/bold green]")
        ui.console.print(f"Total Complaints: {stats['total_complaints']}")
        ui.console.print(f"Daily Average: {stats['daily_average']:.1f}")
        ui.console.print(f"Timely Response Rate: {stats['timely_response_rate']:.1f}%")
        ui.console.print()
    
    # Display trending data
    if 'ftc_trending' in results:
        trending_numbers = results['ftc_trending']
        if trending_numbers:
            table = Table(title="🔥 FTC Trending Numbers", border_style="red", box=box.ROUNDED)
            table.add_column("Phone Number", style="bold white")
            table.add_column("Reports", style="red", justify="center")
            table.add_column("Location", style="cyan")
            table.add_column("Type", style="yellow")
            
            for number_data in trending_numbers[:10]:
                table.add_row(
                    number_data.get('phone_number', 'Unknown'),
                    str(number_data.get('report_count', 0)),
                    number_data.get('location', 'Unknown'),
                    number_data.get('scam_type', 'Unknown').title()
                )
            
            ui.console.print(table)
    
    if 'fcc_trending' in results:
        trending_issues = results['fcc_trending']
        if trending_issues:
            table = Table(title="📈 FCC Trending Issues", border_style="yellow", box=box.ROUNDED)
            table.add_column("Issue Type", style="bold white")
            table.add_column("Recent Count", style="green", justify="center")
            table.add_column("Previous Count", style="cyan", justify="center")
            table.add_column("Change", style="red", justify="center")
            table.add_column("Trend", style="yellow")
            
            for issue in trending_issues[:10]:
                change_pct = issue.get('change_percentage', 0)
                change_color = "red" if change_pct > 0 else "green"
                trend_icon = "📈" if change_pct > 10 else "📉" if change_pct < -10 else "➡️"
                
                table.add_row(
                    issue.get('issue', 'Unknown'),
                    str(issue.get('recent_count', 0)),
                    str(issue.get('previous_count', 0)),
                    f"[{change_color}]{change_pct:+.1f}%[/{change_color}]",
                    f"{trend_icon} {issue.get('trend', 'stable').title()}"
                )
            
            ui.console.print(table)
    
    # Display complaint details
    if 'ftc_complaints' in results:
        complaints = results['ftc_complaints']
        if complaints:
            table = Table(title="FTC Complaints", border_style="green", box=box.ROUNDED)
            table.add_column("Date", style="cyan")
            table.add_column("Phone Number", style="red")
            table.add_column("Type", style="yellow")
            table.add_column("Description", style="white")
            
            for complaint in complaints[:15]:
                table.add_row(
                    complaint.get('first_seen', '').split('T')[0] if complaint.get('first_seen') else 'Unknown',
                    complaint.get('phone', 'N/A'),
                    complaint.get('scam_type', 'Unknown').title(),
                    complaint.get('description', '')[:50] + "..." if len(complaint.get('description', '')) > 50 else complaint.get('description', '')
                )
            
            ui.console.print(table)
    
    if 'fcc_complaints' in results:
        complaints = results['fcc_complaints']
        if complaints:
            table = Table(title="FCC Complaints", border_style="blue", box=box.ROUNDED)
            table.add_column("Date", style="cyan")
            table.add_column("Issue", style="yellow")
            table.add_column("State", style="green")
            table.add_column("Description", style="white")
            
            for complaint in complaints[:15]:
                table.add_row(
                    complaint.get('first_seen', '').split('T')[0] if complaint.get('first_seen') else 'Unknown',
                    complaint.get('scam_type', 'Unknown').title(),
                    complaint.get('location', 'Unknown').split(',')[-1].strip() if complaint.get('location') else 'Unknown',
                    complaint.get('description', '')[:50] + "..." if len(complaint.get('description', '')) > 50 else complaint.get('description', '')
                )
            
            ui.console.print(table)
    
    # Summary panel
    if state or city:
        location_str = f"{city}, {state}" if city and state else state or city
        summary_text = f"[bold]Location Filter:[/bold] {location_str}\n"
    else:
        summary_text = "[bold]Scope:[/bold] National Data\n"
    
    summary_text += f"[bold]Source:[/bold] {source.upper()}\n"
    summary_text += f"[bold]Mode:[/bold] {'Trending Analysis' if trending else 'Statistical Overview'}"
    
    summary_panel = Panel(summary_text, title="📋 Query Summary", border_style="cyan")
    ui.console.print(summary_panel)


# Machine Learning Commands
@app.command()
def train(
    model_type: Optional[str] = typer.Option("random_forest", "--model", "-m", help="Model type (random_forest, gradient_boost, logistic_regression, svm)"),
    optimize: bool = typer.Option(False, "--optimize", help="Enable hyperparameter optimization"),
    min_samples: int = typer.Option(100, "--min-samples", help="Minimum training samples required"),
    description: Optional[str] = typer.Option(None, "--description", help="Model description"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags")
):
    """
    Train a machine learning model for scam detection
    """
    try:
        from .ml.pipeline import MLPipeline, PipelineConfig
        from .ml.model_manager import get_model_manager
        
        ui = get_ui()
        ui.print_banner()
        ui.print_info(f"🤖 Training {model_type} model for scam detection")
        
        # Create pipeline configuration
        config = PipelineConfig(
            model_type=model_type,
            hyperparameter_optimization=optimize,
            min_samples=min_samples
        )
        
        # Create and run pipeline
        pipeline = MLPipeline(config)
        
        with ui.console.status("Training model..."):
            result = asyncio.run(pipeline.train_pipeline())
        
        if result.success:
            ui.print_success(f"Model training completed in {result.execution_time:.2f}s")
            
            # Register model with manager
            if pipeline.model and result.metrics:
                model_manager = get_model_manager()
                
                # Convert metrics to ModelMetrics if needed
                from .ml.models import ModelMetrics
                if isinstance(result.metrics, dict):
                    metrics = ModelMetrics(
                        accuracy=result.metrics.get('accuracy_mean', 0),
                        precision=result.metrics.get('precision_weighted_mean', 0),
                        recall=result.metrics.get('recall_weighted_mean', 0),
                        f1_score=result.metrics.get('f1_weighted_mean', 0)
                    )
                else:
                    metrics = result.metrics
                
                tag_list = tags.split(',') if tags else []
                model_id = model_manager.register_model(
                    pipeline.model,
                    metrics,
                    pipeline.training_data_size,
                    description or f"Trained {model_type} model",
                    tag_list
                )
                
                ui.print_success(f"Model registered with ID: {model_id}")
                
                # Display performance metrics
                if result.metrics:
                    ui.print_info("Performance Metrics:")
                    for metric, value in result.metrics.items():
                        if isinstance(value, (int, float)):
                            ui.console.print(f"  {metric}: {value:.4f}")
        else:
            ui.print_error(f"Model training failed: {result.error_message}")
            
    except ImportError as e:
        ui.print_error(f"ML modules not available: {e}")
    except Exception as e:
        handle_exception("ml_train", e, get_logger('cli.train'))


@app.command()
def predict(
    text: Optional[str] = typer.Option(None, "--text", "-t", help="Text content to analyze"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL to analyze"),
    phone: Optional[str] = typer.Option(None, "--phone", "-p", help="Phone number to analyze"),
    model_id: Optional[str] = typer.Option(None, "--model-id", help="Specific model ID to use")
):
    """
    Predict scam probability using ML models
    """
    try:
        from .ml.pipeline import MLPipeline
        from .ml.model_manager import get_model_manager
        
        ui = get_ui()
        
        if not any([text, url, phone]):
            ui.print_error("Please provide at least one input: --text, --url, or --phone")
            return
        
        ui.print_info("🔮 Analyzing content with ML models")
        
        # Get model
        model_manager = get_model_manager()
        pipeline = MLPipeline()
        
        if model_id:
            pipeline.model = model_manager.get_model(model_id)
            if not pipeline.model:
                ui.print_error(f"Model {model_id} not found")
                return
        
        # Prepare content
        content = {}
        if text:
            content['text'] = text
        if url:
            content['url'] = url
        if phone:
            content['phone'] = phone
        
        # Make prediction
        with ui.console.status("Making prediction..."):
            result = asyncio.run(pipeline.predict_pipeline(content))
        
        if result.success and result.predictions:
            prediction = result.predictions[0]
            
            # Display results
            from rich.panel import Panel
            from rich.table import Table
            from rich import box
            
            # Risk assessment
            risk_color = "red" if prediction.risk_score > 7 else "yellow" if prediction.risk_score > 4 else "green"
            risk_text = f"[{risk_color}]{prediction.risk_score:.1f}/10[/{risk_color}]"
            
            # Create results table
            table = Table(title="🎯 Scam Detection Results", border_style="cyan", box=box.ROUNDED)
            table.add_column("Metric", style="bold white")
            table.add_column("Value", style="green")
            
            table.add_row("Predicted Class", prediction.predicted_class.title())
            table.add_row("Confidence", f"{prediction.confidence:.1%}")
            table.add_row("Risk Score", risk_text)
            table.add_row("Model Version", prediction.model_version)
            
            ui.console.print(table)
            
            # Probability breakdown
            prob_text = "[bold]Class Probabilities:[/bold]\n"
            for class_name, prob in prediction.probabilities.items():
                prob_text += f"• {class_name.title()}: {prob:.1%}\n"
            
            prob_panel = Panel(prob_text, title="📊 Detailed Breakdown", border_style="blue")
            ui.console.print(prob_panel)
            
        else:
            ui.print_error(f"Prediction failed: {result.error_message}")
            
    except ImportError as e:
        ui.print_error(f"ML modules not available: {e}")
    except Exception as e:
        handle_exception("ml_predict", e, get_logger('cli.predict'))


@app.command()
def models(
    list_models: bool = typer.Option(True, "--list/--no-list", help="List registered models"),
    model_type: Optional[str] = typer.Option(None, "--type", help="Filter by model type"),
    set_active: Optional[str] = typer.Option(None, "--set-active", help="Set active model by ID"),
    compare: Optional[str] = typer.Option(None, "--compare", help="Compare two models (comma-separated IDs)"),
    delete: Optional[str] = typer.Option(None, "--delete", help="Delete model by ID"),
    cleanup: bool = typer.Option(False, "--cleanup", help="Clean up old models"),
    stats: bool = typer.Option(False, "--stats", help="Show model statistics")
):
    """
    Manage ML models (list, activate, compare, delete)
    """
    try:
        from .ml.model_manager import get_model_manager
        
        ui = get_ui()
        model_manager = get_model_manager()
        
        # Set active model
        if set_active:
            if model_manager.set_active_model(set_active):
                ui.print_success(f"Set model {set_active} as active")
            else:
                ui.print_error(f"Failed to set model {set_active} as active")
            return
        
        # Compare models
        if compare:
            model_ids = [mid.strip() for mid in compare.split(',')]
            if len(model_ids) != 2:
                ui.print_error("Please provide exactly two model IDs separated by comma")
                return
            
            comparison = model_manager.compare_models(model_ids[0], model_ids[1])
            if comparison:
                from rich.table import Table
                from rich.panel import Panel
                from rich import box
                
                # Comparison table
                table = Table(title="📊 Model Comparison", border_style="cyan", box=box.ROUNDED)
                table.add_column("Metric", style="bold white")
                table.add_column(f"Model 1 ({model_ids[0]})", style="green")
                table.add_column(f"Model 2 ({model_ids[1]})", style="blue")
                table.add_column("Difference", style="yellow")
                
                for metric, data in comparison.metric_comparisons.items():
                    table.add_row(
                        metric.replace('_', ' ').title(),
                        f"{data['model1']:.4f}",
                        f"{data['model2']:.4f}",
                        f"{data['difference']:+.4f}"
                    )
                
                ui.console.print(table)
                
                # Recommendation
                rec_panel = Panel(
                    comparison.recommendation,
                    title="🎯 Recommendation",
                    border_style="green"
                )
                ui.console.print(rec_panel)
            else:
                ui.print_error("Failed to compare models")
            return
        
        # Delete model
        if delete:
            if Confirm.ask(f"Are you sure you want to delete model {delete}?"):
                if model_manager.delete_model(delete):
                    ui.print_success(f"Deleted model {delete}")
                else:
                    ui.print_error(f"Failed to delete model {delete}")
            return
        
        # Cleanup old models
        if cleanup:
            deleted_count = model_manager.cleanup_old_models()
            ui.print_success(f"Cleaned up {deleted_count} old models")
            return
        
        # Show statistics
        if stats:
            stats_data = model_manager.get_model_stats()
            
            from rich.panel import Panel
            
            stats_text = f"""
[bold]Total Models:[/bold] {stats_data.get('total_models', 0)}
[bold]Active Model:[/bold] {stats_data.get('active_model', 'None')}

[bold]Models by Type:[/bold]
"""
            for model_type, count in stats_data.get('models_by_type', {}).items():
                stats_text += f"• {model_type}: {count}\n"
            
            perf_stats = stats_data.get('performance_stats', {})
            stats_text += f"""
[bold]Performance:[/bold]
• Average F1 Score: {perf_stats.get('avg_f1_score', 0):.4f}
• Average Accuracy: {perf_stats.get('avg_accuracy', 0):.4f}
• Best Model: {perf_stats.get('best_model_id', 'None')}

[bold]Storage:[/bold]
• Total Size: {stats_data.get('storage_stats', {}).get('total_size_mb', 0):.1f} MB
"""
            
            stats_panel = Panel(stats_text, title="📈 Model Statistics", border_style="cyan")
            ui.console.print(stats_panel)
            return
        
        # List models (default)
        if list_models:
            models_list = model_manager.list_models(model_type=model_type)
            
            if not models_list:
                ui.print_warning("No models found")
                return
            
            from rich.table import Table
            from rich import box
            
            table = Table(title="🤖 Registered ML Models", border_style="cyan", box=box.ROUNDED)
            table.add_column("Model ID", style="bold white")
            table.add_column("Type", style="green")
            table.add_column("F1 Score", style="cyan", justify="center")
            table.add_column("Accuracy", style="yellow", justify="center")
            table.add_column("Created", style="blue")
            table.add_column("Active", style="red", justify="center")
            
            for model in models_list:
                f1_score = model.performance_metrics.get('f1_score', 0)
                accuracy = model.performance_metrics.get('accuracy', 0)
                
                table.add_row(
                    model.model_id,
                    model.model_type,
                    f"{f1_score:.3f}" if f1_score else "N/A",
                    f"{accuracy:.3f}" if accuracy else "N/A",
                    model.created_at.strftime("%Y-%m-%d"),
                    "✅" if model.is_active else "❌"
                )
            
            ui.console.print(table)
            
    except ImportError as e:
        ui.print_error(f"ML modules not available: {e}")
    except Exception as e:
        handle_exception("ml_models", e, get_logger('cli.models'))


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Show version information"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
    log_file: Optional[str] = typer.Option(None, "--log-file", help="Custom log file path")
):
    """
    EagleEye - Your personal scam radar
    
    Real-time scam intelligence at your fingertips.
    """
    global logger
    
    # Initialize logging
    try:
        config = get_config()
        
        # Override log level if debug is enabled
        log_level = "DEBUG" if debug else config.log_level
        
        # Setup log file path
        if log_file:
            log_path = Path(log_file)
        elif config.log_to_file:
            from .config import get_config_dir
            log_path = get_config_dir() / "logs" / "eagleeye.log"
        else:
            log_path = None
        
        # Initialize logging
        logger = setup_logging(
            log_level=log_level,
            log_file=log_path,
            max_file_size=config.log_file_max_size,
            backup_count=config.log_backup_count,
            json_format=config.log_json_format,
            enable_console=True
        )
        
        logger.info("EagleEye CLI starting up")
        
    except Exception as e:
        console.print(f"[red]Failed to initialize logging: {e}[/red]")
        # Continue without logging rather than crash
    
    if version:
        try:
            from . import __version__
            version_str = f"EagleEye CLI v{__version__}"
            console.print(version_str)
            if logger:
                logger.info(f"Version requested: {version_str}")
        except ImportError:
            version_str = "EagleEye CLI (version unknown)"
            console.print(version_str)
            if logger:
                logger.warning("Version import failed")
        
        raise typer.Exit()


if __name__ == "__main__":
    app()
