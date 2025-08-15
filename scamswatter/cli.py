"""
Main CLI application for ScamSwatter
"""
import asyncio
from typing import Optional, List
from pathlib import Path
import typer
from rich.console import Console
from rich.live import Live
from rich.prompt import Confirm
import time

from .config import get_config, create_default_config, get_config_file, save_config
from .database import get_database, ScamRecord
from .ui import get_ui
from .sources import MockSource, PhishTankSource, URLVoidSource, ScamSourceError

# Create the main Typer app
app = typer.Typer(
    name="scamswatter",
    help="🛡️ ScamSwatter - Your personal scam radar",
    add_completion=False,
    rich_markup_mode="rich"
)

# Global instances
console = Console()


@app.command()
def fetch(
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Specific source to fetch from"),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of scams to fetch"),
    scam_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by scam type"),
    save_to_db: bool = typer.Option(True, "--save/--no-save", help="Save results to local database"),
    show_new: bool = typer.Option(False, "--new", help="Only show new scams since last fetch")
):
    """
    🔍 Fetch the latest scam intelligence from configured sources
    """
    asyncio.run(_fetch_command(source, limit, scam_type, save_to_db, show_new))


@app.command()
def watch(
    interval: int = typer.Option(30, "--interval", "-i", help="Refresh interval in seconds"),
    source: Optional[str] = typer.Option(None, "--source", "-s", help="Specific source to monitor"),
    limit: int = typer.Option(25, "--limit", "-l", help="Number of scams to display"),
    compact: bool = typer.Option(False, "--compact", "-c", help="Use compact display mode")
):
    """
    👁️ Watch for new scams in real-time with live updates
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
    🔎 Search scam database or online sources for specific threats
    """
    asyncio.run(_search_command(query, limit, scam_type, source, hours, online))


@app.command()
def stats():
    """
    📊 Show database statistics and source information
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
    ⚙️ Manage ScamSwatter configuration
    """
    _config_command(show, edit, reset, set_key)


@app.command()
def sources(
    test: bool = typer.Option(False, "--test", help="Test all configured sources"),
    list_sources: bool = typer.Option(False, "--list", help="List available sources")
):
    """
    🔌 Manage and test scam intelligence sources
    """
    asyncio.run(_sources_command(test, list_sources))


async def _fetch_command(source: Optional[str], limit: int, scam_type: Optional[str], save_to_db: bool, show_new: bool):
    """Implementation of fetch command"""
    ui = get_ui()
    config = get_config()
    db = get_database()
    
    ui.print_banner()
    
    # Get available sources
    sources = _get_configured_sources()
    
    if not sources:
        ui.print_error("No sources configured. Please check your configuration.")
        return
    
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
                    scams = [s for s in scams if scam_type.lower() in s.scam_type.lower()]
                
                # Filter new scams if requested
                if show_new:
                    new_scams = []
                    for scam in scams:
                        existing = db.get_scam_by_source(scam.source, scam.source_id)
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
    sources = _get_configured_sources()
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
        
        sources = _get_configured_sources()
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
    sources = _get_configured_sources()
    for src in sources:
        status = db.get_source_sync_status(src.name)
        if status:
            last_sync = status.get('last_sync', 'Never')
            error_count = status.get('error_count', 0)
            health = "🟢 Healthy" if error_count == 0 else f"🔴 {error_count} errors"
            console.print(f"  • {src.name.upper()}: {health} (Last sync: {last_sync})")
        else:
            console.print(f"  • {src.name.upper()}: 🟡 Not synced yet")


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
        sources = _get_configured_sources()
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


def _get_configured_sources() -> List:
    """Get list of configured and available sources"""
    config = get_config()
    sources = []
    
    # Always include mock source for testing
    sources.append(MockSource())
    
    # Add PhishTank if configured or available
    if 'phishtank' in config.preferred_sources:
        phishtank = PhishTankSource(config.phishtank_api_key)
        if phishtank.is_configured():
            sources.append(phishtank)
    
    # Add URLVoid if configured
    if 'urlvoid' in config.preferred_sources and config.urlvoid_api_key:
        urlvoid = URLVoidSource(config.urlvoid_api_key)
        if urlvoid.is_configured():
            sources.append(urlvoid)
    
    return sources


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Show version information")
):
    """
    🛡️ ScamSwatter - Your personal scam radar
    
    Real-time scam intelligence at your fingertips.
    """
    if version:
        from . import __version__
        console.print(f"ScamSwatter CLI v{__version__}")
        raise typer.Exit()


if __name__ == "__main__":
    app()
