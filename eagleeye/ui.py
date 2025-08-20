"""
Rich-based UI components and styling for EagleEye CLI
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.layout import Layout
from rich.align import Align
from rich import box
from rich.style import Style

from .database import ScamRecord
from .config import get_config


class EagleEyeTheme:
    """Color themes for EagleEye CLI"""
    
    SECURITY = {
        'primary': '#FF6B6B',      # Red for alerts
        'secondary': '#4ECDC4',    # Teal for info
        'accent': '#45B7D1',       # Blue for links
        'success': '#96CEB4',      # Green for success
        'warning': '#FFEAA7',      # Yellow for warnings
        'error': '#FF7675',        # Red for errors
        'muted': '#636E72',        # Gray for muted text
        'background': '#2D3436',   # Dark background
        'text': '#DDD',            # Light text
    }
    
    MINIMAL = {
        'primary': '#333333',
        'secondary': '#666666',
        'accent': '#0066CC',
        'success': '#008000',
        'warning': '#FF8C00',
        'error': '#CC0000',
        'muted': '#999999',
        'background': '#FFFFFF',
        'text': '#000000',
    }
    
    COLORFUL = {
        'primary': '#E74C3C',
        'secondary': '#3498DB',
        'accent': '#9B59B6',
        'success': '#2ECC71',
        'warning': '#F39C12',
        'error': '#E74C3C',
        'muted': '#95A5A6',
        'background': '#ECF0F1',
        'text': '#2C3E50',
    }


class EagleEyeUI:
    """Main UI class for EagleEye CLI"""
    
    def __init__(self):
        self.console = Console()
        self.config = get_config()
        self.theme = self._get_theme()
    
    def _get_theme(self) -> Dict[str, str]:
        """Get the current color theme"""
        theme_name = self.config.color_scheme.lower()
        if theme_name == 'minimal':
            return EagleEyeTheme.MINIMAL
        elif theme_name == 'colorful':
            return EagleEyeTheme.COLORFUL
        else:
            return EagleEyeTheme.SECURITY
    
    def print_banner(self) -> None:
        """Print the EagleEye banner"""
        import os
        
        # On Windows with encoding issues, use simple banner
        if os.name == 'nt':
            simple_banner = Panel(
                Align.center(Text("EAGLEEYE", style=f"bold {self.theme['primary']}")),
                title="[bold]Your Personal Scam Radar[/bold]",
                title_align="center",
                border_style=self.theme['accent']
            )
            self.console.print(simple_banner)
        else:
            # Use ASCII art on Unix systems
            try:
                banner_text = """
 ███████╗ █████╗  ██████╗ ██╗     ███████╗███████╗██╗   ██╗███████╗
 ██╔════╝██╔══██╗██╔════╝ ██║     ██╔════╝██╔════╝╚██╗ ██╔╝██╔════╝
 █████╗  ███████║██║  ███╗██║     █████╗  █████╗   ╚████╔╝ █████╗  
 ██╔══╝  ██╔══██║██║   ██║██║     ██╔══╝  ██╔══╝    ╚██╔╝  ██╔══╝  
 ███████╗██║  ██║╚██████╔╝███████╗███████╗███████╗   ██║   ███████╗
 ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝   ╚═╝   ╚══════╝
                """
                
                banner_panel = Panel(
                    Align.center(Text(banner_text, style=self.theme['primary'])),
                    title="[bold]Your Personal Scam Radar[/bold]",
                    title_align="center",
                    border_style=self.theme['accent'],
                    box=box.DOUBLE
                )
                
                self.console.print(banner_panel)
            except Exception:
                # Fallback to simple text banner
                simple_banner = Panel(
                    Align.center(Text("EAGLEEYE", style=f"bold {self.theme['primary']}")),
                    title="[bold]Your Personal Scam Radar[/bold]",
                    title_align="center",
                    border_style=self.theme['accent']
                )
                self.console.print(simple_banner)
        
        self.console.print()
    
    def create_scam_table(
        self, 
        scams: List[ScamRecord], 
        title: str = "Scam Intelligence Feed",
        show_source: bool = True,
        compact: bool = False
    ) -> Table:
        """Create a Rich table for displaying scam data"""
        
        table = Table(
            title=title,
            title_style=f"bold {self.theme['primary']}",
            border_style=self.theme['accent'],
            header_style=f"bold {self.theme['secondary']}",
            show_header=True,
            show_lines=not compact,
            box=box.ROUNDED if not compact else box.SIMPLE
        )
        
        # Add columns based on configuration
        table.add_column("Type", style=self.theme['accent'], width=12)
        table.add_column("Title", style="white", min_width=30, max_width=50)
        
        if not compact:
            table.add_column("Description", style=self.theme['muted'], max_width=40)
        
        if show_source and self.config.show_source:
            table.add_column("Source", style=self.theme['secondary'], width=10)
        
        table.add_column("Severity", justify="center", width=8)
        
        if self.config.show_timestamps:
            table.add_column("First Seen", style=self.theme['muted'], width=16)
        
        if not compact:
            table.add_column("Location", style=self.theme['warning'], width=12)
        
        # Add rows
        for scam in scams:
            row_data = []
            
            # Scam type with color coding
            type_style = self._get_type_style(scam.scam_type)
            row_data.append(f"[{type_style}]{scam.scam_type}[/{type_style}]")
            
            # Title (truncated if too long)
            title = scam.title[:47] + "..." if len(scam.title) > 50 else scam.title
            row_data.append(title)
            
            # Description (only in non-compact mode)
            if not compact:
                desc = scam.description[:37] + "..." if len(scam.description) > 40 else scam.description
                row_data.append(desc or "N/A")
            
            # Source
            if show_source and self.config.show_source:
                row_data.append(scam.source.upper())
            
            # Severity with color coding
            severity_style = self._get_severity_style(scam.severity)
            row_data.append(f"[{severity_style}]{scam.severity:.1f}[/{severity_style}]")
            
            # Timestamp
            if self.config.show_timestamps:
                if scam.first_seen:
                    time_str = self._format_relative_time(scam.first_seen)
                    row_data.append(time_str)
                else:
                    row_data.append("Unknown")
            
            # Location (only in non-compact mode)
            if not compact:
                row_data.append(scam.location or "Unknown")
            
            table.add_row(*row_data)
        
        return table
    
    def create_stats_panel(self, stats: Dict[str, Any]) -> Panel:
        """Create a statistics panel"""
        content = []
        
        # Total records
        content.append(f"[bold {self.theme['primary']}]Total Records:[/bold {self.theme['primary']}] {stats['total_records']:,}")
        content.append(f"[bold {self.theme['secondary']}]Last 24h:[/bold {self.theme['secondary']}] {stats['recent_records_24h']:,}")
        
        # Top scam types
        if stats['top_scam_types']:
            content.append("\n[bold]Top Scam Types:[/bold]")
            for scam_type, count in stats['top_scam_types'][:3]:
                content.append(f"  • {scam_type}: {count:,}")
        
        # Top sources
        if stats['top_sources']:
            content.append("\n[bold]Active Sources:[/bold]")
            for source, count in stats['top_sources'][:3]:
                content.append(f"  • {source.upper()}: {count:,}")
        
        return Panel(
            "\n".join(content),
            title="[bold]Database Statistics[/bold]",
            border_style=self.theme['accent'],
            padding=(1, 2)
        )
    
    def create_config_panel(self) -> Panel:
        """Create a configuration panel"""
        content = []
        
        config_items = [
            ("Theme", self.config.color_scheme),
            ("Refresh Interval", f"{self.config.refresh_interval}s"),
            ("Max Results", str(self.config.max_results)),
            ("Default Location", self.config.default_location or "Not set"),
            ("Preferred Sources", ", ".join(self.config.preferred_sources)),
            ("Offline Mode", "Yes" if self.config.offline_mode else "No")
        ]
        
        for label, value in config_items:
            content.append(f"[bold]{label}:[/bold] {value}")
        
        return Panel(
            "\n".join(content),
            title="[bold]Configuration[/bold]",
            border_style=self.theme['secondary'],
            padding=(1, 2)
        )
    
    def print_error(self, message: str) -> None:
        """Print an error message"""
        error_style = self.theme['error']
        self.console.print(
            f"[bold {error_style}]Error:[/bold {error_style}] {message}"
        )
    
    def print_warning(self, message: str) -> None:
        """Print a warning message"""
        self.console.print(f"[bold {self.theme['warning']}]Warning:[/bold {self.theme['warning']}] {message}")
    
    def print_success(self, message: str) -> None:
        """Print a success message"""
        self.console.print(f"[bold {self.theme['success']}]Success:[/bold {self.theme['success']}] {message}")
    
    def print_info(self, message: str) -> None:
        """Print an info message"""
        self.console.print(f"[bold {self.theme['secondary']}]Info:[/bold {self.theme['secondary']}] {message}")
    
    def create_progress_spinner(self, text: str) -> Progress:
        """Create a progress spinner"""
        return Progress(
            SpinnerColumn(),
            TextColumn(f"[bold {self.theme['primary']}]{text}[/bold {self.theme['primary']}]"),
            console=self.console,
            transient=True
        )
    
    def _get_type_style(self, scam_type: str) -> str:
        """Get color style for scam type"""
        type_colors = {
            'phishing': self.theme['error'],
            'malware': self.theme['error'],
            'fraud': self.theme['warning'],
            'scam': self.theme['warning'],
            'spam': self.theme['muted'],
            'suspicious': self.theme['accent'],
        }
        
        for key, color in type_colors.items():
            if key in scam_type.lower():
                return color
        
        return self.theme['secondary']
    
    def _get_severity_style(self, severity: float) -> str:
        """Get color style for severity score"""
        if severity >= 8.0:
            return f"bold {self.theme['error']}"
        elif severity >= 6.0:
            return f"bold {self.theme['warning']}"
        elif severity >= 4.0:
            return self.theme['accent']
        else:
            return self.theme['muted']
    
    def _format_relative_time(self, timestamp: datetime) -> str:
        """Format timestamp as relative time"""
        now = datetime.utcnow()
        diff = now - timestamp
        
        if diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours}h ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes}m ago"
        else:
            return "Just now"
    
    def create_live_layout(self) -> Layout:
        """Create a live layout for watch mode"""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        layout["main"].split_row(
            Layout(name="table", ratio=3),
            Layout(name="sidebar", ratio=1)
        )
        
        return layout
    
    def update_live_layout(self, layout: Layout, scams: List[ScamRecord], stats: Dict[str, Any]) -> None:
        """Update the live layout with new data"""
        # Header
        header_text = Text("EagleEye - Live Monitoring", style=f"bold {self.theme['primary']}")
        layout["header"].update(Align.center(header_text))
        
        # Main table
        table = self.create_scam_table(scams, title="Live Scam Feed", compact=True)
        layout["table"].update(table)
        
        # Sidebar with stats
        stats_panel = self.create_stats_panel(stats)
        layout["sidebar"].update(stats_panel)
        
        # Footer
        footer_text = Text(
            f"Last updated: {datetime.now().strftime('%H:%M:%S')} | Press Ctrl+C to exit",
            style=self.theme['muted']
        )
        layout["footer"].update(Align.center(footer_text))


# Global UI instance
_ui: Optional[EagleEyeUI] = None


def get_ui() -> EagleEyeUI:
    """Get the global UI instance"""
    global _ui
    if _ui is None:
        _ui = EagleEyeUI()
    return _ui
