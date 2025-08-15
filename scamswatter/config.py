"""
Configuration management for ScamSwatter CLI
"""
import os
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field
import yaml


class ScamSwatterConfig(BaseSettings):
    """Main configuration for ScamSwatter CLI"""
    
    # API Configuration
    phishtank_api_key: Optional[str] = None
    urlvoid_api_key: Optional[str] = None
    ftc_api_key: Optional[str] = None
    
    # User Preferences
    default_location: Optional[str] = None
    preferred_sources: List[str] = Field(default_factory=lambda: ["phishtank", "urlvoid"])
    refresh_interval: int = 30  # seconds for watch mode
    max_results: int = 50
    
    # Display Settings
    color_scheme: str = "security"  # security, minimal, colorful
    show_timestamps: bool = True
    show_source: bool = True
    compact_mode: bool = False
    
    # Storage Settings
    cache_duration: int = 3600  # seconds
    max_cache_size: int = 10000  # number of records
    offline_mode: bool = False
    
    # Notification Settings
    enable_notifications: bool = False
    notification_webhook: Optional[str] = None
    notification_email: Optional[str] = None
    
    class Config:
        env_prefix = "SCAMSWATTER_"
        case_sensitive = False


def get_config_dir() -> Path:
    """Get the configuration directory for ScamSwatter"""
    if os.name == 'nt':  # Windows
        config_dir = Path.home() / "AppData" / "Local" / "ScamSwatter"
    else:  # Unix-like
        config_dir = Path.home() / ".scamswatter"
    
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_config_file() -> Path:
    """Get the configuration file path"""
    return get_config_dir() / "config.yml"


def get_cache_dir() -> Path:
    """Get the cache directory for ScamSwatter"""
    cache_dir = get_config_dir() / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def get_database_path() -> Path:
    """Get the SQLite database path"""
    return get_config_dir() / "scamswatter.db"


def load_config() -> ScamSwatterConfig:
    """Load configuration from file and environment"""
    config_file = get_config_file()
    
    # Default configuration
    config_data = {}
    
    # Load from YAML file if it exists
    if config_file.exists():
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    
    # Create config object (will also load from environment variables)
    return ScamSwatterConfig(**config_data)


def save_config(config: ScamSwatterConfig) -> None:
    """Save configuration to file"""
    config_file = get_config_file()
    
    # Convert to dict, excluding environment variables and defaults
    config_dict = {}
    
    # Only save non-default values
    default_config = ScamSwatterConfig()
    for field_name, field_value in config:
        default_value = getattr(default_config, field_name)
        if field_value != default_value:
            config_dict[field_name] = field_value
    
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=True)
    except Exception as e:
        print(f"Error: Could not save config file: {e}")


def create_default_config() -> None:
    """Create a default configuration file"""
    config_file = get_config_file()
    
    if not config_file.exists():
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                # Write with comments
                f.write("# ScamSwatter Configuration File\n")
                f.write("# Edit this file to customize your ScamSwatter experience\n\n")
                
                f.write("# API Keys (get from respective services)\n")
                f.write("phishtank_api_key: your_phishtank_api_key_here\n")
                f.write("urlvoid_api_key: your_urlvoid_api_key_here\n\n")
                
                f.write("# User Preferences\n")
                f.write("default_location: US\n")
                f.write("preferred_sources:\n  - phishtank\n  - urlvoid\n")
                f.write("refresh_interval: 30\n")
                f.write("max_results: 50\n\n")
                
                f.write("# Display Settings\n")
                f.write("color_scheme: security  # security, minimal, colorful\n")
                f.write("show_timestamps: true\n")
                f.write("show_source: true\n")
                f.write("compact_mode: false\n\n")
                
                f.write("# Storage Settings\n")
                f.write("cache_duration: 3600  # seconds\n")
                f.write("max_cache_size: 10000  # number of records\n")
                f.write("offline_mode: false\n\n")
                
                f.write("# Notification Settings\n")
                f.write("enable_notifications: false\n")
                f.write("notification_webhook: null\n")
                f.write("notification_email: null\n")
                
        except Exception as e:
            print(f"Error: Could not create default config file: {e}")


# Global config instance
_config: Optional[ScamSwatterConfig] = None


def get_config() -> ScamSwatterConfig:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def refresh_config() -> ScamSwatterConfig:
    """Refresh the global configuration from file"""
    global _config
    _config = load_config()
    return _config
