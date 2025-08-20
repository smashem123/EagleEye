"""
Comprehensive logging configuration for EagleEye
"""
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
import json
from datetime import datetime


class EagleEyeFormatter(logging.Formatter):
    """Custom formatter for EagleEye logs with color support"""
    
    # Color codes for different log levels
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green  
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors and sys.stderr.isatty()
        super().__init__()
    
    def format(self, record):
        # Add timestamp
        record.timestamp = datetime.now().isoformat()
        
        # Basic format
        log_format = '[{timestamp}] {levelname:8} {name:20} | {message}'
        
        if self.use_colors:
            color = self.COLORS.get(record.levelname, '')
            reset = self.COLORS['RESET']
            log_format = f'{color}{log_format}{reset}'
        
        formatter = logging.Formatter(log_format, style='{')
        return formatter.format(record)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'lineno', 'funcName', 'created', 
                          'msecs', 'relativeCreated', 'thread', 'threadName', 
                          'processName', 'process', 'exc_info', 'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    json_format: bool = False,
    enable_console: bool = True
) -> logging.Logger:
    """
    Setup comprehensive logging for EagleEye
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (optional)
        max_file_size: Maximum size per log file in bytes
        backup_count: Number of backup files to keep
        json_format: Use JSON formatting for structured logs
        enable_console: Enable console logging
    
    Returns:
        Configured logger instance
    """
    
    # Get or create root logger
    logger = logging.getLogger('eagleeye')
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.INFO)
        
        if json_format:
            console_handler.setFormatter(JSONFormatter())
        else:
            console_handler.setFormatter(EagleEyeFormatter(use_colors=True))
        
        logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        if max_file_size > 0:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_file_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
        else:
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
        
        file_handler.setLevel(logging.DEBUG)
        
        if json_format:
            file_handler.setFormatter(JSONFormatter())
        else:
            file_formatter = logging.Formatter(
                '[{asctime}] {levelname:8} {name:20} | {message}',
                style='{',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
        
        logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for a specific module"""
    return logging.getLogger(f'eagleeye.{name}')


class LoggerMixin:
    """Mixin class to add logging capabilities to any class"""
    
    @property
    def logger(self) -> logging.Logger:
        if not hasattr(self, '_logger'):
            self._logger = get_logger(self.__class__.__name__)
        return self._logger


def log_performance(func):
    """Decorator to log function performance"""
    import functools
    import time
    
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger('performance')
        start_time = time.time()
        
        try:
            result = func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.debug(
                f"{func.__name__} completed in {execution_time:.3f}s",
                extra={
                    'function': func.__name__,
                    'execution_time': execution_time,
                    'success': True
                }
            )
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(
                f"{func.__name__} failed after {execution_time:.3f}s: {e}",
                extra={
                    'function': func.__name__,
                    'execution_time': execution_time,
                    'success': False,
                    'error': str(e)
                }
            )
            raise
    
    return wrapper


def log_async_performance(func):
    """Decorator to log async function performance"""
    import functools
    import time
    import asyncio
    
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        logger = get_logger('performance')
        start_time = time.time()
        
        try:
            result = await func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.debug(
                f"{func.__name__} completed in {execution_time:.3f}s",
                extra={
                    'function': func.__name__,
                    'execution_time': execution_time,
                    'success': True
                }
            )
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(
                f"{func.__name__} failed after {execution_time:.3f}s: {e}",
                extra={
                    'function': func.__name__,
                    'execution_time': execution_time,
                    'success': False,
                    'error': str(e)
                }
            )
            raise
    
    return wrapper


# Initialize default logging
def init_default_logging():
    """Initialize default logging configuration"""
    from pathlib import Path
    
    # Get user config directory
    config_dir = Path.home() / '.eagleeye'
    log_file = config_dir / 'logs' / 'eagleeye.log'
    
    return setup_logging(
        log_level="INFO",
        log_file=log_file,
        enable_console=True
    )


# Auto-initialize logging when module is imported
_default_logger = None

def ensure_logging():
    """Ensure logging is initialized"""
    global _default_logger
    if _default_logger is None:
        _default_logger = init_default_logging()
    return _default_logger