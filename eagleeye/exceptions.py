"""
Custom exception classes for EagleEye with comprehensive error handling
"""
from typing import Optional, Dict, Any
import traceback
from enum import Enum


class ErrorCode(Enum):
    """Standard error codes for EagleEye"""
    
    # General errors
    UNKNOWN_ERROR = "E001"
    CONFIGURATION_ERROR = "E002" 
    VALIDATION_ERROR = "E003"
    TIMEOUT_ERROR = "E004"
    
    # Data source errors
    SOURCE_UNAVAILABLE = "E101"
    SOURCE_AUTH_ERROR = "E102"
    SOURCE_RATE_LIMIT = "E103"
    SOURCE_PARSE_ERROR = "E104"
    
    # Analysis errors
    ANALYSIS_FAILED = "E201"
    MODEL_NOT_FOUND = "E202"
    INSUFFICIENT_DATA = "E203"
    
    # Database errors
    DATABASE_ERROR = "E301"
    DATABASE_CONNECTION = "E302"
    QUERY_FAILED = "E303"
    
    # Network errors
    NETWORK_ERROR = "E401"
    API_ERROR = "E402"
    HTTP_ERROR = "E403"
    
    # File system errors
    FILE_NOT_FOUND = "E501"
    FILE_PERMISSION = "E502"
    FILE_CORRUPTED = "E503"


class EagleEyeException(Exception):
    """Base exception for all EagleEye errors"""
    
    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.UNKNOWN_ERROR,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.cause = cause
        
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging"""
        return {
            'error_code': self.error_code.value,
            'message': self.message,
            'details': self.details,
            'cause': str(self.cause) if self.cause else None,
            'traceback': traceback.format_exc()
        }


class ConfigurationError(EagleEyeException):
    """Raised when configuration is invalid or missing"""
    
    def __init__(self, message: str, config_key: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if config_key:
            details['config_key'] = config_key
        
        super().__init__(
            message,
            error_code=ErrorCode.CONFIGURATION_ERROR,
            details=details,
            **kwargs
        )


class ValidationError(EagleEyeException):
    """Raised when input validation fails"""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Any = None, **kwargs):
        details = kwargs.get('details', {})
        if field:
            details['field'] = field
        if value is not None:
            details['value'] = str(value)
        
        super().__init__(
            message,
            error_code=ErrorCode.VALIDATION_ERROR,
            details=details,
            **kwargs
        )


class SourceError(EagleEyeException):
    """Base class for data source errors"""
    
    def __init__(self, message: str, source_name: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if source_name:
            details['source_name'] = source_name
        
        super().__init__(
            message,
            error_code=ErrorCode.SOURCE_UNAVAILABLE,
            details=details,
            **kwargs
        )


class SourceAuthenticationError(SourceError):
    """Raised when source authentication fails"""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message,
            error_code=ErrorCode.SOURCE_AUTH_ERROR,
            **kwargs
        )


class SourceRateLimitError(SourceError):
    """Raised when source rate limit is exceeded"""
    
    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs):
        details = kwargs.get('details', {})
        if retry_after:
            details['retry_after'] = retry_after
        
        super().__init__(
            message,
            error_code=ErrorCode.SOURCE_RATE_LIMIT,
            details=details,
            **kwargs
        )


class AnalysisError(EagleEyeException):
    """Raised when analysis operations fail"""
    
    def __init__(self, message: str, analysis_type: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if analysis_type:
            details['analysis_type'] = analysis_type
        
        super().__init__(
            message,
            error_code=ErrorCode.ANALYSIS_FAILED,
            details=details,
            **kwargs
        )


class DatabaseError(EagleEyeException):
    """Raised when database operations fail"""
    
    def __init__(self, message: str, operation: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if operation:
            details['operation'] = operation
        
        super().__init__(
            message,
            error_code=ErrorCode.DATABASE_ERROR,
            details=details,
            **kwargs
        )


class NetworkError(EagleEyeException):
    """Raised when network operations fail"""
    
    def __init__(self, message: str, url: Optional[str] = None, status_code: Optional[int] = None, **kwargs):
        details = kwargs.get('details', {})
        if url:
            details['url'] = url
        if status_code:
            details['status_code'] = status_code
        
        super().__init__(
            message,
            error_code=ErrorCode.NETWORK_ERROR,
            details=details,
            **kwargs
        )


class FileError(EagleEyeException):
    """Raised when file operations fail"""
    
    def __init__(self, message: str, file_path: Optional[str] = None, **kwargs):
        details = kwargs.get('details', {})
        if file_path:
            details['file_path'] = file_path
        
        super().__init__(
            message,
            error_code=ErrorCode.FILE_NOT_FOUND,
            details=details,
            **kwargs
        )


def handle_exception(
    func_name: str,
    exception: Exception,
    logger=None,
    reraise: bool = True
) -> Optional[EagleEyeException]:
    """
    Handle and convert exceptions to EagleEye exceptions
    
    Args:
        func_name: Name of the function where exception occurred
        exception: The original exception
        logger: Logger instance to use
        reraise: Whether to reraise the exception
    
    Returns:
        EagleEyeException if not reraised
    """
    
    # Convert common exceptions to EagleEye exceptions
    if isinstance(exception, EagleEyeException):
        eagle_exception = exception
    elif isinstance(exception, (ConnectionError, TimeoutError)):
        eagle_exception = NetworkError(
            f"Network error in {func_name}: {exception}",
            cause=exception
        )
    elif isinstance(exception, FileNotFoundError):
        eagle_exception = FileError(
            f"File not found in {func_name}: {exception}",
            cause=exception
        )
    elif isinstance(exception, PermissionError):
        eagle_exception = FileError(
            f"Permission denied in {func_name}: {exception}",
            error_code=ErrorCode.FILE_PERMISSION,
            cause=exception
        )
    elif isinstance(exception, ValueError):
        eagle_exception = ValidationError(
            f"Validation error in {func_name}: {exception}",
            cause=exception
        )
    else:
        eagle_exception = EagleEyeException(
            f"Unexpected error in {func_name}: {exception}",
            cause=exception
        )
    
    # Log the exception
    if logger:
        logger.error(
            f"Exception in {func_name}: {eagle_exception.message}",
            extra=eagle_exception.to_dict()
        )
    
    if reraise:
        raise eagle_exception
    else:
        return eagle_exception


def safe_execute(func, *args, logger=None, default=None, **kwargs):
    """
    Safely execute a function with exception handling
    
    Args:
        func: Function to execute
        *args: Function arguments
        logger: Logger instance
        default: Default value to return on error
        **kwargs: Function keyword arguments
    
    Returns:
        Function result or default value on error
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        handle_exception(func.__name__, e, logger, reraise=False)
        return default


async def safe_execute_async(func, *args, logger=None, default=None, **kwargs):
    """
    Safely execute an async function with exception handling
    
    Args:
        func: Async function to execute
        *args: Function arguments
        logger: Logger instance
        default: Default value to return on error
        **kwargs: Function keyword arguments
    
    Returns:
        Function result or default value on error
    """
    try:
        return await func(*args, **kwargs)
    except Exception as e:
        handle_exception(func.__name__, e, logger, reraise=False)
        return default


class ErrorHandler:
    """Context manager for error handling"""
    
    def __init__(self, operation_name: str, logger=None):
        self.operation_name = operation_name
        self.logger = logger
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            handle_exception(
                self.operation_name,
                exc_val,
                self.logger,
                reraise=True
            )
        return False


class RetryHandler:
    """Utility for handling retries with exponential backoff"""
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0,
        retriable_exceptions: tuple = (NetworkError, SourceError)
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.retriable_exceptions = retriable_exceptions
    
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Determine if an exception should trigger a retry"""
        if attempt >= self.max_retries:
            return False
        
        if isinstance(exception, self.retriable_exceptions):
            return True
        
        return False
    
    def get_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt"""
        delay = self.base_delay * (self.backoff_factor ** attempt)
        return min(delay, self.max_delay)