"""
Performance monitoring utilities
Simple performance monitoring and timing utilities for the application
"""

import logging
import time
import functools
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class OperationTimer:
    """Simple operation timer for performance monitoring"""
    
    def __init__(self, operation_name: str):
        self.operation_name = operation_name
        self.start_time = None
        self.end_time = None
        
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        duration = (self.end_time - self.start_time) * 1000  # Convert to milliseconds
        
        if exc_type is None:
            logger.info(f"⏱️ {self.operation_name}: {duration:.2f}ms")
        else:
            logger.warning(f"⏱️ {self.operation_name}: {duration:.2f}ms (failed)")
            
    @property
    def duration_ms(self) -> float:
        """Get duration in milliseconds"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0

def monitor_performance(operation_name: str):
    """
    Decorator to monitor function performance
    
    Args:
        operation_name: Name of the operation being monitored
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            with OperationTimer(f"{operation_name}({func.__name__})"):
                return await func(*args, **kwargs)
                
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            with OperationTimer(f"{operation_name}({func.__name__})"):
                return func(*args, **kwargs)
                
        # Return appropriate wrapper based on whether function is async
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
            
    return decorator

@contextmanager
def performance_timer(operation_name: str):
    """Context manager for timing operations"""
    start_time = time.perf_counter()
    try:
        yield
    finally:
        end_time = time.perf_counter()
        duration = (end_time - start_time) * 1000
        logger.info(f"⏱️ {operation_name}: {duration:.2f}ms")

def log_memory_usage(operation_name: str = "Memory Check"):
    """Log current memory usage"""
    try:
        import psutil
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_mb = memory_info.rss / (1024 * 1024)
        logger.info(f"💾 {operation_name}: {memory_mb:.1f}MB RAM")
    except ImportError:
        logger.debug("psutil not available for memory monitoring")
    except Exception as e:
        logger.warning(f"Failed to get memory usage: {e}")

def get_performance_stats() -> Dict[str, Any]:
    """Get basic performance statistics"""
    try:
        import psutil
        process = psutil.Process()
        memory_info = process.memory_info()
        
        return {
            'memory_mb': memory_info.rss / (1024 * 1024),
            'cpu_percent': process.cpu_percent(),
            'timestamp': datetime.utcnow().isoformat(),
            'process_id': process.pid
        }
    except ImportError:
        return {
            'memory_mb': 0,
            'cpu_percent': 0,
            'timestamp': datetime.utcnow().isoformat(),
            'process_id': 0
        }
    except Exception as e:
        logger.warning(f"Failed to get performance stats: {e}")
        return {
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }

# Ensure asyncio is imported for the decorator
try:
    import asyncio
except ImportError:
    logger.warning("asyncio not available - async performance monitoring disabled")

logger.info("🔧 Performance monitoring system initialized")