"""
Performance caching utilities
Simple in-memory caching for frequently accessed data
"""

import logging
import time
from typing import Dict, Any, Optional, Callable
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SimpleCache:
    """Simple in-memory cache with TTL support"""
    
    def __init__(self, default_ttl: int = 300):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
        
    def get(self, key: str) -> Optional[Any]:
        """Get cached value"""
        try:
            if key in self.cache:
                entry = self.cache[key]
                if entry['expires'] > time.time():
                    return entry['value']
                else:
                    # Expired, remove it
                    del self.cache[key]
            return None
        except Exception as e:
            logger.warning(f"Cache get error: {e}")
            return None
            
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set cached value"""
        try:
            ttl = ttl or self.default_ttl
            self.cache[key] = {
                'value': value,
                'expires': time.time() + ttl,
                'created': time.time()
            }
        except Exception as e:
            logger.warning(f"Cache set error: {e}")
            
    def delete(self, key: str) -> None:
        """Delete cached value"""
        try:
            if key in self.cache:
                del self.cache[key]
        except Exception as e:
            logger.warning(f"Cache delete error: {e}")
            
    def clear(self) -> None:
        """Clear all cached values"""
        self.cache.clear()
        
    def cleanup_expired(self) -> int:
        """Remove expired entries"""
        try:
            current_time = time.time()
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry['expires'] <= current_time
            ]
            for key in expired_keys:
                del self.cache[key]
            return len(expired_keys)
        except Exception as e:
            logger.warning(f"Cache cleanup error: {e}")
            return 0

# Global cache instance
_cache = SimpleCache()

def get_cached(key: str) -> Optional[Any]:
    """Get value from global cache"""
    return _cache.get(key)

def set_cached(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """Set value in global cache"""
    _cache.set(key, value, ttl)

def delete_cached(key: str) -> None:
    """Delete value from global cache"""
    _cache.delete(key)

def clear_cache() -> None:
    """Clear global cache"""
    _cache.clear()

def cache_stats() -> Dict[str, Any]:
    """Get cache statistics"""
    return {
        'total_entries': len(_cache.cache),
        'cache_size_mb': len(str(_cache.cache)) / (1024 * 1024),
        'cleanup_count': _cache.cleanup_expired()
    }

# Legacy function names for compatibility
def cache_get(key: str) -> Optional[Any]:
    """Legacy function name for get_cached"""
    return get_cached(key)

def cache_set(key: str, value: Any, ttl: Optional[int] = None) -> None:
    """Legacy function name for set_cached"""
    set_cached(key, value, ttl)

def cache_invalidate(key: str) -> None:
    """Legacy function name for delete_cached"""
    delete_cached(key)

def cache_invalidate_category(category: str) -> int:
    """Invalidate all cached entries in a category (simplified implementation)"""
    try:
        # Simple implementation - clear all cache for category-based invalidation
        count = 0
        keys_to_delete = [key for key in _cache.cache.keys() if key.startswith(category)]
        for key in keys_to_delete:
            _cache.delete(key)
            count += 1
        return count
    except Exception as e:
        logger.warning(f"Cache category invalidation error: {e}")
        return 0

logger.info("🔧 Performance cache system initialized")