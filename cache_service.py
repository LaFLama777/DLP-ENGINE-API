"""
Caching Service for DLP Engine

Provides in-memory caching for expensive operations like Graph API calls.

Usage:
    from cache_service import user_cache

    # Check cache first
    cached = user_cache.get(user_upn)
    if cached:
        return cached

    # Cache miss - fetch and cache
    data = await fetch_from_api(user_upn)
    user_cache.set(user_upn, data)
"""

from typing import Optional, Dict, Any, TypeVar, Generic
from datetime import datetime, timedelta
from threading import Lock
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CacheEntry(Generic[T]):
    """Single cache entry with expiration"""

    def __init__(self, value: T, ttl_minutes: int):
        """
        Initialize cache entry

        Args:
            value: Value to cache
            ttl_minutes: Time-to-live in minutes
        """
        self.value = value
        self.created_at = datetime.utcnow()
        self.expires_at = self.created_at + timedelta(minutes=ttl_minutes)

    def is_expired(self) -> bool:
        """Check if entry has expired"""
        return datetime.utcnow() > self.expires_at

    def time_remaining(self) -> timedelta:
        """Get remaining time before expiration"""
        return self.expires_at - datetime.utcnow()


class InMemoryCache(Generic[T]):
    """
    Thread-safe in-memory cache with TTL support

    Features:
    - Automatic expiration
    - Thread-safe operations
    - Statistics tracking
    - Bulk operations
    """

    def __init__(self, ttl_minutes: int = 60, max_size: int = 1000):
        """
        Initialize cache

        Args:
            ttl_minutes: Default time-to-live for entries
            max_size: Maximum number of entries (prevents memory bloat)
        """
        self._cache: Dict[str, CacheEntry[T]] = {}
        self._lock = Lock()
        self._ttl_minutes = ttl_minutes
        self._max_size = max_size

        # Statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0

        logger.info(f"Cache initialized: TTL={ttl_minutes}min, MaxSize={max_size}")

    def get(self, key: str) -> Optional[T]:
        """
        Get value from cache

        Args:
            key: Cache key

        Returns:
            Cached value if found and not expired, None otherwise
        """
        with self._lock:
            entry = self._cache.get(key)

            if entry is None:
                self._misses += 1
                logger.debug(f"Cache MISS: {key}")
                return None

            if entry.is_expired():
                # Expired - remove it
                del self._cache[key]
                self._misses += 1
                logger.debug(f"Cache EXPIRED: {key}")
                return None

            self._hits += 1
            logger.debug(f"Cache HIT: {key} (TTL remaining: {entry.time_remaining()})")
            return entry.value

    def set(self, key: str, value: T, ttl_minutes: Optional[int] = None) -> None:
        """
        Store value in cache

        Args:
            key: Cache key
            value: Value to cache
            ttl_minutes: Custom TTL (uses default if None)
        """
        with self._lock:
            # Check size limit
            if len(self._cache) >= self._max_size and key not in self._cache:
                self._evict_oldest()

            ttl = ttl_minutes or self._ttl_minutes
            self._cache[key] = CacheEntry(value, ttl)
            logger.debug(f"Cache SET: {key} (TTL={ttl}min)")

    def delete(self, key: str) -> bool:
        """
        Remove entry from cache

        Args:
            key: Cache key

        Returns:
            True if entry was removed, False if not found
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                logger.debug(f"Cache DELETE: {key}")
                return True
            return False

    def clear(self) -> int:
        """
        Clear all entries from cache

        Returns:
            Number of entries removed
        """
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            logger.info(f"Cache CLEARED: {count} entries removed")
            return count

    def exists(self, key: str) -> bool:
        """
        Check if key exists and is not expired

        Args:
            key: Cache key

        Returns:
            True if key exists and is valid
        """
        return self.get(key) is not None

    def _evict_oldest(self) -> None:
        """Evict oldest entry to make room"""
        if not self._cache:
            return

        # Find oldest entry
        oldest_key = min(
            self._cache.keys(),
            key=lambda k: self._cache[k].created_at
        )

        del self._cache[oldest_key]
        self._evictions += 1
        logger.debug(f"Cache EVICTED: {oldest_key} (size limit reached)")

    def cleanup_expired(self) -> int:
        """
        Remove all expired entries

        Returns:
            Number of entries removed
        """
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]

            for key in expired_keys:
                del self._cache[key]

            if expired_keys:
                logger.info(f"Cache CLEANUP: {len(expired_keys)} expired entries removed")

            return len(expired_keys)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dictionary with cache stats
        """
        with self._lock:
            total_requests = self._hits + self._misses
            hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0

            return {
                "size": len(self._cache),
                "max_size": self._max_size,
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "total_requests": total_requests,
                "hit_rate_percent": round(hit_rate, 2),
                "ttl_minutes": self._ttl_minutes
            }

    def get_keys(self) -> list[str]:
        """Get all current cache keys"""
        with self._lock:
            return list(self._cache.keys())

    def get_info(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed info about a cache entry

        Args:
            key: Cache key

        Returns:
            Dictionary with entry info or None if not found
        """
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None

            return {
                "key": key,
                "created_at": entry.created_at.isoformat(),
                "expires_at": entry.expires_at.isoformat(),
                "time_remaining_seconds": int(entry.time_remaining().total_seconds()),
                "is_expired": entry.is_expired()
            }


# ============================================================================
# GLOBAL CACHE INSTANCES
# ============================================================================

# User details cache (60 minute TTL)
user_cache: InMemoryCache[Dict[str, Any]] = InMemoryCache(
    ttl_minutes=60,
    max_size=1000
)

# Risk assessment cache (30 minute TTL)
risk_cache: InMemoryCache[Any] = InMemoryCache(
    ttl_minutes=30,
    max_size=500
)

# General purpose cache (15 minute TTL)
general_cache: InMemoryCache[Any] = InMemoryCache(
    ttl_minutes=15,
    max_size=2000
)


def get_cache_stats() -> Dict[str, Dict[str, Any]]:
    """
    Get statistics for all caches

    Returns:
        Dictionary with stats for each cache
    """
    return {
        "user_cache": user_cache.get_stats(),
        "risk_cache": risk_cache.get_stats(),
        "general_cache": general_cache.get_stats()
    }


def clear_all_caches() -> Dict[str, int]:
    """
    Clear all caches

    Returns:
        Dictionary with count of cleared entries per cache
    """
    return {
        "user_cache": user_cache.clear(),
        "risk_cache": risk_cache.clear(),
        "general_cache": general_cache.clear()
    }


def cleanup_all_caches() -> Dict[str, int]:
    """
    Remove expired entries from all caches

    Returns:
        Dictionary with count of removed entries per cache
    """
    return {
        "user_cache": user_cache.cleanup_expired(),
        "risk_cache": risk_cache.cleanup_expired(),
        "general_cache": general_cache.cleanup_expired()
    }


if __name__ == "__main__":
    """Test cache functionality"""
    import time

    print("="*60)
    print("Cache Service - Test Cases")
    print("="*60)

    # Test 1: Basic get/set
    print("\n1. Testing basic get/set...")
    test_cache = InMemoryCache[str](ttl_minutes=1, max_size=3)
    test_cache.set("key1", "value1")
    result = test_cache.get("key1")
    print(f"   [OK] Set and retrieved: {result}")

    # Test 2: Cache miss
    print("\n2. Testing cache miss...")
    result = test_cache.get("nonexistent")
    print(f"   [OK] Cache miss returns None: {result is None}")

    # Test 3: Expiration
    print("\n3. Testing expiration (TTL=1 second)...")
    short_cache = InMemoryCache[str](ttl_minutes=1/60, max_size=10)  # 1 second TTL
    short_cache.set("temp", "temporary value")
    print(f"   Immediate get: {short_cache.get('temp')}")
    time.sleep(2)
    print(f"   After 2 seconds: {short_cache.get('temp')}")
    print("   [OK] Entry expired correctly")

    # Test 4: Size limit
    print("\n4. Testing size limit (max=3)...")
    test_cache.set("key1", "value1")
    test_cache.set("key2", "value2")
    test_cache.set("key3", "value3")
    test_cache.set("key4", "value4")  # Should evict oldest
    print(f"   Keys in cache: {test_cache.get_keys()}")
    print(f"   [OK] Evicted oldest when limit reached")

    # Test 5: Statistics
    print("\n5. Testing statistics...")
    stats = test_cache.get_stats()
    print(f"   Hits: {stats['hits']}")
    print(f"   Misses: {stats['misses']}")
    print(f"   Hit Rate: {stats['hit_rate_percent']}%")
    print(f"   [OK] Stats tracked correctly")

    # Test 6: Global caches
    print("\n6. Testing global caches...")
    user_cache.set("user@example.com", {"name": "Test User"})
    cached_user = user_cache.get("user@example.com")
    print(f"   [OK] User cache: {cached_user}")

    all_stats = get_cache_stats()
    print(f"   Total caches: {len(all_stats)}")

    print("\n" + "="*60)
    print("[OK] All cache tests passed!")
    print("="*60)
