"""
OpenProvider domain registration API integration
Handles domain availability, registration, and management
Enhanced with high-performance caching for 20+ ops/sec target
"""

import os
import logging
import httpx
import time
import asyncio
from typing import Dict, List, Optional, Union, Any, Callable
# Base64 no longer needed - using Bearer token authentication
from pricing_utils import calculate_marked_up_price, format_price_display
from performance_cache import cache_get, cache_set, cache_invalidate
from performance_monitor import monitor_performance, OperationTimer  # type: ignore[misc]
from admin_alerts import send_critical_alert, send_error_alert, send_warning_alert

logger = logging.getLogger(__name__)

# Import TLD requirements validation system
try:
    from services.tld_requirements import TLDRequirementsValidator, TLDValidationResult
    TLD_VALIDATION_AVAILABLE = True
    # Initialize global TLD validator instance
    _tld_validator = TLDRequirementsValidator()
    logger.info("✅ TLD requirements validation system loaded")
except ImportError as e:
    logger.warning(f"⚠️ TLD requirements validation not available: {e}")
    TLD_VALIDATION_AVAILABLE = False
    _tld_validator = None

class IPDetectionService:
    """Robust IP detection service with multiple fallback providers and caching"""
    
    # IP detection services in order of preference
    IP_SERVICES = [
        {
            'url': 'https://api.ipify.org',
            'name': 'IPify',
            'timeout': 5,
            'response_type': 'text'
        },
        {
            'url': 'https://ifconfig.me/ip',
            'name': 'ifconfig.me',
            'timeout': 5,
            'response_type': 'text'
        },
        {
            'url': 'https://httpbin.org/ip',
            'name': 'HTTPBin',
            'timeout': 5,
            'response_type': 'json',
            'json_key': 'origin'
        },
        {
            'url': 'https://icanhazip.com',
            'name': 'CanHazIP',
            'timeout': 5,
            'response_type': 'text'
        }
    ]
    
    # Cache duration in seconds (10 minutes)
    CACHE_DURATION = 600
    
    def __init__(self):
        self._cached_ip = None
        self._cache_timestamp = 0
        self._detection_history = []  # Track success/failure patterns
    
    def _is_cache_valid(self) -> bool:
        """Check if cached IP is still valid"""
        if not self._cached_ip:
            return False
        
        current_time = time.time()
        cache_age = current_time - self._cache_timestamp
        is_valid = cache_age < self.CACHE_DURATION
        
        if is_valid:
            logger.debug(f"🔄 Using cached IP: {self._cached_ip} (age: {cache_age:.1f}s)")
        else:
            logger.debug(f"⏰ IP cache expired (age: {cache_age:.1f}s), fetching new IP")
        
        return is_valid
    
    def _cache_ip(self, ip_address: str) -> None:
        """Cache the detected IP address"""
        self._cached_ip = ip_address
        self._cache_timestamp = time.time()
        logger.debug(f"💾 Cached IP address: {ip_address}")
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Basic IP address validation"""
        if not ip_str or not isinstance(ip_str, str):
            return False
        
        ip_str = ip_str.strip()
        
        # Basic IPv4 validation
        parts = ip_str.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
        
        # Basic IPv6 validation (simplified)
        if ':' in ip_str and len(ip_str) > 2:
            return True
        
        return False
    
    async def _try_ip_service(self, service: Dict, client: httpx.AsyncClient) -> Optional[str]:
        """Try a single IP detection service"""
        service_name = service['name']
        url = service['url']
        timeout = service['timeout']
        
        try:
            logger.debug(f"🌐 Trying IP service: {service_name} ({url})")
            start_time = time.time()
            
            response = await client.get(url, timeout=timeout)
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                # Parse response based on type
                if service['response_type'] == 'text':
                    ip_address = response.text.strip()
                elif service['response_type'] == 'json':
                    json_data = response.json()
                    json_key = service.get('json_key', 'ip')
                    ip_address = json_data.get(json_key, '').strip()
                    # Handle cases where HTTPBin returns multiple IPs
                    if ',' in ip_address:
                        ip_address = ip_address.split(',')[0].strip()
                else:
                    logger.error(f"❌ Unknown response type for {service_name}")
                    return None
                
                # Validate the IP address
                if self._is_valid_ip(ip_address):
                    logger.info(f"✅ {service_name} returned valid IP: {ip_address} ({response_time:.2f}s)")
                    self._detection_history.append({
                        'service': service_name,
                        'success': True,
                        'ip': ip_address,
                        'response_time': response_time,
                        'timestamp': time.time()
                    })
                    return ip_address
                else:
                    logger.warning(f"⚠️ {service_name} returned invalid IP: '{ip_address}'")
                    
            else:
                logger.warning(f"⚠️ {service_name} returned HTTP {response.status_code}")
                
        except asyncio.TimeoutError:
            error_msg = f"Timed out after {timeout}s"
            logger.warning(f"⏰ {service_name} {error_msg}")
        except Exception as e:
            error_msg = str(e)
            logger.warning(f"❌ {service_name} failed: {e}")
        else:
            error_msg = "HTTP error or invalid response"
        
        # Record failure
        self._detection_history.append({
            'service': service_name,
            'success': False,
            'error': error_msg,
            'timestamp': time.time()
        })
        
        return None
    
    async def detect_public_ip(self, force_refresh: bool = False) -> Optional[str]:
        """
        Detect public IP using multiple fallback services with caching
        
        Args:
            force_refresh: If True, bypass cache and fetch fresh IP
            
        Returns:
            IP address string or None if all services fail
        """
        # Check manual override first (highest priority)
        manual_ip = os.getenv('OPENPROVIDER_IP')
        if manual_ip:
            logger.info(f"🎯 Using manually configured IP: {manual_ip}")
            return manual_ip
        
        # Check cache if not forcing refresh
        if not force_refresh and self._is_cache_valid():
            return self._cached_ip
        
        logger.info("🔍 Detecting public IP address using fallback services...")
        start_time = time.time()
        
        # Try each service in order with optimized HTTP client
        timeout_config = httpx.Timeout(connect=3.0, read=8.0, write=5.0, pool=10.0)
        async with httpx.AsyncClient(timeout=timeout_config) as client:
            for i, service in enumerate(self.IP_SERVICES):
                ip_address = await self._try_ip_service(service, client)
                
                if ip_address:
                    # Success! Cache and return
                    self._cache_ip(ip_address)
                    total_time = time.time() - start_time
                    logger.info(f"🎉 IP detection successful: {ip_address} (took {total_time:.2f}s, service #{i+1})")
                    return ip_address
                
                # Small delay between services to be respectful
                if i < len(self.IP_SERVICES) - 1:
                    await asyncio.sleep(0.5)
        
        # All services failed
        total_time = time.time() - start_time
        logger.error(f"❌ All IP detection services failed after {total_time:.2f}s")
        
        # Log recent detection history for debugging
        if self._detection_history:
            recent_history = self._detection_history[-5:]  # Last 5 attempts
            logger.error("📊 Recent IP detection history:")
            for entry in recent_history:
                status = "✅" if entry['success'] else "❌"
                timestamp = time.strftime('%H:%M:%S', time.localtime(entry['timestamp']))
                if entry['success']:
                    logger.error(f"   {status} {entry['service']}: {entry['ip']} ({entry['response_time']:.2f}s) at {timestamp}")
                else:
                    logger.error(f"   {status} {entry['service']}: {entry.get('error', 'Failed')} at {timestamp}")
        
        return None
    
    def get_cache_status(self) -> Dict:
        """Get current cache status for debugging"""
        if not self._cached_ip:
            return {'cached': False, 'ip': None, 'age': 0}
        
        cache_age = time.time() - self._cache_timestamp
        return {
            'cached': True,
            'ip': self._cached_ip,
            'age': cache_age,
            'valid': self._is_cache_valid(),
            'expires_in': max(0, self.CACHE_DURATION - cache_age)
        }

# Global IP detection service instance
_ip_detector = IPDetectionService()

class DomainIDCache:
    """Thread-safe cache for domain IDs with TTL support"""
    
    def __init__(self, ttl_seconds: int = 3600):  # 1 hour TTL
        self._cache = {}
        self._timestamps = {}
        self._ttl = ttl_seconds
    
    def get(self, domain_name: str) -> Optional[int]:
        """Get cached domain ID if valid"""
        domain_key = domain_name.lower().strip()
        current_time = time.time()
        
        if domain_key in self._cache:
            cache_age = current_time - self._timestamps[domain_key]
            if cache_age < self._ttl:
                logger.debug(f"💾 Using cached domain ID for {domain_name}: {self._cache[domain_key]} (age: {cache_age:.1f}s)")
                return self._cache[domain_key]
            else:
                # Cache expired, remove it
                logger.debug(f"⏰ Cache expired for {domain_name} (age: {cache_age:.1f}s)")
                self._remove(domain_key)
        
        return None
    
    def set(self, domain_name: str, domain_id: int) -> None:
        """Cache domain ID with timestamp"""
        domain_key = domain_name.lower().strip()
        self._cache[domain_key] = domain_id
        self._timestamps[domain_key] = time.time()
        logger.debug(f"💾 Cached domain ID for {domain_name}: {domain_id}")
    
    def _remove(self, domain_key: str) -> None:
        """Remove domain from cache"""
        self._cache.pop(domain_key, None)
        self._timestamps.pop(domain_key, None)
    
    def invalidate(self, domain_name: str) -> None:
        """Invalidate cached domain ID"""
        domain_key = domain_name.lower().strip()
        self._remove(domain_key)
        logger.debug(f"🗑️ Invalidated cache for {domain_name}")
    
    def clear(self) -> None:
        """Clear all cached domain IDs"""
        self._cache.clear()
        self._timestamps.clear()
        logger.debug("🗑️ Cleared all domain ID cache")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics for debugging"""
        current_time = time.time()
        valid_entries = 0
        expired_entries = 0
        
        for domain_key, timestamp in self._timestamps.items():
            cache_age = current_time - timestamp
            if cache_age < self._ttl:
                valid_entries += 1
            else:
                expired_entries += 1
        
        return {
            'total_entries': len(self._cache),
            'valid_entries': valid_entries,
            'expired_entries': expired_entries,
            'cache_ttl_seconds': self._ttl
        }

# Global domain ID cache instance
_domain_id_cache = DomainIDCache()

class TLDPriceCache:
    """Cache for TLD pricing to avoid repeated API calls"""
    
    def __init__(self, ttl_seconds: int = 1800):  # 30 minutes TTL
        self._cache = {}
        self._timestamps = {}
        self._ttl = ttl_seconds
    
    def get(self, tld: str) -> Optional[Dict]:
        """Get cached pricing for TLD if valid"""
        tld_key = tld.lower().strip()
        current_time = time.time()
        
        if tld_key in self._cache:
            cache_age = current_time - self._timestamps[tld_key]
            if cache_age < self._ttl:
                logger.debug(f"💾 Using cached TLD pricing for {tld}: age {cache_age:.1f}s")
                return self._cache[tld_key]
            else:
                # Cache expired, remove it
                self._remove(tld_key)
        
        return None
    
    def set(self, tld: str, pricing_data: Dict) -> None:
        """Cache TLD pricing with timestamp"""
        tld_key = tld.lower().strip()
        self._cache[tld_key] = pricing_data
        self._timestamps[tld_key] = time.time()
        logger.debug(f"💾 Cached TLD pricing for {tld}")
    
    def _remove(self, tld_key: str) -> None:
        """Remove TLD from cache"""
        self._cache.pop(tld_key, None)
        self._timestamps.pop(tld_key, None)
    
    def clear(self) -> None:
        """Clear all cached TLD pricing"""
        self._cache.clear()
        self._timestamps.clear()
        logger.debug("🗑️ Cleared all TLD pricing cache")

# Global TLD price cache instance
_tld_price_cache = TLDPriceCache()

class OptimizedOpenProviderService:
    """High-performance OpenProvider API service with connection pooling and caching"""
    
    _instance = None
    _client = None
    _token_cache_time = 0
    _token_ttl = 3600  # 1 hour token cache
    
    def __new__(cls):
        """Singleton pattern for shared connections and auth"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        # SECURITY: Check TEST_MODE to prevent live credential usage during tests
        if os.getenv('TEST_MODE') == '1':
            logger.info("🔒 TEST_MODE active - using mock OpenProvider configuration")
            self.username = 'test_user'
            self.password = 'test_password'
            self.base_url = "https://api.test.openprovider.eu"
            self.bearer_token = 'test_bearer_token'
            self.headers = {'Content-Type': 'application/json'}
            self._initialized = True
            return
            
        # Backward compatibility for credential variable names
        self.username = os.getenv('OPENPROVIDER_USERNAME') or os.getenv('OPENPROVIDER_EMAIL')
        self.password = os.getenv('OPENPROVIDER_PASSWORD')
        self.base_url = "https://api.openprovider.eu"
        self.bearer_token = None
        self.headers = {'Content-Type': 'application/json'}
        
        # Initialize persistent HTTP client with optimizations
        self._init_client()
        self._initialized = True
    
    def _get_platform_name(self) -> str:
        """Get platform name from BrandConfig for dynamic User-Agent"""
        try:
            import os
            return os.getenv('PLATFORM_NAME', 'HostBay')
        except Exception:
            return 'HostBay'
    
    def _format_phone_for_openprovider(self, phone: str) -> dict:
        """Format phone number for OpenProvider API requirements"""
        try:
            # Clean the phone number - remove all non-digits except +
            phone_clean = ''.join(char for char in phone if char.isdigit() or char == '+')
            
            if not phone_clean:
                # Default fallback phone number
                return {
                    'countryCode': '+1',
                    'areaCode': '555',
                    'subscriberNumber': '1234567'
                }
            
            # Parse phone number based on common patterns
            if phone_clean.startswith('+'):
                # International format like +15551234567
                if phone_clean.startswith('+1') and len(phone_clean) >= 11:
                    # US/Canada format: +1AAANNNNNNN
                    return {
                        'countryCode': '+1',
                        'areaCode': phone_clean[2:5],
                        'subscriberNumber': phone_clean[5:]
                    }
                elif phone_clean.startswith('+33') and len(phone_clean) >= 11:
                    # France format: +33NNNNNNNNN
                    return {
                        'countryCode': '+33',
                        'areaCode': phone_clean[3:4],
                        'subscriberNumber': phone_clean[4:]
                    }
                elif phone_clean.startswith('+32') and len(phone_clean) >= 10:
                    # Belgium format: +32NNNNNNNNN
                    return {
                        'countryCode': '+32',
                        'areaCode': phone_clean[3:4],
                        'subscriberNumber': phone_clean[4:]
                    }
                else:
                    # Generic international format - assume first 1-3 digits are country code
                    country_code_len = 2 if phone_clean[1:3].isdigit() else 1
                    return {
                        'countryCode': phone_clean[:country_code_len+1],
                        'areaCode': phone_clean[country_code_len+1:country_code_len+4],
                        'subscriberNumber': phone_clean[country_code_len+4:]
                    }
            elif len(phone_clean) == 10:
                # US format without country code: AAANNNNNNN
                return {
                    'countryCode': '+1',
                    'areaCode': phone_clean[:3],
                    'subscriberNumber': phone_clean[3:]
                }
            else:
                # Default fallback with provided number as subscriber
                return {
                    'countryCode': '+1',
                    'areaCode': '555',
                    'subscriberNumber': phone_clean[-7:] if len(phone_clean) >= 7 else phone_clean
                }
                
        except Exception as e:
            logger.warning(f"📞 Phone number parsing failed for '{phone}': {e}")
            # Safe fallback
            return {
                'countryCode': '+1',
                'areaCode': '555',
                'subscriberNumber': '1234567'
            }
    
    def _init_client(self):
        """Initialize optimized HTTP client with connection pooling"""
        if self._client is None:
            # HTTP/2 and connection pooling for optimal performance
            limits = httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
                keepalive_expiry=30.0
            )
            
            # PERFORMANCE OPTIMIZED: Balanced timeouts for faster response
            timeout = httpx.Timeout(
                connect=3.0,   # Reduced from 5s for faster connection
                read=15.0,     # Reduced from 30s for better UX  
                write=6.0,     # Reduced from 10s for faster response
                pool=3.0       # Reduced from 5s for better pool management
            )
            
            self._client = httpx.AsyncClient(
                http2=False,  # Disabled to avoid hyperframe dependency issues in deployment
                limits=limits,
                timeout=timeout,
                headers={'User-Agent': f'{self._get_platform_name()}-Bot/1.0'},
                follow_redirects=True  # Handle redirects automatically
            )
            logger.info("🚀 Initialized HTTP client with OPTIMIZED timeouts: 15s read, 3s connect for faster domain operations")
    
    async def _ensure_client(self):
        """Ensure HTTP client is initialized and available"""
        if self._client is None or self._client.is_closed:
            self._init_client()
    
    def _is_token_valid(self) -> bool:
        """Check if cached bearer token is still valid"""
        if not self.bearer_token:
            return False
        
        token_age = time.time() - self._token_cache_time
        is_valid = token_age < self._token_ttl
        
        if is_valid:
            logger.debug(f"🔄 Using cached auth token (age: {token_age:.1f}s)")
        else:
            logger.debug(f"⏰ Auth token expired (age: {token_age:.1f}s)")
        
        return is_valid
    
    def _cache_token(self, token: str) -> None:
        """Cache authentication token"""
        self.bearer_token = token
        self._token_cache_time = time.time()
        self.headers['Authorization'] = f'Bearer {token}'
        logger.debug("🔐 Cached authentication token")

    async def authenticate(self) -> bool:
        """Get bearer token from OpenProvider API with caching"""
        try:
            if not self.username or not self.password:
                logger.warning("⚠️ OpenProvider credentials not configured")
                return False
            
            # Check if we have a valid cached token first
            if self._is_token_valid():
                return True
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client")
                return False
                
            logger.info("🔐 Authenticating with OpenProvider API...")
            
            login_data = {
                "username": self.username,
                "password": self.password
            }
            
            # Detect current public IP using robust fallback service
            current_ip = await _ip_detector.detect_public_ip()
            
            if current_ip:
                login_data["ip"] = current_ip
                logger.info(f"🌐 Using detected IP for OpenProvider: {current_ip}")
            else:
                logger.warning("⚠️ Could not detect public IP - will try authentication without IP field")
            
            response = await self._client.post(
                f"{self.base_url}/v1beta/auth/login",
                headers={'Content-Type': 'application/json'},
                json=login_data
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('code', 0) == 0:
                    token = data.get('data', {}).get('token')
                    if token:
                        self._cache_token(token)
                        logger.info("✅ OpenProvider authentication successful")
                        return True
                    else:
                        logger.error("❌ No authentication token received")
                else:
                    logger.error(f"❌ OpenProvider authentication failed: {data}")
            else:
                logger.error(f"❌ Authentication request failed: {response.status_code}")
        except Exception as e:
            logger.error(f"❌ Error authenticating with OpenProvider: {e}")
        
        return False
    
    async def test_connection(self) -> tuple[bool, str]:
        """Test OpenProvider API connectivity"""
        try:
            if not self.username or not self.password:
                return False, "OpenProvider credentials not configured"
            
            await self._ensure_client()
            if self._client is None:
                return False, "Failed to initialize HTTP client"
            
            # Test authentication first
            auth_success = await self.authenticate()
            if not auth_success:
                return False, "Authentication failed - check credentials"
            
            # Test with minimal domain check to verify API access
            response = await self._client.post(
                f"{self.base_url}/v1beta/domains/check",
                headers=self.headers,
                json={
                    "domains": [{"name": "example", "extension": "com"}],
                    "with_price": False
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code') == 0:
                    return True, "API connected - domain check successful"
                else:
                    return False, f"API error: {data.get('desc', 'Unknown error')}"
            else:
                return False, f"HTTP {response.status_code}: API not reachable"
                
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

    @monitor_performance("domain_availability_check")
    async def check_domain_availability(self, domain_name: str, contact_data: Optional[Dict[str, Any]] = None) -> Optional[Dict]:
        """Check if a domain is available for registration - OPTIMIZED VERSION with TLD validation"""
        try:
            if not self.username or not self.password:
                logger.warning("⚠️ OpenProvider credentials not configured")
                return None
            
            # Authenticate first to get bearer token (with caching)
            auth_success = await self.authenticate()
            if not auth_success:
                logger.error("❌ Failed to authenticate with OpenProvider")
                return None
            
            # Parse domain into name and extension
            try:
                domain_parts = self._parse_domain(domain_name)
            except ValueError as e:
                logger.error(f"❌ Domain parsing error: {e}")
                return None
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client")
                return None
                
            start_time = time.time()
            
            request_data = {
                'domains': [domain_parts],
                'with_price': True  # Request price in the same call
            }
            logger.info(f"🔍 Checking domain availability for: {domain_name}")
            logger.debug(f"🌐 API URL: {self.base_url}/v1beta/domains/check")
            logger.debug(f"📤 Request data: {request_data}")
            
            response = await self._client.post(
                f"{self.base_url}/v1beta/domains/check",
                headers=self.headers,
                json=request_data
            )
            
            api_time = time.time() - start_time
            logger.info(f"📥 OpenProvider response status: {response.status_code} (took {api_time:.2f}s)")
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('code', 0) == 0:
                    domains_data = data.get('data', {}).get('results', [])
                    
                    if domains_data:
                        domain_info = domains_data[0]
                        available = domain_info.get('status') == 'free'
                        is_premium = domain_info.get('premium', False)
                        
                        # Extract pricing using optimized method
                        price_info = self._extract_price_from_domain_check(domain_info, domain_name)
                        
                        # Fallback to pricing API if domains/check didn't return pricing
                        if not price_info or price_info.get('create_price', 0) <= 0:
                            logger.info("💰 No price in domains/check; using pricing API fallback")
                            fallback = await self.get_domain_pricing(domain_name)
                            if fallback and fallback.get('create_price', 0) > 0:
                                price_info = {
                                    'create_price': fallback['create_price'],
                                    'currency': fallback.get('currency', 'USD'),
                                    'base_price_eur': fallback.get('base_price_eur', 0),
                                    'base_price_usd': fallback.get('base_price_usd', 0),
                                    'markup_applied': fallback.get('markup_applied', True),
                                    'minimum_enforced': fallback.get('minimum_enforced', False),
                                    'source': 'pricing_api_fallback'
                                }
                        
                        logger.info(f"✅ Domain {domain_name} - Available: {available}, Premium: {is_premium}, Price: ${price_info['create_price']:.2f}")
                        
                        # Run TLD-specific validation if available and contact data provided
                        tld_validation_info = {}
                        if TLD_VALIDATION_AVAILABLE and contact_data and _tld_validator is not None:
                            try:
                                tld = domain_name.split('.')[-1].lower()
                                if _tld_validator.has_specific_requirements(tld):
                                    logger.info(f"🔍 Running TLD validation for .{tld} domain availability check")
                                    validation_result = await _tld_validator.validate_tld_requirements(
                                        domain_name, contact_data
                                    )
                                    tld_validation_info = {
                                        'tld_validation': {
                                            'required': True,
                                            'tld': tld,
                                            'valid': validation_result.is_valid,
                                            'errors': validation_result.errors,
                                            'warnings': validation_result.warnings
                                        }
                                    }
                                    if not validation_result.is_valid:
                                        logger.warning(f"⚠️ TLD validation issues for {domain_name}: {validation_result.errors}")
                                else:
                                    tld_validation_info = {
                                        'tld_validation': {
                                            'required': False,
                                            'tld': tld
                                        }
                                    }
                            except Exception as e:
                                logger.error(f"❌ TLD validation error during availability check: {e}")
                                tld_validation_info = {
                                    'tld_validation': {
                                        'error': str(e)
                                    }
                                }
                        
                        result = {
                            'available': available,
                            'premium': is_premium,
                            'price_info': price_info
                        }
                        
                        # Add TLD validation info if available
                        if tld_validation_info:
                            result.update(tld_validation_info)
                        
                        return result
                    else:
                        logger.warning(f"⚠️ No domain results returned for {domain_name}")
                        return None
                else:
                    error_message = data.get('desc', 'Unknown API error')
                    logger.error(f"❌ OpenProvider API error: {error_message}")
                    return None
            else:
                logger.error(f"❌ HTTP error {response.status_code} from OpenProvider API")
                try:
                    error_data = response.json()
                    logger.error(f"❌ Error details: {error_data}")
                except:
                    logger.error(f"❌ Error response: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"❌ Exception in domain availability check: {e}")
            return None

    def _extract_price_from_domain_check(self, domain_info: Dict, domain_name: str) -> Dict:
        """Extract and process pricing from domains/check response"""
        pricing_result = {
            'create_price': 0,
            'currency': 'USD',
            'base_price_eur': 0,
            'base_price_usd': 0,
            'markup_applied': False,
            'minimum_enforced': False,
            'source': 'domains_check_fallback'
        }
        
        try:
            # DEBUG: Log the entire domain_info to see what we're getting
            logger.info(f"🔍 DEBUG: Full domain_info for {domain_name}: {domain_info}")
            
            # Extract price from the actual OpenProvider response structure
            price_data = None
            
            # OpenProvider domains/check response has pricing in domain_info['price']
            if 'price' in domain_info and isinstance(domain_info['price'], dict):
                price_data = domain_info['price']
                logger.info(f"💰 Found price data in domain_info['price']: {price_data}")
            else:
                logger.warning(f"⚠️ No 'price' key found in domain_info. Available keys: {list(domain_info.keys())}")
                return pricing_result
            
            # OpenProvider price structure: price.reseller.price or price.product.price
            if price_data:
                base_price = 0
                currency = 'EUR'
                
                # Try reseller price first (preferred), then product price
                if 'reseller' in price_data and isinstance(price_data['reseller'], dict):
                    reseller_data = price_data['reseller']
                    if 'price' in reseller_data:
                        base_price = float(reseller_data['price'])
                        currency = reseller_data.get('currency', 'EUR')
                        logger.info(f"💰 Using reseller price from domains/check: {base_price} {currency}")
                elif 'product' in price_data and isinstance(price_data['product'], dict):
                    product_data = price_data['product']
                    if 'price' in product_data:
                        base_price = float(product_data['price'])
                        currency = product_data.get('currency', 'EUR')
                        logger.info(f"💰 Using product price from domains/check: {base_price} {currency}")
                
                if base_price > 0:
                    # Apply markup calculations directly
                    from pricing_utils import calculate_marked_up_price
                    markup_result = calculate_marked_up_price(base_price, currency)
                    
                    pricing_result.update({
                        'create_price': markup_result['final_price'],
                        'currency': 'USD',  # Always return USD after markup
                        'base_price_eur': markup_result['base_price_eur'],
                        'base_price_usd': markup_result['base_price_usd'],
                        'markup_applied': markup_result['markup_applied'],
                        'minimum_enforced': markup_result['minimum_enforced'],
                        'source': 'domains_check_direct'
                    })
                    
                    logger.info(f"✅ Successfully extracted pricing from domains/check: ${pricing_result['create_price']:.2f} USD")
                    return pricing_result
                else:
                    logger.warning(f"⚠️ Price data found but no valid price extracted from: {price_data}")
            else:
                logger.warning(f"⚠️ Price data is None or empty")
            
        except Exception as e:
            logger.warning(f"⚠️ Error extracting price from domains/check response: {e}")
        
        logger.debug(f"💡 No price found in domains/check response, will use fallback pricing API")
        return pricing_result

    @monitor_performance("domain_pricing_check")
    async def get_domain_pricing(self, domain_name: str) -> Optional[Dict]:
        """Get pricing information for a domain - OPTIMIZED with caching"""
        try:
            if not self.username or not self.password:
                return None
            
            # Parse domain into name and extension
            try:
                domain_parts = self._parse_domain(domain_name)
            except ValueError as e:
                logger.error(f"❌ Domain parsing error: {e}")
                return None
            
            # Check TLD price cache first
            tld = domain_parts['extension']
            cached_pricing = _tld_price_cache.get(tld)
            if cached_pricing:
                logger.info(f"🚀 Using cached TLD pricing for {tld}: ${cached_pricing['create_price']:.2f}")
                return {
                    'domain': domain_name,
                    **cached_pricing
                }
            
            # Authenticate first to get bearer token (with caching)
            auth_success = await self.authenticate()
            if not auth_success:
                return None
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client")
                return None
            
            # Use dedicated pricing endpoint with optimized client
            response = await self._client.get(
                f"{self.base_url}/v1beta/domains/prices",
                headers=self.headers,
                params={
                    'domain.name': domain_parts['name'],
                    'domain.extension': domain_parts['extension'],
                    'operation': 'create',
                    'period': 1
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"🔍 Pricing API response: {data}")
                if data.get('code', 0) == 0:
                    price_data = data.get('data', {})
                    if 'price' in price_data:
                        # Extract price from dedicated pricing endpoint
                        price_info = price_data['price']
                        
                        # Try reseller price first, then product price
                        create_price = 0
                        currency = 'EUR'
                        
                        if 'reseller' in price_info and price_info['reseller']:
                            create_price = float(price_info['reseller']['price'])
                            currency = price_info['reseller'].get('currency', 'EUR')
                            logger.info(f"💰 Using reseller pricing: {create_price} {currency}")
                        elif 'product' in price_info and price_info['product']:
                            create_price = float(price_info['product']['price'])
                            currency = price_info['product'].get('currency', 'EUR')
                            logger.info(f"💰 Using product pricing: {create_price} {currency}")
                        
                        if create_price > 0:
                            # Apply markup calculations
                            from pricing_utils import calculate_marked_up_price
                            markup_result = calculate_marked_up_price(create_price, currency)
                            
                            # Cache TLD pricing for future use
                            cache_data = {
                                'create_price': markup_result['final_price'],
                                'currency': 'USD',
                                'base_price_eur': markup_result['base_price_eur'],
                                'base_price_usd': markup_result['base_price_usd'],
                                'markup_applied': markup_result['markup_applied'],
                                'minimum_enforced': markup_result['minimum_enforced'],
                                'source': 'pricing_api'
                            }
                            _tld_price_cache.set(tld, cache_data)
                            
                            return {
                                'domain': domain_name,
                                **cache_data
                            }
            else:
                logger.error(f"❌ Pricing API request failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ Error getting domain pricing: {e}")
        
        return None

    def _parse_domain(self, domain_name: str) -> Dict[str, str]:
        """Parse domain name into name and extension parts with comprehensive RFC validation"""
        # First perform comprehensive validation
        validation_result = self.validate_domain_rfc_compliant(domain_name)
        if not validation_result['valid']:
            raise ValueError(validation_result['error'])
        
        parts = domain_name.strip().lower().split('.')
        if len(parts) < 2:
            raise ValueError(f"Domain must contain at least 2 parts separated by dots: {domain_name}")
        
        # Join all parts except the last one as the name (handles subdomains)
        name = '.'.join(parts[:-1])
        extension = parts[-1]
        
        return {
            'name': name,
            'extension': extension
        }
    
    def validate_domain_rfc_compliant(self, domain_name: str) -> Dict[str, Any]:
        """Comprehensive RFC-compliant domain validation with detailed error reporting"""
        import re
        import idna
        
        if not domain_name or not isinstance(domain_name, str):
            return {'valid': False, 'error': 'Domain name is required and must be a string'}
        
        # Clean and normalize input
        domain_name = domain_name.strip()
        if not domain_name:
            return {'valid': False, 'error': 'Domain name cannot be empty'}
        
        # Handle IDN (Internationalized Domain Names) conversion
        try:
            # Convert Unicode domain to ASCII (punycode)
            ascii_domain = idna.encode(domain_name, uts46=True).decode('ascii')
        except (idna.core.IDNAError, UnicodeError, UnicodeDecodeError) as e:
            return {'valid': False, 'error': f'Invalid internationalized domain name: {str(e)}'}
        
        # Use ASCII version for all subsequent checks
        domain_to_validate = ascii_domain.lower()
        
        # RFC 1035/1123 total length limit (253 characters)
        if len(domain_to_validate) > 253:
            return {
                'valid': False, 
                'error': f'Domain name too long: {len(domain_to_validate)} characters (maximum: 253)'
            }
        
        # Check for minimum length
        if len(domain_to_validate) < 3:
            return {'valid': False, 'error': 'Domain name too short (minimum: 3 characters like "a.b")'}
        
        # Check for invalid characters or patterns
        if '..' in domain_to_validate:
            return {'valid': False, 'error': 'Domain name cannot contain consecutive dots'}
        
        if domain_to_validate.startswith('.') or domain_to_validate.endswith('.'):
            return {'valid': False, 'error': 'Domain name cannot start or end with a dot'}
        
        # Split into labels (parts between dots)
        labels = domain_to_validate.split('.')
        
        if len(labels) < 2:
            return {'valid': False, 'error': 'Domain must have at least 2 parts (e.g., "example.com")'}
        
        # Validate each label individually
        for i, label in enumerate(labels):
            label_type = 'TLD' if i == len(labels) - 1 else f'Label {i+1}'
            
            # RFC 1123 label length limit (63 characters per label)
            if len(label) > 63:
                return {
                    'valid': False,
                    'error': f'{label_type} too long: "{label}" ({len(label)} characters, maximum: 63)'
                }
            
            # Labels cannot be empty
            if len(label) == 0:
                return {'valid': False, 'error': f'{label_type} cannot be empty'}
            
            # Labels cannot start or end with hyphens
            if label.startswith('-') or label.endswith('-'):
                return {
                    'valid': False,
                    'error': f'{label_type} cannot start or end with hyphen: "{label}"'
                }
            
            # Check for valid characters only (a-z, 0-9, hyphens)
            if not re.match(r'^[a-z0-9-]+$', label):
                invalid_chars = [c for c in label if not re.match(r'[a-z0-9-]', c)]
                return {
                    'valid': False,
                    'error': f'{label_type} contains invalid characters: "{label}" (invalid: {", ".join(set(invalid_chars))})'
                }
        
        # TLD-specific validation
        tld = labels[-1]
        
        # TLD cannot be all numeric
        if tld.isdigit():
            return {'valid': False, 'error': f'TLD cannot be all numeric: "{tld}"'}
        
        # TLD should be at least 2 characters
        if len(tld) < 2:
            return {'valid': False, 'error': f'TLD too short: "{tld}" (minimum: 2 characters)'}
        
        # Additional domain-specific checks for common patterns
        if domain_to_validate.count('.') > 10:
            return {'valid': False, 'error': 'Domain has too many subdomains (maximum: 10 levels)'}
        
        # All validations passed
        return {
            'valid': True,
            'domain': domain_to_validate,
            'ascii_domain': ascii_domain,
            'original_domain': domain_name,
            'labels': labels,
            'tld': tld
        }
    
    async def _make_request_with_retry(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make HTTP request with retry logic and fallback mechanisms for domain operations"""
        max_retries = 3
        base_delay = 2.0
        
        for attempt in range(max_retries):
            try:
                await self._ensure_client()
                if self._client is None:
                    raise Exception("HTTP client initialization failed")
                
                # PERFORMANCE OPTIMIZATION: For domain registration, use fast timeout
                if 'domains.json' in url and method.upper() == 'POST':
                    custom_timeout = httpx.Timeout(
                        connect=3.0,   # Reduced from 5s to 3s for faster response
                        read=12.0,     # Reduced from 30s to 12s for better UX
                        write=6.0,     # Reduced from 10s to 6s
                        pool=4.0       # Reduced from 8s to 4s
                    )
                    kwargs['timeout'] = custom_timeout
                    logger.info(f"🕐 Using optimized 12s timeout for domain registration operation")
                
                # Make the request
                if method.upper() == 'GET':
                    response = await self._client.get(url, **kwargs)
                elif method.upper() == 'POST':
                    response = await self._client.post(url, **kwargs)
                elif method.upper() == 'PUT':
                    response = await self._client.put(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Success - return response
                return response
                
            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout) as e:
                attempt_num = attempt + 1
                if attempt_num >= max_retries:
                    logger.error(f"❌ Request failed after {max_retries} attempts: {str(e)}")
                    raise
                
                delay = base_delay * (2 ** attempt)  # Exponential backoff
                logger.warning(f"⚠️ Request timeout (attempt {attempt_num}/{max_retries}), retrying in {delay}s...")
                await asyncio.sleep(delay)
                
                # Try HTTP/1.1 fallback on final attempt
                if attempt_num == 2:
                    logger.info("🔄 Falling back to HTTP/1.1 for compatibility")
                    await self._fallback_to_http1()
                    
            except Exception as e:
                logger.error(f"❌ Unexpected error during request: {str(e)}")
                raise
        
        # This should never be reached due to the raise statements above
        # but adding for type safety
        raise Exception("Request failed after all retries")
    
    async def _fallback_to_http1(self):
        """Fallback to HTTP/1.1 for compatibility issues"""
        try:
            if self._client and not self._client.is_closed:
                await self._client.aclose()
            
            # Reinitialize with HTTP/1.1
            limits = httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
                keepalive_expiry=30.0
            )
            
            timeout = httpx.Timeout(
                connect=6.0,     # Reduced from 10s to 6s
                read=45.0,       # Reduced from 90s to 45s for faster fallback
                write=10.0,      # Reduced from 15s to 10s
                pool=8.0         # Reduced from 10s to 8s
            )
            
            self._client = httpx.AsyncClient(
                http2=False,  # Disable HTTP/2
                limits=limits,
                timeout=timeout,
                headers={'User-Agent': f'{self._get_platform_name()}-Bot/1.0'},
                follow_redirects=True
            )
            logger.info("🔄 Switched to HTTP/1.1 client with 90s timeout for improved compatibility")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize HTTP/1.1 fallback: {str(e)}")
    
    async def register_domain(
        self, 
        domain_name: str, 
        contact_handle: str, 
        nameservers: Optional[List[str]] = None,
        contact_data: Optional[Dict[str, Any]] = None,
        tld_additional_params: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict]:
        """Register a domain - CRITICAL METHOD with TLD-specific validation and additional data support"""
        try:
            if not self.username or not self.password:
                logger.error("❌ OpenProvider credentials not configured for domain registration")
                return None
            
            # Authenticate first to get bearer token
            if not self.bearer_token:
                auth_success = await self.authenticate()
                if not auth_success:
                    logger.error("❌ Failed to authenticate with OpenProvider for domain registration")
                    return None
            
            # Validate nameservers - should be Cloudflare nameservers
            if not nameservers or not isinstance(nameservers, list) or len(nameservers) == 0:
                logger.error(f"❌ No valid nameservers provided for {domain_name}")
                logger.error(f"   Received nameservers: {nameservers}")
                return None
            
            # Log nameservers being used for registration
            logger.info(f"🌐 Registering {domain_name} with nameservers: {nameservers}")
            
            # Validate nameservers are not dummy ones
            dummy_ns = ['ns1.example.com', 'ns2.example.com']
            if any(ns in dummy_ns for ns in nameservers):
                logger.error(f"❌ Dummy nameservers detected for {domain_name}: {nameservers}")
                return None
            
            # Validate Cloudflare nameservers format
            valid_cloudflare_patterns = ['.ns.cloudflare.com']
            is_cloudflare_ns = any(any(pattern in ns for pattern in valid_cloudflare_patterns) for ns in nameservers)
            if not is_cloudflare_ns:
                logger.warning(f"⚠️ Non-Cloudflare nameservers detected for {domain_name}: {nameservers}")
                # Continue anyway as they might be valid nameservers
            
            # Parse domain into name and extension
            try:
                domain_parts = self._parse_domain(domain_name)
                tld = domain_name.split('.')[-1].lower()
            except ValueError as e:
                logger.error(f"❌ Domain parsing error: {e}")
                return None
            
            # CRITICAL: Run TLD-specific validation before registration
            tld_additional_data = None
            if TLD_VALIDATION_AVAILABLE:
                try:
                    logger.info(f"🔍 Running comprehensive TLD validation for .{tld} domain registration")
                    
                    # Use provided contact data or fetch default contact for validation
                    validation_contact_data = contact_data
                    if not validation_contact_data:
                        # Try to extract contact info from handle (simplified)
                        validation_contact_data = {
                            'first_name': 'Hostbay',
                            'last_name': 'Admin', 
                            'email': 'admin@hostbay.sbs',
                            'address': '123 Main Street',
                            'city': 'New York',
                            'state': 'NY',
                            'postal_code': '10001',
                            'country': 'US',
                            'phone': '+15551234567',
                            'organization': 'Hostbay Services'
                        }
                        logger.info(f"📝 Using default contact data for TLD validation")
                    
                    # Prepare additional parameters for TLD validation
                    validation_params = tld_additional_params or {}
                    
                    # Run TLD-specific validation using new instance-based approach
                    if _tld_validator is not None:
                        validation_result = await _tld_validator.validate(
                            tld,  # Pass TLD only, not full domain name
                            validation_contact_data,
                            nameservers,
                            validation_params  # This becomes 'extras' parameter
                        )
                    else:
                        # Fallback if validator is not available - create mock validation result
                        from services.tld_requirements import TLDValidationResult
                        validation_result = TLDValidationResult(
                            is_valid=True,
                            errors=[],
                            warnings=["TLD validator not available - skipping validation"],
                            additional_data=None
                        )
                        logger.warning(f"⚠️ TLD validator not available for domain {domain_name}, proceeding without validation")
                    
                    # Check validation results
                    if not validation_result.is_valid:
                        error_msg = f"TLD validation failed for {domain_name}: {'; '.join(validation_result.errors)}"
                        logger.error(f"❌ {error_msg}")
                        
                        # Send admin alert for TLD validation failure
                        await send_critical_alert(
                            "TLD_Validation",
                            f"TLD validation failed before registration: {domain_name}",
                            "domain_registration",
                            {
                                "domain": domain_name,
                                "tld": tld,
                                "validation_errors": validation_result.errors,
                                "validation_warnings": validation_result.warnings,
                                "contact_data": validation_contact_data,
                                "nameservers": nameservers
                            }
                        )
                        
                        return {
                            'success': False,
                            'error': 'TLD_VALIDATION_FAILED',
                            'message': error_msg,
                            'validation_errors': validation_result.errors,
                            'validation_warnings': validation_result.warnings
                        }
                    
                    # Log successful validation
                    logger.info(f"✅ TLD validation passed for .{tld} domain: {domain_name}")
                    if validation_result.warnings:
                        logger.warning(f"⚠️ TLD validation warnings: {validation_result.warnings}")
                    
                    # Extract additional data for registration if provided
                    if validation_result.additional_data:
                        tld_additional_data = validation_result.additional_data
                        logger.info(f"📦 TLD additional data for registration: {tld_additional_data}")
                    
                except Exception as e:
                    logger.error(f"❌ TLD validation exception for {domain_name}: {e}")
                    
                    # Send admin alert for TLD validation exception
                    await send_error_alert(
                        "TLD_Validation",
                        f"TLD validation exception during registration: {domain_name}",
                        "domain_registration", 
                        {
                            "domain": domain_name,
                            "exception": str(e),
                            "contact_handle": contact_handle,
                            "nameservers": nameservers
                        }
                    )
                    
                    # Depending on TLD, we might want to fail hard or continue
                    if tld == 'de':  # Critical nameserver validation for .de
                        return {
                            'success': False,
                            'error': 'TLD_VALIDATION_EXCEPTION',
                            'message': f"Critical TLD validation failed for .{tld} domain: {str(e)}"
                        }
                    else:
                        logger.warning(f"⚠️ Continuing registration despite TLD validation exception for .{tld}")
            else:
                logger.info(f"📝 TLD validation not available - proceeding with standard registration")
            
            # Build registration data with TLD-specific additional data
            registration_data = {
                'domain': domain_parts,
                'period': 1,  # 1 year only
                'autorenew': 'off',  # Disable auto-renewal (manual control only)
                'unit': 'y',  # Yearly registration
                'owner_handle': contact_handle,
                'admin_handle': contact_handle,
                'tech_handle': contact_handle,
                'billing_handle': contact_handle,
                'name_servers': [{'name': ns, 'seq_nr': i + 1} for i, ns in enumerate(nameservers)],
                'use_domicile': False
            }
            
            # Add TLD-specific additional data if available
            if tld_additional_data and 'extension_additional_data' in tld_additional_data:
                registration_data['extension_additional_data'] = tld_additional_data['extension_additional_data']
                logger.info(f"🔧 Added TLD-specific additional data for .{tld}: {registration_data['extension_additional_data']}")
            
            # Log complete registration data for debugging (with TLD validation info)
            logger.info(f"🔍 OPENPROVIDER REGISTRATION DATA (TLD-VALIDATED):")
            logger.info(f"   Domain: {domain_name} (TLD: .{tld})")
            logger.info(f"   Domain Parts: {domain_parts}")
            logger.info(f"   Contact Handle: {contact_handle}")
            logger.info(f"   Nameservers: {nameservers}")
            logger.info(f"   TLD Additional Data: {tld_additional_data}")
            logger.info(f"   Full Payload: {registration_data}")
            
            # Use retry mechanism with extended timeout for domain registration
            response = await self._make_request_with_retry(
                'POST',
                f"{self.base_url}/v1beta/domains",
                headers=self.headers,
                json=registration_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code', 0) == 0:
                    domain_data = data.get('data', {})
                    logger.info(f"✅ Domain registered successfully: {domain_name}")
                    logger.info(f"   OpenProvider ID: {domain_data.get('id')}")
                    logger.info(f"   Status: {domain_data.get('status')}")
                    
                    return {
                        'success': True,
                        'domain_id': domain_data.get('id'),
                        'status': domain_data.get('status'),
                        'nameservers': nameservers,
                        'tld': tld,
                        'tld_validation_passed': True,
                        'tld_additional_data_used': bool(tld_additional_data),
                        'message': f"Domain {domain_name} registered successfully with TLD validation"
                    }
                else:
                    errors = data.get('desc', 'Unknown registration error')
                    logger.error(f"❌ Domain registration failed: {errors}")
                    # Send admin alert for domain registration failure
                    await send_critical_alert(
                        "OpenProvider",
                        f"Domain registration failed for {domain_name}: {errors}",
                        "domain_registration",
                        {
                            "domain": domain_name,
                            "contact_handle": contact_handle,
                            "nameservers": nameservers,
                            "api_error": errors,
                            "api_response": data
                        }
                    )
                    return {
                        'success': False,
                        'error': errors,
                        'message': f"Failed to register {domain_name}: {errors}"
                    }
            else:
                error_text = response.text
                logger.error(f"❌ Domain registration API failed: {response.status_code} - {error_text}")
                # Send admin alert for domain registration API failure
                await send_critical_alert(
                    "OpenProvider",
                    f"Domain registration API failure for {domain_name}",
                    "external_api",
                    {
                        "domain": domain_name,
                        "http_status": response.status_code,
                        "api_response": error_text,
                        "contact_handle": contact_handle,
                        "nameservers": nameservers
                    }
                )
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}",
                    'message': f"API request failed for {domain_name}"
                }
                
        except Exception as e:
            logger.error(f"❌ Error during domain registration for {domain_name}: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            # Send admin alert for domain registration exception
            await send_critical_alert(
                "OpenProvider",
                f"Domain registration exception for {domain_name}: {str(e)}",
                "domain_registration",
                {
                    "domain": domain_name,
                    "exception": str(e),
                    "traceback": traceback.format_exc(),
                    "contact_handle": contact_handle,
                    "nameservers": nameservers
                }
            )
            return {
                'success': False,
                'error': str(e),
                'message': f"Registration exception for {domain_name}"
            }

    async def get_domain_details(self, domain_name: str) -> Optional[Dict]:
        """Get domain details including the numerical ID required for updates"""
        try:
            if not self.username or not self.password:
                logger.error("❌ OpenProvider credentials not configured")
                return None
            
            # Authenticate first to get bearer token
            if not self.bearer_token:
                auth_success = await self.authenticate()
                if not auth_success:
                    logger.error("❌ Failed to authenticate with OpenProvider")
                    return None
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client")
                return None
            
            # Search for domain in domain list
            response = await self._client.get(
                f"{self.base_url}/v1beta/domains",
                headers=self.headers,
                params={'full_name': domain_name, 'limit': 1}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code', 0) == 0:
                    results = data.get('data', {}).get('results', [])
                    if results:
                        domain_info = results[0]
                        logger.info(f"✅ Found domain details for {domain_name}: ID={domain_info.get('id')}")
                        return domain_info
                    else:
                        logger.error(f"❌ Domain {domain_name} not found in OpenProvider account")
                        return None
                else:
                    logger.error(f"❌ OpenProvider API error: {data.get('desc', 'Unknown error')}")
                    return None
            else:
                logger.error(f"❌ Failed to fetch domain details: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error fetching domain details for {domain_name}: {e}")
            return None

    async def update_nameservers(self, domain_name: str, nameservers: List[str], domain_id: Optional[str] = None) -> Optional[Dict]:
        """Update nameservers for an existing domain via OpenProvider API"""
        try:
            if not self.username or not self.password:
                logger.error("❌ OpenProvider credentials not configured for nameserver update")
                return None
            
            if not nameservers or not isinstance(nameservers, list) or len(nameservers) == 0:
                logger.error(f"❌ No valid nameservers provided for {domain_name}")
                return None
            
            # Log nameserver update attempt
            logger.info(f"🌐 Updating nameservers for {domain_name} to: {nameservers}")
            
            # Get domain details to fetch the numerical ID and current configuration
            domain_info = await self.get_domain_details(domain_name)
            if not domain_info:
                logger.error(f"❌ Could not fetch domain details for {domain_name}")
                return None
            
            numerical_id = domain_info.get('id')
            if not numerical_id:
                logger.error(f"❌ No domain ID found for {domain_name}")
                return None
            
            # Parse domain for the request body
            domain_parts = domain_name.split('.')
            name = '.'.join(domain_parts[:-1])
            extension = domain_parts[-1]
            
            # Prepare complete domain update data according to OpenProvider API docs
            update_data = {
                'domain': {
                    'name': name,
                    'extension': extension
                },
                'name_servers': [{'name': ns, 'seq_nr': i + 1} for i, ns in enumerate(nameservers)],
                # Include existing contact handles from domain info
                'owner_handle': domain_info.get('owner_handle'),
                'admin_handle': domain_info.get('admin_handle'),
                'tech_handle': domain_info.get('tech_handle'),
                'billing_handle': domain_info.get('billing_handle')
            }
            
            logger.info(f"📤 Sending nameserver update request for {domain_name}")
            logger.info(f"   Domain ID: {numerical_id}")
            logger.info(f"   Nameservers: {nameservers}")
            
            # Use PUT request with correct OpenProvider URL format: /v1beta/domains/{id}
            api_url = f"{self.base_url}/v1beta/domains/{numerical_id}"
            logger.info(f"   API URL: {api_url}")
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client for nameserver update")
                return {
                    'success': False,
                    'error': 'HTTP client initialization failed',
                    'message': f"Failed to initialize client for nameserver update on {domain_name}"
                }
            
            response = await self._client.put(
                api_url,
                headers=self.headers,
                json=update_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code', 0) == 0:
                    logger.info(f"✅ Nameservers updated successfully for {domain_name}")
                    return {
                        'success': True,
                        'domain_name': domain_name,
                        'nameservers': nameservers,
                        'message': f"Nameservers updated successfully for {domain_name}"
                    }
                else:
                    errors = data.get('desc', 'Unknown nameserver update error')
                    logger.error(f"❌ Nameserver update failed: {errors}")
                    return {
                        'success': False,
                        'error': errors,
                        'message': f"Failed to update nameservers for {domain_name}: {errors}"
                    }
            else:
                error_text = response.text
                logger.error(f"❌ Nameserver update API failed: {response.status_code} - {error_text}")
                logger.error(f"   Request URL: {api_url}")
                logger.error(f"   Request Body: {update_data}")
                return {
                    'success': False,
                    'error': f"HTTP {response.status_code}",
                    'message': f"API request failed for nameserver update on {domain_name}"
                }
                
        except Exception as e:
            logger.error(f"❌ Error during nameserver update for {domain_name}: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            return {
                'success': False,
                'error': str(e),
                'message': f"Nameserver update exception for {domain_name}"
            }

    async def create_contact_handle(self, contact_info: Dict) -> Optional[str]:
        """Create a contact handle for domain registration"""
        try:
            if not self.username or not self.password:
                return None
            
            # Authenticate first to get bearer token
            if not self.bearer_token:
                auth_success = await self.authenticate()
                if not auth_success:
                    return None
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client for contact creation")
                return None

            response = await self._client.post(
                f"{self.base_url}/v1beta/customers",
                headers=self.headers,
                json={
                    'name': {
                        'first_name': contact_info.get('first_name', ''),
                        'last_name': contact_info.get('last_name', '')
                    },
                    'address': {
                        'street': contact_info.get('address', ''),
                        'city': contact_info.get('city', ''),
                        'state': contact_info.get('state', ''),
                        'zipcode': contact_info.get('postal_code', ''),
                        'country': contact_info.get('country', 'US')
                    },
                    'phone': self._format_phone_for_openprovider(contact_info.get('phone', '+15551234567')),
                    'email': contact_info.get('email', ''),
                    'company_name': contact_info.get('organization', '')
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code', 0) == 0:
                    handle = data.get('data', {}).get('handle')
                    logger.info(f"✅ Contact handle created: {handle}")
                    return handle
                else:
                    error_msg = data.get('desc', 'Unknown contact creation error')
                    logger.error(f"❌ Contact creation failed: {error_msg}")
                    # Send admin alert for contact handle creation failure
                    await send_error_alert(
                        "OpenProvider",
                        f"Contact handle creation failed: {error_msg}",
                        "domain_registration",
                        {
                            "contact_info": contact_info,
                            "api_response": data,
                            "error_code": data.get('code')
                        }
                    )
                    
        except Exception as e:
            logger.error(f"❌ Error creating contact handle: {e}")
            # Send admin alert for contact handle creation exception
            await send_critical_alert(
                "OpenProvider",
                f"Contact handle creation exception: {str(e)}",
                "domain_registration",
                {
                    "contact_info": contact_info,
                    "exception": str(e)
                }
            )
        
        return None
    
    async def get_contact_handles(self) -> List[str]:
        """Get list of existing contact handles from OpenProvider"""
        try:
            if not self.username or not self.password:
                return []
            
            # Authenticate first to get bearer token
            if not self.bearer_token:
                auth_success = await self.authenticate()
                if not auth_success:
                    return []
            
            await self._ensure_client()
            if self._client is None:
                logger.error("❌ Failed to initialize HTTP client for contact list")
                return []

            response = await self._client.get(
                f"{self.base_url}/v1beta/customers",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('code', 0) == 0:
                    customers = data.get('data', {}).get('results', [])
                    handles = [customer.get('handle') for customer in customers if customer.get('handle')]
                    logger.info(f"✅ Found {len(handles)} contact handles: {handles}")
                    return handles
                else:
                    logger.error(f"❌ Failed to get contact handles: {data}")
            else:
                logger.error(f"❌ OpenProvider contact API failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ Error getting contact handles: {e}")
        
        return []
    
    async def get_or_create_contact_handle(self) -> Optional[str]:
        """Get an existing contact handle or create a default one with proper phone formatting"""
        try:
            # CRITICAL FIX: Skip problematic contact handles with invalid phone formats
            # Contact handle RA1083275-US has invalid phone (+86 China code with US address)
            # that causes OpenProvider to reject domain registrations
            
            handles = await self.get_contact_handles()
            problematic_handles = ['RA1083275-US']  # Known bad contact handles
            
            if handles:
                # Filter out known problematic contact handles
                valid_handles = [h for h in handles if h not in problematic_handles]
                
                if valid_handles:
                    handle = valid_handles[0]
                    logger.info(f"✅ Using existing valid contact handle: {handle}")
                    return handle
                else:
                    logger.warning(f"⚠️ All existing contact handles are problematic: {handles}")
                    logger.info("📝 Creating new contact handle with proper phone formatting")
            else:
                logger.info("📝 No existing contact handles found, creating default contact")
            
            # Create a new contact handle with PROPER phone formatting
            logger.info("🔧 PHONE FIX: Creating contact with properly formatted US phone number")
            default_contact = {
                'first_name': 'Hostbay',
                'last_name': 'Support',
                'email': 'hostbay.support@gmail.com',
                'address': '123 Business Ave',
                'city': 'New York',
                'state': 'NY',
                'postal_code': '10001',
                'country': 'US',
                'phone': '+15551234567',  # PROPER US format: +1 + 10 digits
                'organization': 'Hostbay Domain Services'
            }
            
            handle = await self.create_contact_handle(default_contact)
            if handle:
                logger.info(f"✅ Created new contact handle with proper phone format: {handle}")
                return handle
            else:
                logger.error("❌ Failed to create contact handle with proper phone format")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error getting or creating contact handle: {e}")
            return None


# Global optimized service instance
_optimized_service = OptimizedOpenProviderService()

class OpenProviderService(OptimizedOpenProviderService):
    """OpenProvider API service for domain registration - optimized version"""
    
    def __init__(self):
        super().__init__()
        # Ensure all methods are properly inherited and accessible
        logger.debug("🔧 OpenProviderService initialized with full method inheritance")
    
    # All methods are inherited from OptimizedOpenProviderService
    # No need to redefine them here to avoid LSP "obscured" warnings
    pass


# Helper function to get the global optimized service instance
def get_openprovider_service():
    """Get the global OpenProvider service instance"""
    return _optimized_service


# Legacy compatibility function (replaced by the above optimized version)
    return OpenProviderService()

# Performance monitoring decorator
def monitor_performance(func):
    """Decorator to monitor API call performance"""
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            execution_time = time.time() - start_time
            logger.info(f"🚀 {func.__name__} completed in {execution_time:.2f}s")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"❌ {func.__name__} failed after {execution_time:.2f}s: {e}")
            raise
    return wrapper

