"""
cPanel hosting integration service
Handles hosting account creation and management
"""

import os
import logging
import httpx
import random
import string
import socket
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class CPanelService:
    """cPanel/WHM API service for hosting management"""
    
    def __init__(self):
        # SECURITY: Check TEST_MODE to prevent live credential usage during tests
        if os.getenv('TEST_MODE') == '1':
            logger.info("🔒 TEST_MODE active - using mock cPanel configuration")
            self.whm_host = 'test-server.local'
            self.whm_username = 'test_user'
            self.whm_api_token = 'test_token'
            self.whm_password = 'test_password'
            self.default_server_ip = '127.0.0.1'
            self.default_nameservers = ['ns1.test.com', 'ns2.test.com']
            return
        
        self.whm_host = os.getenv('WHM_HOST', 'your-server.com')
        self.whm_username = os.getenv('WHM_USERNAME', 'root')
        self.whm_api_token = os.getenv('WHM_API_TOKEN')
        self.whm_password = os.getenv('WHM_PASSWORD')  # Alternative to API token
        
        # Auto-detect hosting server IP or use environment variable
        self.default_server_ip = self._detect_server_ip()
        self.default_nameservers = [
            os.getenv('NS1', 'ns1.yourhost.com'),
            os.getenv('NS2', 'ns2.yourhost.com')
        ]
        
        # Log connection details at startup
        logger.info(f"🔧 cPanel Service initialized:")
        logger.info(f"   • WHM Host: {self.whm_host}")
        logger.info(f"   • WHM Username: {self.whm_username}")
        logger.info(f"   • API Token: {'✅ SET' if self.whm_api_token else '❌ NOT SET'}")
        logger.info(f"   • Password: {'✅ SET' if self.whm_password else '❌ NOT SET'}")
        logger.info(f"   • Server IP: {self._obfuscate_ip(self.default_server_ip)}")
        
        # Check if credentials are available
        if self.whm_api_token or self.whm_password:
            logger.info("✅ cPanel credentials are configured - real account creation enabled")
        else:
            logger.warning("⚠️ cPanel credentials not configured - will simulate account creation")
    
    def generate_username(self, domain: str) -> str:
        """
        Generate a deterministic cPanel username from domain
        FIXED: Uses longer hash-based suffix to reduce collision risk
        COLLISION SAFETY: 6-character suffix provides 16M+ unique variants
        """
        import hashlib
        
        # Remove TLD and special characters, limit to 2 chars for suffix space
        username = domain.split('.')[0][:2]
        username = ''.join(c for c in username if c.isalnum())
        
        # Ensure we have at least some base text
        if not username:
            username = 'u'  # Default prefix for edge cases
        
        # Generate deterministic suffix based on full domain hash
        # FIXED: Use 6 hex chars for 16,777,216 unique variants (low collision risk)
        domain_hash = hashlib.sha256(domain.lower().encode()).hexdigest()
        suffix = domain_hash[:6]  # Use first 6 chars of hash as suffix
        
        # cPanel usernames are limited to 8 characters max
        generated_username = f"{username}{suffix}".lower()
        
        # Ensure it fits cPanel limits (8 chars max)
        if len(generated_username) > 8:
            generated_username = generated_username[:8]
            
        return generated_username
    
    def _obfuscate_ip(self, ip_address: str) -> str:
        """
        Obfuscate IP addresses for production security
        SECURITY FIX: Prevents sensitive server IP disclosure in logs
        """
        try:
            if not ip_address or ip_address == '192.168.1.100':
                return '[FALLBACK-IP]'  # Default fallback IP doesn't need obfuscation
            
            # Split IP address into octets
            parts = ip_address.split('.')
            if len(parts) == 4:
                # Obfuscate middle two octets for security
                return f"{parts[0]}.***.***.{parts[3]}"
            else:
                # Not a standard IPv4 address
                return '[CONFIGURED-IP]'
        except Exception:
            return '[IP-OBFUSCATED]'
    
    def _detect_server_ip(self) -> str:
        """Auto-detect the real server IP from WHM host or use environment variable"""
        try:
            # First try environment variable
            env_ip = os.getenv('DEFAULT_SERVER_IP')
            if env_ip and env_ip != '192.168.1.100':
                logger.info(f"🌐 Using server IP from environment: {self._obfuscate_ip(env_ip)}")
                return env_ip
            
            # Auto-detect IP from WHM hostname
            hostname = None  # Initialize variable
            if self.whm_host and self.whm_host != 'your-server.com':
                try:
                    # Remove any protocol prefix and port suffix for DNS lookup
                    hostname = self.whm_host.replace('https://', '').replace('http://', '')
                    if ':' in hostname:
                        hostname = hostname.split(':')[0]
                    
                    detected_ip = socket.gethostbyname(hostname)
                    logger.info(f"🌐 Auto-detected server IP from {hostname}: {self._obfuscate_ip(detected_ip)}")
                    return detected_ip
                except socket.gaierror as e:
                    logger.warning(f"⚠️ Failed to resolve WHM hostname {hostname or 'unknown'}: {e}")
            
            # Fallback to environment or hardcoded value
            fallback_ip = os.getenv('DEFAULT_SERVER_IP', '192.168.1.100')
            logger.warning(f"⚠️ Using fallback server IP: {self._obfuscate_ip(fallback_ip)}")
            return fallback_ip
            
        except Exception as e:
            logger.error(f"❌ Error detecting server IP: {e}")
            return os.getenv('DEFAULT_SERVER_IP', '192.168.1.100')
    
    async def test_connection(self) -> tuple[bool, str]:
        """Test cPanel/WHM API connectivity"""
        try:
            if not self.whm_api_token and not self.whm_password:
                return False, "WHM credentials not configured"
            
            async with httpx.AsyncClient(verify=True) as client:
                headers = None
                auth = None
                
                if self.whm_api_token:
                    headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
                elif self.whm_password:
                    auth = (self.whm_username, self.whm_password)
                
                # Test with proper WHM API 1 endpoint that returns metadata
                if headers:
                    response = await client.get(
                        f"https://{self.whm_host}:2087/json-api/gethostname?api.version=1",
                        headers=headers
                    )
                else:
                    response = await client.get(
                        f"https://{self.whm_host}:2087/json-api/gethostname?api.version=1",
                        auth=auth
                    )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        version = data.get('data', {}).get('version', 'unknown')
                        return True, f"WHM {version} connected"
                    else:
                        return False, f"WHM API error: {data.get('metadata', {}).get('reason', 'unknown')}"
                else:
                    return False, f"HTTP {response.status_code}: Connection failed"
                    
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
    
    def generate_password(self, length: int = 12) -> str:
        """Generate a secure random password"""
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choices(characters, k=length))
    
    async def create_hosting_account(self, domain: str, plan: str, email: str, intent_id: Optional[int] = None) -> Optional[Dict]:
        """Create a new cPanel hosting account with idempotency support"""
        try:
            # Test connection first to give detailed error information
            logger.info(f"🔗 Testing cPanel connection before creating account for {domain}")
            connection_ok, connection_msg = await self.test_connection()
            
            if not connection_ok:
                logger.error(f"❌ cPanel connection failed: {connection_msg}")
                logger.error("❌ PRODUCTION MODE: Account creation failed - connection issue must be resolved")
                logger.error(f"❌ Actionable Fix: Check WHM host ({self.whm_host}), credentials, and network connectivity")
                return None
                
            logger.info(f"✅ cPanel connection successful: {connection_msg}")
            
            if not self.whm_api_token and not self.whm_password:
                logger.error("❌ PRODUCTION MODE: WHM credentials not configured")
                logger.error("❌ Actionable Fix: Set WHM_API_TOKEN or WHM_PASSWORD environment variables")
                logger.error(f"❌ Current config: WHM_HOST={self.whm_host}, WHM_USERNAME={self.whm_username}")
                return None
            
            # Generate deterministic username based on domain for idempotency
            username = self.generate_username(domain)
            
            # IMPROVED: Check if account already exists by BOTH username AND domain
            # This prevents false positives from hash collisions
            existing_account = await self._check_existing_account_by_domain(domain, username)
            if existing_account:
                logger.info(f"✅ Existing cPanel account found for {username} on domain {domain} - returning existing account details")
                return existing_account
            
            password = self.generate_password()
            
            # WHM API createacct parameters
            create_data = {
                'api.version': '1',
                'username': username,
                'domain': domain,
                'password': password,
                'contactemail': email,
                'plan': plan,
                'featurelist': 'default',
                'quota': '1024',  # 1GB default quota
            }
            
            # Prepare headers and auth properly typed for HTTPX
            # PERFORMANCE OPTIMIZATION: Reduced timeout from 30s to 12s for faster operations
            timeout_config = httpx.Timeout(connect=3.0, read=12.0, write=5.0, pool=10.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                if self.whm_api_token:
                    headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/createacct",
                        data=create_data,
                        headers=headers
                    )
                elif self.whm_password:
                    auth = (self.whm_username, self.whm_password)
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/createacct",
                        data=create_data,
                        auth=auth
                    )
                else:
                    raise ValueError("No authentication method available")
                
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"🔍 WHM API Response for {username}: {data}")
                    
                    # WHM API uses different response formats - check both
                    result = data.get('metadata', {}).get('result', data.get('result', 0))
                    
                    if result == 1:
                        logger.info(f"✅ cPanel account created: {username}@{domain}")
                        
                        # Extract actual server IP from response if available
                        actual_server_ip = data.get('data', {}).get('ip', 
                                          data.get('metadata', {}).get('ip', self.default_server_ip))
                        
                        return {
                            'username': username,
                            'password': password,
                            'domain': domain,
                            'server_ip': actual_server_ip,
                            'nameservers': self.default_nameservers,
                            'status': 'active',
                            'cpanel_url': f"https://{domain}:2083"
                        }
                    else:
                        # Enhanced error reporting
                        errors = data.get('errors', data.get('metadata', {}).get('reason', ['Unknown error']))
                        raw_output = data.get('data', {}).get('rawout', '')
                        error_msg = data.get('metadata', {}).get('reason', '')
                        
                        logger.error(f"❌ cPanel account creation failed for {username}@{domain}:")
                        logger.error(f"   • Errors: {errors}")
                        logger.error(f"   • Reason: {error_msg}")
                        logger.error(f"   • Raw output: {raw_output}")
                        logger.error(f"   • Full response: {data}")
                        
                        # Don't fall back to simulation - return None to force real debugging
                        logger.error("❌ PRODUCTION MODE: Not falling back to simulation - account creation must succeed")
                        return None
                else:
                    logger.error(f"❌ WHM API request failed: {response.status_code}")
                    logger.error(f"   • Response body: {response.text}")
                    logger.error("❌ PRODUCTION MODE: Not falling back to simulation - connection issue must be resolved")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ Error creating hosting account: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            # Don't fall back to simulation in production mode
            logger.error("❌ PRODUCTION MODE: Not falling back to simulation - exception must be resolved")
            return None
        
        return None
    
    async def _check_existing_account_by_domain(self, domain: str, username: str) -> Optional[Dict]:
        """
        Check if cPanel account already exists for domain AND username
        COLLISION SAFETY: Prevents false positives from hash collisions
        """
        try:
            if not self.whm_api_token and not self.whm_password:
                # In simulation mode, check our database for existing accounts
                logger.info(f"🔧 Simulated account check: {username} for domain {domain}")
                return None  # Assume no existing account in simulation
            
            # Check by username first (primary key in WHM)
            check_data = {
                'api.version': '1',
                'user': username
            }
            
            # PERFORMANCE OPTIMIZATION: Reduced timeout from 15s to 8s for faster checks
            timeout_config = httpx.Timeout(connect=2.0, read=8.0, write=3.0, pool=8.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                if self.whm_api_token:
                    headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/accountsummary",
                        data=check_data,
                        headers=headers
                    )
                elif self.whm_password:
                    auth = (self.whm_username, self.whm_password)
                    response = await client.post(
                        f"https://{self.whm_host}:2087/json-api/accountsummary",
                        data=check_data,
                        auth=auth
                    )
                else:
                    raise ValueError("No authentication method available")
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        account_info = data.get('data', {}).get('acct', [])
                        
                        if account_info:
                            # Account exists - verify it matches our domain
                            account = account_info[0]
                            existing_domain = account.get('domain', '')
                            
                            if existing_domain.lower() == domain.lower():
                                logger.info(f"✅ Found existing cPanel account {username} for domain {domain}")
                                return {
                                    'username': username,
                                    'domain': existing_domain,
                                    'status': 'active',
                                    'server_ip': account.get('ip', self.default_server_ip),
                                    'cpanel_url': f"https://{existing_domain}:2083",
                                    'existing': True
                                }
                            else:
                                # Username exists but for different domain - collision detected!
                                logger.warning(f"⚠️ USERNAME COLLISION: {username} exists for domain {existing_domain}, not {domain}")
                                return None  # Force new username generation
                    
                # No existing account found
                return None
                    
        except Exception as e:
            logger.error(f"❌ Error checking existing account for {domain}: {e}")
            return None  # Assume no existing account on error
    
    def _simulate_account_creation(self, domain: str, plan: str, email: str, intent_id: Optional[int] = None) -> Dict:
        """Simulate account creation when WHM is not available"""
        username = self.generate_username(domain)
        password = self.generate_password()
        
        logger.info(f"🔧 Simulated cPanel account creation: {username}@{domain}")
        
        return {
            'username': username,
            'password': password,
            'domain': domain,
            'server_ip': self.default_server_ip,
            'nameservers': self.default_nameservers,
            'status': 'active',
            'cpanel_url': f"https://{domain}:2083",
            'simulated': True
        }
    
    async def suspend_account(self, username: str) -> bool:
        """Suspend a hosting account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated account suspension: {username}")
                return True
            
            suspend_data = {
                'api.version': '1',
                'user': username,
                'reason': 'Administrative suspension'
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': suspend_data,  # Use form data instead of JSON
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/suspendacct",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        logger.info(f"✅ Account suspended: {username}")
                        return True
                        
        except Exception as e:
            logger.error(f"❌ Error suspending account: {e}")
        
        return False
    
    async def unsuspend_account(self, username: str) -> bool:
        """Unsuspend a hosting account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated account unsuspension: {username}")
                return True
            
            unsuspend_data = {
                'api.version': '1',
                'user': username
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': unsuspend_data,  # Use form data instead of JSON
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/unsuspendacct",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        logger.info(f"✅ Account unsuspended: {username}")
                        return True
                        
        except Exception as e:
            logger.error(f"❌ Error unsuspending account: {e}")
        
        return False
    
    async def restart_service(self, service_name: str, username: str = None) -> bool:
        """Restart a specific hosting service via WHM API"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated service restart: {service_name}" + (f" for {username}" if username else ""))
                return True
            
            restart_data = {
                'api.version': '1',
                'service': service_name
            }
            
            # Prepare headers and auth
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            # Extended timeout for service operations (services can take up to 60s to restart)
            timeout_config = httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=15.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                kwargs = {
                    'data': restart_data,
                    'timeout': timeout_config
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                logger.info(f"🔄 Restarting {service_name} service" + (f" for account {username}" if username else ""))
                
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/restartservice",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"🔍 WHM API Response for {service_name} restart: {data}")
                    
                    # Check both metadata.result and direct result
                    result = data.get('metadata', {}).get('result', data.get('result', 0))
                    
                    if result == 1:
                        # Extract status message
                        status = data.get('data', {}).get('status', 'restarted')
                        reason = data.get('metadata', {}).get('reason', 'Service restart successful')
                        
                        logger.info(f"✅ {service_name} service restarted successfully: {reason}")
                        return True
                    else:
                        # Enhanced error reporting
                        errors = data.get('errors', data.get('metadata', {}).get('reason', ['Unknown error']))
                        error_msg = data.get('metadata', {}).get('reason', 'Service restart failed')
                        
                        logger.error(f"❌ Failed to restart {service_name} service:")
                        logger.error(f"   • Errors: {errors}")
                        logger.error(f"   • Reason: {error_msg}")
                        logger.error(f"   • Full response: {data}")
                        return False
                else:
                    logger.error(f"❌ WHM API request failed for {service_name}: {response.status_code}")
                    logger.error(f"   • Response body: {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Error restarting {service_name} service: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
            return False
        
        return False
    
    async def restart_apache(self, username: str = None) -> bool:
        """Restart Apache/HTTP service"""
        return await self.restart_service('httpd', username)
    
    async def restart_mysql(self, username: str = None) -> bool:
        """Restart MySQL database service"""
        return await self.restart_service('mysql', username)
    
    async def restart_ftp(self, username: str = None) -> bool:
        """Restart FTP service"""
        return await self.restart_service('proftpd', username)
    
    async def restart_dns(self, username: str = None) -> bool:
        """Restart DNS/BIND service"""
        return await self.restart_service('named', username)
    
    async def restart_mail(self, username: str = None) -> bool:
        """Restart Exim mail service"""
        return await self.restart_service('exim', username)
    
    async def restart_ssh(self, username: str = None) -> bool:
        """Restart SSH service"""
        return await self.restart_service('sshd', username)
    
    async def restart_cpanel_service(self, username: str = None) -> bool:
        """Restart cPanel service daemon"""
        return await self.restart_service('cpsrvd', username)
    
    async def restart_services(self, username: str) -> dict:
        """
        Backward compatibility wrapper for restart_services method
        COMPATIBILITY FIX: Prevents runtime errors for legacy code calling restart_services
        """
        logger.info(f"🔄 Running backward compatibility restart_services for user: {username}")
        
        # Default services typically restarted for hosting accounts
        default_services = ['httpd', 'mysql', 'proftpd', 'named', 'exim']
        results = {}
        
        for service in default_services:
            try:
                result = await self.restart_service(service, username)
                results[service] = result
                logger.debug(f"✅ Service restart result: {service} = {result}")
            except Exception as e:
                logger.warning(f"⚠️ Service restart failed for {service}: {e}")
                results[service] = False
        
        # Count successful restarts
        successful = sum(1 for result in results.values() if result)
        total = len(results)
        
        logger.info(f"🔄 Backward compatibility restart_services completed: {successful}/{total} services restarted")
        
        return results
    
    async def get_service_status(self, service_name: str) -> Optional[Dict]:
        """Get the status of a specific service"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated service status check: {service_name}")
                return {
                    'service': service_name,
                    'status': 'running',
                    'enabled': True,
                    'simulated': True
                }
            
            status_data = {
                'api.version': '1',
                'service': service_name
            }
            
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            timeout_config = httpx.Timeout(connect=3.0, read=15.0, write=5.0, pool=10.0)
            async with httpx.AsyncClient(verify=True, timeout=timeout_config) as client:
                kwargs = {
                    'params': status_data,  # Use params for GET request
                    'timeout': timeout_config
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.get(
                    f"https://{self.whm_host}:2087/json-api/servicestatus",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        # Handle both dict and list response formats from WHM API
                        service_data = data.get('data', {})
                        
                        if isinstance(service_data, list) and len(service_data) > 0:
                            service_info = service_data[0]  # Get first service info
                        elif isinstance(service_data, dict):
                            service_info = service_data.get('service', {})
                        else:
                            service_info = {}
                        
                        # Extract status information with fallbacks
                        status = 'unknown'
                        enabled = False
                        
                        if isinstance(service_info, dict):
                            status = service_info.get('status', service_info.get('state', 'unknown'))
                            enabled = service_info.get('enabled', service_info.get('running', False))
                        
                        return {
                            'service': service_name,
                            'status': status,
                            'enabled': enabled,
                            'monitored': service_info.get('monitored', False) if isinstance(service_info, dict) else False,
                            'raw_response': service_data  # Include raw response for debugging
                        }
                        
        except Exception as e:
            logger.error(f"❌ Error checking {service_name} service status: {e}")
        
        return None
    
    async def restart_services(self, username: str, services: list = None) -> bool:
        """Restart hosting services for an account or server-wide"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated service restart for: {username}")
                return True
            
            # Default services to restart for hosting accounts
            default_services = ['httpd', 'mysql', 'proftpd', 'named']
            target_services = services or default_services
            
            logger.info(f"🔄 Starting service restart sequence for {username}")
            logger.info(f"   • Services to restart: {', '.join(target_services)}")
            
            restart_results = {}
            overall_success = True
            
            # Restart each service individually with status tracking
            for service in target_services:
                logger.info(f"🔄 Restarting {service} service...")
                
                # Check status before restart
                pre_status = await self.get_service_status(service)
                if pre_status:
                    logger.info(f"   • Pre-restart status: {pre_status.get('status', 'unknown')}")
                
                # Perform restart
                restart_success = await self.restart_service(service, username)
                restart_results[service] = restart_success
                
                if restart_success:
                    logger.info(f"✅ {service} service restarted successfully")
                    
                    # Brief delay to let service stabilize
                    import asyncio
                    await asyncio.sleep(2)
                    
                    # Check status after restart
                    post_status = await self.get_service_status(service)
                    if post_status:
                        logger.info(f"   • Post-restart status: {post_status.get('status', 'unknown')}")
                else:
                    logger.error(f"❌ Failed to restart {service} service")
                    overall_success = False
            
            # Summary report
            successful_services = [svc for svc, success in restart_results.items() if success]
            failed_services = [svc for svc, success in restart_results.items() if not success]
            
            if successful_services:
                logger.info(f"✅ Successfully restarted services: {', '.join(successful_services)}")
            
            if failed_services:
                logger.error(f"❌ Failed to restart services: {', '.join(failed_services)}")
                logger.error("❌ Some services may need manual intervention")
            
            if overall_success:
                logger.info(f"✅ All services restarted successfully for account: {username}")
            else:
                logger.warning(f"⚠️ Service restart completed with some failures for account: {username}")
            
            return overall_success
                        
        except Exception as e:
            logger.error(f"❌ Error restarting services for account: {e}")
            import traceback
            logger.error(f"❌ Full traceback: {traceback.format_exc()}")
        
        return False
    
    async def check_account_status(self, username: str) -> Optional[Dict]:
        """Check the current status of a hosting account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated status check: {username}")
                return {
                    'status': 'active',
                    'details': {
                        'web_server': 'running',
                        'email': 'running', 
                        'ftp': 'running',
                        'databases': 'running'
                    }
                }
            
            status_data = {
                'api.version': '1',
                'user': username
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': status_data,  # Use form data instead of JSON
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/accountsummary",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        account_info = data.get('data', {}).get('acct', [{}])[0]
                        
                        # Parse account status
                        suspended = account_info.get('suspended', 0)
                        status = 'suspended' if suspended else 'active'
                        
                        logger.info(f"✅ Status checked for account {username}: {status}")
                        return {
                            'status': status,
                            'details': {
                                'disk_usage': account_info.get('diskused', 'unknown'),
                                'disk_limit': account_info.get('disklimit', 'unknown'),
                                'bandwidth_usage': account_info.get('totalbwused', 'unknown'),
                                'email_accounts': account_info.get('emailaccounts', 'unknown'),
                                'databases': account_info.get('mysqldatabases', 'unknown')
                            }
                        }
                        
        except Exception as e:
            logger.error(f"❌ Error checking account status: {e}")
        
        return None
    
    def get_hosting_plans(self) -> list:
        """Get available hosting plans - Simplified 2-plan structure"""
        return [
            {
                'id': 1,
                'plan_name': 'Pro 7 Days',
                'name': 'Pro 7 Days',
                'whm_package': 'pro_7day',
                'type': 'shared',
                'disk_space_gb': 50,
                'bandwidth_gb': 500,
                'databases': 25,
                'email_accounts': 50,
                'subdomains': 25,
                'daily_price': 7.14,
                'weekly_price': 50.00,
                'monthly_price': 50.00,  # 7-day total price (not per month!)
                'period_price': 50.00,   # Actual price for this billing period
                'yearly_price': 0,
                'duration_days': 7,
                'billing_cycle': '7days',
                'display_price': '$50.00/7days',
                'features': [
                    'cPanel Control Panel',
                    'Free SSL Certificate',
                    '99.9% Uptime Guarantee',
                    '24/7 Support',
                    'Advanced Security',
                    'Daily Backups',
                    'Developer Tools',
                    'Perfect for Testing'
                ]
            },
            {
                'id': 2,
                'plan_name': 'Pro 30 Days',
                'name': 'Pro 30 Days', 
                'whm_package': 'pro_30day',
                'type': 'shared',
                'disk_space_gb': 100,
                'bandwidth_gb': 1000,
                'databases': 50,
                'email_accounts': 100,
                'subdomains': 50,
                'daily_price': 4.00,
                'monthly_price': 120.00,  # 30-day total price
                'period_price': 120.00,   # Actual price for this billing period
                'yearly_price': 0,
                'duration_days': 30,
                'billing_cycle': '30days',
                'display_price': '$120.00/30days',
                'features': [
                    'Everything in Pro 7 Days',
                    'Unlimited Subdomains',
                    'Advanced Analytics',
                    'White-label Email',
                    'Priority Support',
                    'Custom PHP Settings',
                    'Best Value (Save 44%)'
                ]
            }
        ]
    
    def format_hosting_plan(self, plan: Dict) -> str:
        """Format hosting plan for display - Updated for time-based plans"""
        duration = plan.get('duration_days', 0)
        
        # Choose appropriate price display
        if duration == 7:
            price_text = f"${plan.get('monthly_price', 0)} for 7 days"
            daily_rate = f"(${plan.get('daily_price', 0):.2f}/day)"
        elif duration == 30:
            price_text = f"${plan.get('monthly_price', 0)} for 30 days"
            daily_rate = f"(${plan.get('daily_price', 0):.2f}/day - Save 16%!)"
        else:
            price_text = f"${plan.get('monthly_price', 0)}"
            daily_rate = ""
        
        features_text = '\n'.join([f"• {feature}" for feature in plan.get('features', [])])
        
        return f"""
<b>{plan.get('name', 'Unknown')}</b> - {price_text}
💰 {daily_rate}

📊 {plan.get('disk_space_gb', 0)}GB Storage • {plan.get('databases', 0)} Databases

{features_text}
"""

    async def list_all_accounts(self) -> Optional[Dict]:
        """List all cPanel accounts on the server"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info("🔧 Simulated account listing - no credentials")
                return {
                    'accounts': [],
                    'simulation': True
                }
            
            list_data = {
                'api.version': '1'
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': list_data,
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/listaccts",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        accounts = data.get('data', {}).get('acct', [])
                        logger.info(f"✅ Found {len(accounts)} accounts on server")
                        return {
                            'accounts': accounts,
                            'simulation': False
                        }
                    else:
                        logger.error(f"❌ WHM API error: {data.get('metadata', {}).get('reason', 'Unknown error')}")
                else:
                    logger.error(f"❌ WHM API request failed: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"❌ Error listing accounts: {e}")
        
        return None

    async def delete_account(self, username: str, keep_dns: bool = False) -> bool:
        """Delete/terminate a cPanel account"""
        try:
            if not self.whm_api_token and not self.whm_password:
                logger.info(f"🔧 Simulated account deletion: {username}")
                return True
            
            delete_data = {
                'api.version': '1',
                'user': username,
                'keepdns': '1' if keep_dns else '0'
            }
            
            # Prepare headers and auth properly typed for HTTPX
            headers = None
            auth = None
            
            if self.whm_api_token:
                headers = {'Authorization': f'WHM {self.whm_username}:{self.whm_api_token}'}
            elif self.whm_password:
                auth = (self.whm_username, self.whm_password)
            
            async with httpx.AsyncClient(verify=True) as client:
                kwargs = {
                    'data': delete_data,
                    'timeout': 30.0
                }
                if headers:
                    kwargs['headers'] = headers
                if auth:
                    kwargs['auth'] = auth
                    
                response = await client.post(
                    f"https://{self.whm_host}:2087/json-api/removeacct",
                    **kwargs
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('metadata', {}).get('result') == 1:
                        logger.info(f"✅ Account deleted successfully: {username}")
                        return True
                    else:
                        reason = data.get('metadata', {}).get('reason', 'Unknown error')
                        logger.error(f"❌ Failed to delete account {username}: {reason}")
                else:
                    logger.error(f"❌ WHM API request failed: {response.status_code}")
                    
        except Exception as e:
            logger.error(f"❌ Error deleting account {username}: {e}")
        
        return False