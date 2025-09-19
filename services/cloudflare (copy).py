"""
Cloudflare DNS management API integration
Handles zone creation, DNS record management, and nameserver operations
"""

import os
import logging
import asyncio
import httpx  # HTTP client for Cloudflare API
from typing import Dict, List, Optional
from brand_config import get_platform_name

logger = logging.getLogger(__name__)

class CloudflareService:
    """Cloudflare API service for DNS management"""
    _client: Optional[httpx.AsyncClient] = None
    
    def __init__(self):
        self.email = os.getenv('CLOUDFLARE_EMAIL')
        self.api_key = os.getenv('CLOUDFLARE_API_KEY')
        self.api_token = os.getenv('CLOUDFLARE_API_TOKEN')
        self.base_url = "https://api.cloudflare.com/client/v4"
        
        # Prioritize API Key auth since Bearer token is failing validation
        if self.email and self.api_key:
            self.headers = {
                'X-Auth-Email': self.email.strip(),
                'X-Auth-Key': self.api_key.strip(),
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'Hostbay-Bot/1.0'
            }
        elif self.api_token:
            self.headers = {
                'Authorization': f'Bearer {self.api_token.strip()}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'Hostbay-Bot/1.0'
            }
        else:
            self.headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'Hostbay-Bot/1.0'
            }
    
    @classmethod
    async def get_client(cls) -> httpx.AsyncClient:
        """Get or create persistent HTTP client with connection pooling"""
        if cls._client is None or cls._client.is_closed:
            limits = httpx.Limits(
                max_keepalive_connections=20,
                max_connections=100,
                keepalive_expiry=30
            )
            timeout = httpx.Timeout(connect=3.0, read=10.0, write=5.0, pool=5.0)
            cls._client = httpx.AsyncClient(
                limits=limits,
                timeout=timeout,
                http2=False  # Disabled until h2 package is installed
            )
        return cls._client
    
    @classmethod
    async def close_client(cls):
        """Close HTTP client for clean shutdown"""
        if cls._client and not cls._client.is_closed:
            await cls._client.aclose()
            cls._client = None
    
    async def test_connection(self) -> tuple[bool, str]:
        """Test Cloudflare API connectivity with enhanced header handling"""
        try:
            if not self.api_token and not (self.email and self.api_key):
                return False, "Cloudflare credentials not configured"
            
            client = await self.get_client()
            
            if self.email and self.api_key:
                # Enhanced headers for API key auth (proven to work)
                enhanced_headers = {
                    'X-Auth-Email': self.email.strip(),
                    'X-Auth-Key': self.api_key.strip()
                }
                
                # Test with user endpoint first
                response = await client.get(
                    f"{self.base_url}/user",
                    headers=enhanced_headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        user_email = data.get('result', {}).get('email', 'unknown')
                        return True, f"API Key connected - user: {user_email}"
                    else:
                        errors = data.get('errors', [])
                        return False, f"API errors: {errors}"
                
                # Also test zones access with API key
                response = await client.get(
                    f"{self.base_url}/zones",
                    headers=enhanced_headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        zones_count = len(data.get('result', []))
                        return True, f"API Key connected - {zones_count} zones accessible"
                    else:
                        errors = data.get('errors', [])
                        return False, f"API errors: {errors}"
                else:
                    return False, f"API Key auth failed: HTTP {response.status_code}"
                    
            elif self.api_token:
                # Try Bearer token as fallback (currently failing)
                enhanced_headers = {
                    'Authorization': f'Bearer {self.api_token.strip()}'
                }
                
                response = await client.get(
                    f"{self.base_url}/user/tokens/verify",
                    headers=enhanced_headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        return True, "Bearer Token verified successfully"
                    else:
                        errors = data.get('errors', [])
                        return False, f"Token verification failed: {errors}"
                else:
                    return False, f"Bearer Token invalid or expired: HTTP {response.status_code}"
            
            # Fallback if neither API key nor token is available
            return False, "No valid authentication method available"
                
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
    
    async def create_zone(self, domain_name: str, domain_id: Optional[int] = None, standalone: bool = False) -> Optional[Dict]:
        """Create a new DNS zone in Cloudflare with atomic database locking
        
        Args:
            domain_name: The domain name for the zone
            domain_id: Optional domain ID if domain exists in database
            standalone: If True, create zone without requiring domain to exist in database (for hosting bundles)
        """
        try:
            if not self.api_token and not (self.email and self.api_key):
                logger.warning("⚠️ Cloudflare credentials not configured")
                return None
            
            logger.info(f"🌐 Creating Cloudflare zone for: {domain_name} (domain_id: {domain_id}, standalone: {standalone})")
            
            # STEP 1: Import database functions for zone creation locking
            from database import check_zone_creation_lock, create_zone_with_lock, get_zone_by_domain_id, get_domain_by_name
            
            # STEP 2: Get domain_id if not provided (unless standalone mode)
            if not domain_id and not standalone:
                domain_data = await get_domain_by_name(domain_name)
                if domain_data:
                    domain_id = domain_data['id']
                else:
                    logger.error(f"❌ Domain {domain_name} not found in database")
                    return None
            
            # STEP 2b: For non-standalone mode, ensure domain_id is valid
            if not standalone and domain_id is None:
                logger.error(f"❌ Invalid domain_id for {domain_name}")
                return None
            
            # STEP 3: Check if zone creation is already in progress (skip for standalone mode)
            if not standalone and domain_id:
                zone_lock_exists = await check_zone_creation_lock(domain_id)
                if zone_lock_exists:
                    logger.info(f"🔒 Zone creation already in progress for domain {domain_id}, checking existing zone")
                    
                    # Check if zone exists in our database
                    existing_zone = await get_zone_by_domain_id(domain_id)
                    if existing_zone:
                        logger.info(f"✅ Zone already exists in database for {domain_name}")
                        zone_result = {
                            'zone_id': existing_zone['cf_zone_id'],
                            'domain_name': domain_name,
                            'nameservers': existing_zone.get('nameservers', []),
                            'status': existing_zone.get('status')
                        }
                        # Ensure default DNS records exist
                        await self._ensure_default_dns_records(zone_result['zone_id'], domain_name)
                        return zone_result
                    else:
                        logger.warning(f"⚠️ Zone lock exists but no zone in database, retrying...")
                        # Fall through to create zone
            
            # STEP 4: Check Cloudflare API for existing zone first
            existing_zone = await self.get_zone_by_name(domain_name)
            if existing_zone:
                logger.info(f"✅ Zone already exists in Cloudflare for {domain_name}, saving to database")
                zone_id = existing_zone.get('id')
                nameservers = existing_zone.get('name_servers', [])
                status = existing_zone.get('status')
                
                # Validate required parameters before database save
                if zone_id is None:
                    logger.error(f"❌ Invalid zone_id from Cloudflare for {domain_name}")
                    return None
                if status is None:
                    logger.warning(f"⚠️ Missing status for zone {domain_name}, using default")
                    status = 'pending'
                
                # Save to database atomically (skip for standalone mode)
                if not standalone and domain_id is not None:
                    saved = await create_zone_with_lock(
                        domain_id=domain_id,
                        domain_name=domain_name,
                        cf_zone_id=zone_id,
                        nameservers=nameservers,
                        status=status
                    )
                    
                    if not saved:
                        logger.error(f"❌ Failed to save existing zone to database: {domain_name}")
                        return None
                
                zone_result = {
                    'zone_id': zone_id,
                    'domain_name': domain_name,
                    'nameservers': nameservers,
                    'status': status,
                    'success': True,
                    'result': {
                        'id': zone_id,
                        'name_servers': nameservers,
                        'status': status
                    }
                }
                # Ensure default DNS records exist
                await self._ensure_default_dns_records(zone_result['zone_id'], domain_name)
                return zone_result
            
            # STEP 5: Create new zone via Cloudflare API
            client = await self.get_client()
            response = await client.post(
                f"{self.base_url}/zones",
                headers=self.headers,
                json={
                    'name': domain_name,
                    'type': 'full'
                }
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    zone_info = data.get('result', {})
                    zone_id = zone_info.get('id')
                    nameservers = zone_info.get('name_servers', [])
                    status = zone_info.get('status')
                    
                    logger.info(f"✅ Cloudflare zone created via API for {domain_name}")
                    
                    # STEP 6: Validate required parameters before database save
                    if zone_id is None:
                        logger.error(f"❌ Invalid zone_id from Cloudflare API for {domain_name}")
                        return None
                    if status is None:
                        logger.warning(f"⚠️ Missing status for new zone {domain_name}, using default")
                        status = 'pending'
                    
                    # STEP 6: Save to database atomically with zone creation lock (skip for standalone mode)
                    if not standalone and domain_id is not None:
                        saved = await create_zone_with_lock(
                            domain_id=domain_id,
                            domain_name=domain_name,
                            cf_zone_id=zone_id,
                            nameservers=nameservers,
                            status=status
                        )
                        
                        if not saved:
                            logger.error(f"❌ Zone created in Cloudflare but failed to save to database: {domain_name}")
                            # The zone exists in Cloudflare but not in our database - this is a warning but not a critical error
                            return None
                    
                    zone_result = {
                        'zone_id': zone_id,
                        'domain_name': domain_name,
                        'nameservers': nameservers,
                        'status': status,
                        'success': True,
                        'result': {
                            'id': zone_id,
                            'name_servers': nameservers,
                            'status': status
                        }
                    }
                    # Create default DNS records for new zone
                    await self._ensure_default_dns_records(zone_result['zone_id'], domain_name)
                    return zone_result
                else:
                    errors = data.get('errors', [])
                    logger.error(f"❌ Cloudflare zone creation failed: {errors}")
                    
                    # Check if error is because zone already exists
                    for error in errors:
                        if error.get('code') == 1061:  # Zone already exists error code
                            logger.info(f"🔄 Zone already exists in Cloudflare (error 1061), fetching existing zone")
                            existing_zone = await self.get_zone_by_name(domain_name)
                            if existing_zone:
                                # Validate existing zone data before saving
                                existing_zone_id = existing_zone.get('id')
                                existing_zone_status = existing_zone.get('status')
                                
                                if existing_zone_id is None:
                                    logger.error(f"❌ Invalid zone_id from existing Cloudflare zone for {domain_name}")
                                    return None
                                if existing_zone_status is None:
                                    logger.warning(f"⚠️ Missing status for existing zone {domain_name}, using default")
                                    existing_zone_status = 'pending'
                                
                                # Save the existing zone to database (skip for standalone mode)
                                if not standalone and domain_id:
                                    saved = await create_zone_with_lock(
                                        domain_id=domain_id,
                                        domain_name=domain_name,
                                        cf_zone_id=existing_zone_id,
                                        nameservers=existing_zone.get('name_servers', []),
                                        status=existing_zone_status
                                    )
                                    if not saved:
                                        logger.error(f"❌ Failed to save existing zone (1061) to database: {domain_name}")
                                        return None
                                
                                zone_result = {
                                    'zone_id': existing_zone.get('id'),
                                    'domain_name': domain_name,
                                    'nameservers': existing_zone.get('name_servers', []),
                                    'status': existing_zone.get('status'),
                                    'success': True,
                                    'result': {
                                        'id': existing_zone.get('id'),
                                        'name_servers': existing_zone.get('name_servers', []),
                                        'status': existing_zone.get('status')
                                    }
                                }
                                await self._ensure_default_dns_records(zone_result['zone_id'], domain_name)
                                return zone_result
            else:
                logger.error(f"❌ Cloudflare API request failed: {response.status_code}")
                try:
                    error_data = response.json()
                    logger.error(f"❌ Cloudflare API error details: {error_data}")
                except:
                    logger.error(f"❌ Cloudflare API raw response: {response.text}")
                    
        except Exception as e:
            logger.error(f"❌ Error creating Cloudflare zone: {e}")
        
        return None
    
    async def get_zone_info(self, zone_id: str) -> Optional[Dict]:
        """Get zone information with event loop resilience"""
        try:
            if not self.email or not self.api_key:
                return None
            
            # Handle event loop closure gracefully
            try:
                client = await self.get_client()
                response = await client.get(
                    f"{self.base_url}/zones/{zone_id}",
                    headers=self.headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        return data.get('result', {})
            except RuntimeError as runtime_error:
                if "event loop" in str(runtime_error).lower():
                    logger.warning(f"⚠️ Event loop closed during zone info fetch, using fallback for zone {zone_id}")
                    # For now, return None - the caller will handle appropriately 
                    return None
                else:
                    raise
                        
        except Exception as e:
            logger.error(f"❌ Error getting zone info: {e}")
        
        return None
    
    async def list_dns_records(self, zone_id: str, record_type: Optional[str] = None) -> List[Dict]:
        """List DNS records for a zone with event loop resilience"""
        try:
            if not self.email or not self.api_key:
                return []
            
            params = {}
            if record_type:
                params['type'] = record_type
            
            # Handle event loop closure gracefully 
            try:
                client = await self.get_client()
                response = await client.get(
                    f"{self.base_url}/zones/{zone_id}/dns_records",
                    headers=self.headers,
                    params=params
                )
                
                if response.status_code == 200:
                        data = response.json()
                        if data.get('success'):
                            return data.get('result', [])
            except RuntimeError as runtime_error:
                if "event loop" in str(runtime_error).lower():
                    logger.warning(f"⚠️ Event loop closed during DNS records fetch, returning empty list for zone {zone_id}")
                    return []
                else:
                    raise
                        
        except Exception as e:
            logger.error(f"❌ Error listing DNS records: {e}")
        
        return []
    
    async def create_dns_record(self, zone_id: str, record_type: str, name: str, content: str, ttl: int = 300, priority: Optional[int] = None, proxied: bool = False) -> Dict:
        """Create a new DNS record"""
        try:
            if not self.email or not self.api_key:
                return {'success': False, 'errors': [{'message': 'Cloudflare credentials not configured'}]}
            
            record_data = {
                'type': record_type.upper(),
                'name': name,
                'content': content,
                'ttl': ttl,
                'proxied': proxied
            }
            
            # Add priority for MX records
            if record_type.upper() == 'MX' and priority is not None:
                record_data['priority'] = priority
            
            client = await self.get_client()
            response = await client.post(
                f"{self.base_url}/zones/{zone_id}/dns_records",
                headers=self.headers,
                json=record_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    logger.info(f"✅ DNS record created: {record_type} {name}")
                    return {'success': True, 'result': data.get('result', {})}
                else:
                    errors = data.get('errors', [])
                    logger.error(f"❌ DNS record creation failed: {errors}")
                    return {'success': False, 'errors': errors}
            else:
                # Handle non-200 responses
                logger.error(f"❌ DNS API request failed with status {response.status_code}")
                try:
                    error_data = response.json()
                    errors = error_data.get('errors', [{'message': f'HTTP {response.status_code} error'}])
                    # Log detailed error information for debugging
                    for error in errors:
                        logger.error(f"Cloudflare API Error Details: {error}")
                except Exception as parse_error:
                    logger.error(f"Failed to parse error response: {parse_error}")
                    logger.error(f"Raw response text: {response.text}")
                    errors = [{'message': f'HTTP {response.status_code} error'}]
                return {'success': False, 'errors': errors}
                        
        except Exception as e:
            logger.error(f"❌ Error creating DNS record: {e}")
            return {'success': False, 'errors': [{'message': str(e)}]}
        
        return {'success': False, 'errors': [{'message': 'Unknown error occurred'}]}
    
    async def update_dns_record(self, zone_id: str, record_id: str, record_type: str, name: str, content: str, ttl: int = 300, priority: Optional[int] = None, proxied: bool = False) -> Dict:
        """Update an existing DNS record"""
        try:
            if not self.email or not self.api_key:
                return {'success': False, 'errors': [{'message': 'Cloudflare credentials not configured'}]}
            
            record_data = {
                'type': record_type.upper(),
                'name': name,
                'content': content,
                'ttl': ttl,
                'proxied': proxied
            }
            
            # Add priority for MX records
            if record_type.upper() == 'MX' and priority is not None:
                record_data['priority'] = priority
            
            client = await self.get_client()
            response = await client.put(
                f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}",
                headers=self.headers,
                json=record_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    logger.info(f"✅ DNS record updated: {record_type} {name}")
                    return {'success': True, 'result': data.get('result', {})}
                else:
                    errors = data.get('errors', [])
                    logger.error(f"❌ DNS record update failed: {errors}")
                    return {'success': False, 'errors': errors}
            else:
                # Handle non-200 responses
                logger.error(f"❌ DNS API update request failed with status {response.status_code}")
                try:
                    error_data = response.json()
                    errors = error_data.get('errors', [{'message': f'HTTP {response.status_code} error'}])
                    # Log detailed error information for debugging
                    for error in errors:
                        logger.error(f"Cloudflare API Update Error Details: {error}")
                except Exception as parse_error:
                    logger.error(f"Failed to parse update error response: {parse_error}")
                    logger.error(f"Raw update response text: {response.text}")
                    errors = [{'message': f'HTTP {response.status_code} error'}]
                return {'success': False, 'errors': errors}

        except Exception as e:
            logger.error(f"❌ Error updating DNS record: {e}")
            return {'success': False, 'errors': [{'message': str(e)}]}
        
        return {'success': False, 'errors': [{'message': 'Unknown error occurred'}]}

    async def get_dns_record(self, zone_id: str, record_id: str) -> Optional[Dict]:
        """Get a specific DNS record by ID"""
        try:
            if not self.email or not self.api_key:
                return None
            
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return data.get('result', {})
                        
        except asyncio.CancelledError:
            logger.warning("DNS record retrieval cancelled")
            raise
        except Exception as e:
            logger.exception("Error getting DNS record")
            error_msg = str(e) if str(e) else f"Exception: {e.__class__.__name__}"
            logger.error(f"❌ Error getting DNS record: {error_msg}")
        
        return None

    async def delete_dns_record(self, zone_id: str, record_id: str) -> bool:
        """Delete a DNS record"""
        try:
            if not self.email or not self.api_key:
                return False
            
            client = await self.get_client()
            response = await client.delete(
                f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        logger.info(f"✅ DNS record deleted: {record_id}")
                        return True
                        
        except Exception as e:
            logger.error(f"❌ Error deleting DNS record: {e}")
        
        return False
    
    async def get_zone_by_name(self, domain_name: str) -> Optional[Dict]:
        """Get zone by domain name"""
        try:
            if not self.email or not self.api_key:
                return None
            
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/zones",
                headers=self.headers,
                params={'name': domain_name}
            )
            
            if response.status_code == 200:
                    data = response.json()
                    if data.get('success') and data.get('result'):
                        zones = data.get('result', [])
                        if zones:
                            return zones[0]  # Return first matching zone
                        
        except Exception as e:
            logger.error(f"❌ Error getting zone by name: {e}")
        
        return None
    
    def format_dns_record(self, record: Dict) -> str:
        """Format DNS record for display"""
        record_type = record.get('type', '')
        name = record.get('name', '')
        content = record.get('content', '')
        ttl = record.get('ttl', 300)
        
        if record_type == 'MX':
            priority = record.get('priority', 0)
            return f"<b>{record_type}</b> <code>{name}</code> → <code>{content}</code> (Priority: {priority}, TTL: {ttl})"
        else:
            return f"<b>{record_type}</b> <code>{name}</code> → <code>{content}</code> (TTL: {ttl})"
    
    def get_supported_record_types(self) -> List[str]:
        """Get list of supported DNS record types"""
        return ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV']
    
    async def _ensure_default_dns_records(self, zone_id: str, domain_name: str):
        """Create default DNS records with 8.8.8.8 A record and www CNAME"""
        try:
            logger.info(f"🔧 Setting up default DNS records for {domain_name}")
            
            # Check existing A records for the root domain
            existing_records = await self.list_dns_records(zone_id, 'A')
            root_a_exists = any(r.get('name') == domain_name for r in existing_records)
            
            # Create root A record pointing to 8.8.8.8 (Google DNS - safe placeholder)
            if not root_a_exists:
                await self.create_dns_record(
                    zone_id=zone_id,
                    record_type='A',
                    name=domain_name,
                    content='8.8.8.8',
                    ttl=300,
                    proxied=False  # Proxy disabled as requested
                )
                logger.info(f"✅ Created default A record: {domain_name} → 8.8.8.8")
            else:
                logger.info(f"ℹ️ A record already exists for {domain_name}")
            
            # Check for www CNAME record
            www_domain = f"www.{domain_name}"
            existing_cnames = await self.list_dns_records(zone_id, 'CNAME')
            www_cname_exists = any(r.get('name') == www_domain for r in existing_cnames)
            
            # Create www CNAME record
            if not www_cname_exists:
                await self.create_dns_record(
                    zone_id=zone_id,
                    record_type='CNAME',
                    name=www_domain,
                    content=domain_name,
                    ttl=300,
                    proxied=False  # Proxy disabled as requested
                )
                logger.info(f"✅ Created www CNAME record: {www_domain} → {domain_name}")
            else:
                logger.info(f"ℹ️ CNAME record already exists for {www_domain}")
                
        except Exception as e:
            logger.error(f"❌ Error creating default DNS records: {e}")
            # Don't fail the zone creation if DNS record creation fails

    async def get_zone_settings(self, zone_id: str) -> Optional[Dict]:
        """Get zone security settings with normalized boolean values"""
        try:
            if not self.email or not self.api_key:
                return None
            
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/zones/{zone_id}/settings",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    raw_settings = {}
                    for setting in data.get('result', []):
                        setting_id = setting.get('id')
                        setting_value = setting.get('value')
                        raw_settings[setting_id] = setting_value
                    
                    # Normalize settings to expected format
                    normalized_settings = {
                        'security_level': raw_settings.get('security_level', 'medium'),
                        'always_use_https': raw_settings.get('always_use_https', 'off') == 'on',
                        'browser_check': raw_settings.get('browser_check', 'off') == 'on',
                        'ssl_mode': raw_settings.get('ssl', 'off'),
                        'raw': raw_settings  # Include raw settings for debugging
                    }
                    return normalized_settings
                else:
                    logger.error(f"❌ Failed to get zone settings: {data.get('errors', [])}")
            else:
                logger.error(f"❌ Zone settings request failed with status {response.status_code}")
                        
        except Exception as e:
            logger.error(f"❌ Error getting zone settings: {e}")
        
        return None

    async def update_security_level(self, zone_id: str, level: str) -> Dict:
        """Update security level. Options: 'off', 'essentially_off', 'low', 'medium', 'high', 'under_attack'"""
        try:
            if not self.email or not self.api_key:
                return {
                    'success': False, 
                    'errors': [{'message': 'Cloudflare credentials not configured'}]
                }
            
            # Validate security level
            valid_levels = ['off', 'essentially_off', 'low', 'medium', 'high', 'under_attack']
            if level not in valid_levels:
                return {
                    'success': False,
                    'errors': [{'message': f'Invalid security level. Must be one of: {", ".join(valid_levels)}'}]
                }
            
            client = await self.get_client()
            response = await client.patch(
                f"{self.base_url}/zones/{zone_id}/settings/security_level",
                headers=self.headers,
                json={'value': level}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    logger.info(f"✅ Updated security level to '{level}' for zone {zone_id}")
                    return {'success': True, 'result': data.get('result', {})}
                else:
                    errors = data.get('errors', [{'message': 'Unknown error occurred'}])
                    logger.error(f"❌ Failed to update security level: {errors}")
                    return {'success': False, 'errors': errors}
            else:
                # Handle non-200 responses with detailed error messages
                logger.error(f"❌ Security level API request failed with status {response.status_code}")
                try:
                    error_data = response.json()
                    errors = error_data.get('errors', [{'message': f'HTTP {response.status_code} error'}])
                    for error in errors:
                        logger.error(f"Cloudflare API Security Level Error: {error}")
                except Exception as parse_error:
                    logger.error(f"Failed to parse security level error response: {parse_error}")
                    logger.error(f"Raw response text: {response.text}")
                    errors = [{'message': f'HTTP {response.status_code} error'}]
                return {'success': False, 'errors': errors}
                        
        except Exception as e:
            logger.error(f"❌ Error updating security level: {e}")
            return {'success': False, 'errors': [{'message': str(e)}]}
        
        return {'success': False, 'errors': [{'message': 'Unknown error occurred'}]}

    async def update_force_https(self, zone_id: str, enabled: bool) -> Dict:
        """Enable or disable automatic HTTPS redirects with SSL validation"""
        try:
            if not self.email or not self.api_key:
                return {
                    'success': False, 
                    'errors': [{'message': 'Cloudflare credentials not configured'}]
                }
            
            # Check SSL status before enabling Force HTTPS
            if enabled:
                ssl_validation = await self.validate_ssl_for_https(zone_id)
                if not ssl_validation['valid']:
                    return {
                        'success': False,
                        'errors': [{
                            'message': ssl_validation['message'],
                            'code': 'ssl_required'
                        }]
                    }
            
            client = await self.get_client()
            response = await client.patch(
                f"{self.base_url}/zones/{zone_id}/settings/always_use_https",
                headers=self.headers,
                json={'value': 'on' if enabled else 'off'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    status = "enabled" if enabled else "disabled"
                    logger.info(f"✅ Force HTTPS {status} for zone {zone_id}")
                    return {'success': True, 'result': data.get('result', {})}
                else:
                    errors = data.get('errors', [{'message': 'Unknown error occurred'}])
                    logger.error(f"❌ Failed to update Force HTTPS: {errors}")
                    
                    # Handle common SSL-related errors
                    for error in errors:
                        error_code = error.get('code', '')
                        if error_code in ['ssl_required', 'ssl_not_active']:
                            error['user_message'] = "SSL certificate is required before enabling Force HTTPS. Please ensure your domain has a valid SSL certificate."
                    
                    return {'success': False, 'errors': errors}
            else:
                # Handle non-200 responses with detailed error messages  
                logger.error(f"❌ Force HTTPS API request failed with status {response.status_code}")
                try:
                    error_data = response.json()
                    errors = error_data.get('errors', [{'message': f'HTTP {response.status_code} error'}])
                    for error in errors:
                        logger.error(f"Cloudflare API Force HTTPS Error: {error}")
                except Exception as parse_error:
                    logger.error(f"Failed to parse Force HTTPS error response: {parse_error}")
                    logger.error(f"Raw response text: {response.text}")
                    errors = [{'message': f'HTTP {response.status_code} error'}]
                return {'success': False, 'errors': errors}
                        
        except Exception as e:
            logger.error(f"❌ Error updating Force HTTPS setting: {e}")
            return {'success': False, 'errors': [{'message': str(e)}]}
        
        return {'success': False, 'errors': [{'message': 'Unknown error occurred'}]}

    async def update_javascript_challenge(self, zone_id: str, enabled: bool) -> Dict:
        """Enable or disable JavaScript Challenge (Browser Integrity Check)"""
        try:
            if not self.email or not self.api_key:
                return {
                    'success': False, 
                    'errors': [{'message': 'Cloudflare credentials not configured'}]
                }
            
            client = await self.get_client()
            response = await client.patch(
                f"{self.base_url}/zones/{zone_id}/settings/browser_check",
                headers=self.headers,
                json={'value': 'on' if enabled else 'off'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    status = "enabled" if enabled else "disabled"
                    logger.info(f"✅ JavaScript Challenge {status} for zone {zone_id}")
                    return {'success': True, 'result': data.get('result', {})}
                else:
                    errors = data.get('errors', [{'message': 'Unknown error occurred'}])
                    logger.error(f"❌ Failed to update JavaScript Challenge: {errors}")
                    return {'success': False, 'errors': errors}
            else:
                # Handle non-200 responses with detailed error messages  
                logger.error(f"❌ JavaScript Challenge API request failed with status {response.status_code}")
                try:
                    error_data = response.json()
                    errors = error_data.get('errors', [{'message': f'HTTP {response.status_code} error'}])
                    for error in errors:
                        logger.error(f"Cloudflare API JavaScript Challenge Error: {error}")
                except Exception as parse_error:
                    logger.error(f"Failed to parse JavaScript Challenge error response: {parse_error}")
                    logger.error(f"Raw response text: {response.text}")
                    errors = [{'message': f'HTTP {response.status_code} error'}]
                return {'success': False, 'errors': errors}
                        
        except asyncio.CancelledError:
            logger.warning("JavaScript Challenge update cancelled")
            raise
        except Exception as e:
            logger.exception("Error updating JavaScript Challenge setting")
            error_msg = str(e) if str(e) else f"Exception: {e.__class__.__name__}"
            return {'success': False, 'errors': [{'message': error_msg}]}

    async def validate_ssl_for_https(self, zone_id: str) -> Dict:
        """Validate if SSL certificate is available before enabling Force HTTPS"""
        try:
            if not self.email or not self.api_key:
                return {'valid': False, 'message': 'Cloudflare credentials not configured'}
            
            client = await self.get_client()
            
            # Check SSL/TLS settings to see if SSL is active
            response = await client.get(
                f"{self.base_url}/zones/{zone_id}/settings/ssl",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    ssl_mode = data.get('result', {}).get('value', 'off')
                    logger.info(f"📋 Current SSL mode for zone {zone_id}: {ssl_mode}")
                    
                    # Check if SSL is properly configured
                    if ssl_mode in ['off', 'flexible']:
                        return {
                            'valid': False,
                            'message': (
                                "SSL certificate is required for Force HTTPS. "
                                f"Current SSL mode: {ssl_mode}. "
                                "Please configure Full or Full (Strict) SSL mode first."
                            )
                        }
                    else:
                        # SSL is configured (full, full_strict, etc.)
                        return {'valid': True, 'message': 'SSL is properly configured'}
                else:
                    logger.error(f"❌ Failed to get SSL settings: {data.get('errors', [])}")
                    return {'valid': False, 'message': 'Could not verify SSL configuration'}
            else:
                logger.error(f"❌ SSL settings request failed with status {response.status_code}")
                return {'valid': False, 'message': 'Could not verify SSL configuration'}
                
        except Exception as e:
            logger.error(f"❌ Error validating SSL for HTTPS: {e}")
            return {'valid': False, 'message': f'SSL validation error: {str(e)}'}

    def format_security_level_display(self, level: str) -> str:
        """Format security level for user-friendly display"""
        level_display = {
            'off': '❌ Off',
            'essentially_off': '🟢 Minimal',
            'low': '🟡 Low', 
            'medium': '🟠 Medium',
            'high': '🔴 High',
            'under_attack': '🚨 Under Attack'
        }
        return level_display.get(level, f'❓ Unknown ({level})')

    def get_security_level_description(self, level: str) -> str:
        """Get detailed description of security level"""
        descriptions = {
            'off': 'No security checks - all visitors allowed',
            'essentially_off': 'Minimal security - only block known bad actors', 
            'low': 'Low security - challenge suspicious visitors',
            'medium': 'Medium security - balanced protection (recommended)',
            'high': 'High security - challenge more visitors',
            'under_attack': 'Maximum security - for DDoS protection only'
        }
        return descriptions.get(level, 'Custom security configuration')

    async def get_ssl_certificate_info(self, zone_id: str) -> Optional[Dict]:
        """Get SSL certificate information for the zone"""
        try:
            if not self.email or not self.api_key:
                return None
            
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/zones/{zone_id}/ssl/certificate_packs",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    certs = data.get('result', [])
                    if certs:
                        # Return info about the primary certificate
                        primary_cert = certs[0]
                        return {
                            'status': primary_cert.get('status'),
                            'type': primary_cert.get('type'),
                            'hosts': primary_cert.get('hosts', []),
                            'expires_on': primary_cert.get('expires_on')
                        }
                        
        except Exception as e:
            logger.error(f"❌ Error getting SSL certificate info: {e}")
        
        return None

    # WAF Custom Rules API Methods for JavaScript Challenges
    
    async def get_waf_ruleset(self, zone_id: str) -> Optional[Dict]:
        """Get the WAF custom rules ruleset for a zone"""
        try:
            if not self.email or not self.api_key:
                return None
            
            client = await self.get_client()
            response = await client.get(
                f"{self.base_url}/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return data.get('result', {})
            elif response.status_code == 404:
                # Ruleset doesn't exist yet - this is normal
                logger.info(f"WAF custom ruleset doesn't exist yet for zone {zone_id}")
                return None
            else:
                logger.error(f"❌ Failed to get WAF ruleset: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    logger.error(f"Error details: {error_data}")
                except:
                    logger.error(f"Raw response: {response.text}")
                        
        except Exception as e:
            logger.error(f"❌ Error getting WAF ruleset: {e}")
        
        return None

    async def create_waf_custom_rule(self, zone_id: str, rule_data: Dict, tag_prefix: Optional[str] = None) -> Dict:
        """Create a WAF custom rule with idempotent management"""
        try:
            if not self.email or not self.api_key:
                return {'success': False, 'errors': [{'message': 'Cloudflare credentials not configured'}]}
            
            # Add tag prefix to description for idempotent management
            if tag_prefix is None:
                tag_prefix = get_platform_name()
            
            if 'description' in rule_data:
                rule_data['description'] = f"{tag_prefix}-{rule_data['description']}"
            else:
                rule_data['description'] = f"{tag_prefix}-Rule"
            
            logger.info(f"🛡️ Creating WAF custom rule for zone: {zone_id} with description: {rule_data['description']}")
            
            # Check for existing rules with same tag to avoid duplicates
            existing_rules = await self.list_waf_custom_rules(zone_id)
            tagged_rules = [
                rule for rule in existing_rules 
                if rule.get('description', '').startswith(f"{tag_prefix}-")
                and rule.get('action') == rule_data.get('action')
            ]
            
            if tagged_rules:
                logger.info(f"✅ Found existing tagged rule, skipping creation")
                return {'success': True, 'result': tagged_rules[0], 'exists': True}
            
            # Check if ruleset exists first
            existing_ruleset = await self.get_waf_ruleset(zone_id)
            client = await self.get_client()
            
            if existing_ruleset:
                # Add rule to existing ruleset
                ruleset_id = existing_ruleset.get('id')
                response = await client.post(
                    f"{self.base_url}/zones/{zone_id}/rulesets/{ruleset_id}/rules",
                    headers=self.headers,
                    json=rule_data
                )
            else:
                # Create new ruleset with the rule using PUT (not POST)
                ruleset_data = {
                    "rules": [rule_data]
                }
                response = await client.put(
                    f"{self.base_url}/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint",
                    headers=self.headers,
                    json=ruleset_data
                )
            
            # Accept both 200 and 201 status codes
            if response.status_code in [200, 201]:
                data = response.json()
                if data.get('success'):
                    logger.info(f"✅ WAF custom rule created successfully")
                    return {'success': True, 'result': data.get('result', {})}
                else:
                    errors = data.get('errors', [])
                    logger.error(f"❌ WAF rule creation failed: {errors}")
                    return {'success': False, 'errors': errors}
            else:
                logger.error(f"❌ WAF API request failed: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    errors = error_data.get('errors', [{'message': f'HTTP {response.status_code} error'}])
                    logger.error(f"Error details: {error_data}")
                except Exception as parse_error:
                    logger.error(f"Failed to parse error response: {parse_error}")
                    logger.error(f"Raw response: {response.text}")
                    errors = [{'message': f'HTTP {response.status_code} error'}]
                return {'success': False, 'errors': errors}
                        
        except Exception as e:
            logger.error(f"❌ Error creating WAF custom rule: {e}")
            return {'success': False, 'errors': [{'message': str(e)}]}

    async def list_waf_custom_rules(self, zone_id: str) -> List[Dict]:
        """List all WAF custom rules for a zone"""
        try:
            ruleset = await self.get_waf_ruleset(zone_id)
            if not ruleset:
                return []
            
            rules = ruleset.get('rules', [])
            logger.info(f"📋 Found {len(rules)} WAF custom rules for zone {zone_id}")
            return rules
                        
        except Exception as e:
            logger.error(f"❌ Error listing WAF custom rules: {e}")
            return []

    async def delete_waf_custom_rule(self, zone_id: str, rule_id: str) -> bool:
        """Delete a specific WAF custom rule"""
        try:
            if not self.email or not self.api_key:
                return False
            
            # Get ruleset to find rule
            ruleset = await self.get_waf_ruleset(zone_id)
            if not ruleset:
                logger.warning(f"No WAF ruleset found for zone {zone_id}")
                return False
            
            ruleset_id = ruleset.get('id')
            client = await self.get_client()
            
            response = await client.delete(
                f"{self.base_url}/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
                headers=self.headers
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    logger.info(f"✅ WAF custom rule deleted: {rule_id}")
                    return True
                else:
                    logger.error(f"❌ Failed to delete WAF rule: {data.get('errors', [])}")
            else:
                logger.error(f"❌ WAF rule deletion failed: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    logger.error(f"Error details: {error_data}")
                except:
                    logger.error(f"Raw response: {response.text}")
                        
        except Exception as e:
            logger.error(f"❌ Error deleting WAF custom rule: {e}")
        
        return False

    async def update_waf_custom_rule(self, zone_id: str, rule_id: str, rule_data: Dict) -> Dict:
        """Update an existing WAF custom rule"""
        try:
            if not self.email or not self.api_key:
                return {'success': False, 'errors': [{'message': 'Cloudflare credentials not configured'}]}
            
            # Get ruleset to find rule
            ruleset = await self.get_waf_ruleset(zone_id)
            if not ruleset:
                return {'success': False, 'errors': [{'message': 'WAF ruleset not found'}]}
            
            ruleset_id = ruleset.get('id')
            client = await self.get_client()
            
            response = await client.patch(
                f"{self.base_url}/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
                headers=self.headers,
                json=rule_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    logger.info(f"✅ WAF custom rule updated: {rule_id}")
                    return {'success': True, 'result': data.get('result', {})}
                else:
                    errors = data.get('errors', [])
                    logger.error(f"❌ WAF rule update failed: {errors}")
                    return {'success': False, 'errors': errors}
            else:
                logger.error(f"❌ WAF rule update failed: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    errors = error_data.get('errors', [{'message': f'HTTP {response.status_code} error'}])
                    logger.error(f"Error details: {error_data}")
                except Exception as parse_error:
                    logger.error(f"Failed to parse error response: {parse_error}")
                    logger.error(f"Raw response: {response.text}")
                    errors = [{'message': f'HTTP {response.status_code} error'}]
                return {'success': False, 'errors': errors}
                        
        except Exception as e:
            logger.error(f"❌ Error updating WAF custom rule: {e}")
            return {'success': False, 'errors': [{'message': str(e)}]}

    async def enable_javascript_challenge(self, zone_id: str, description: str = "JS-Challenge-AllTraffic") -> Dict:
        """Enable visible JavaScript challenge for all traffic with idempotent management"""
        rule_data = {
            "action": "js_challenge",
            "expression": "true",
            "description": description,
            "enabled": True
        }
        
        result = await self.create_waf_custom_rule(zone_id, rule_data)
        if result.get('success'):
            if result.get('exists'):
                logger.info(f"✅ JavaScript challenge already enabled for zone {zone_id}")
            else:
                logger.info(f"✅ JavaScript challenge enabled for zone {zone_id}")
        return result

    async def disable_javascript_challenge(self, zone_id: str) -> bool:
        """Disable JavaScript challenge by finding and removing only platform-tagged rules"""
        try:
            rules = await self.list_waf_custom_rules(zone_id)
            
            # Find only platform-tagged JavaScript challenge rules
            platform_name = get_platform_name()
            js_challenge_rules = [
                rule for rule in rules 
                if (rule.get('action') == 'js_challenge' 
                    and rule.get('description', '').startswith(f'{platform_name}-'))
            ]
            
            if not js_challenge_rules:
                logger.info(f"No {get_platform_name()} JavaScript challenge rules found for zone {zone_id}")
                return True
            
            # Delete only platform-tagged JavaScript challenge rules with verification
            success_count = 0
            for rule in js_challenge_rules:
                rule_id = rule.get('id')
                rule_desc = rule.get('description', 'unknown')
                if rule_id:
                    logger.info(f"🗑️ Deleting JS challenge rule: {rule_desc} (ID: {rule_id})")
                    if await self.delete_waf_custom_rule(zone_id, rule_id):
                        success_count += 1
                        logger.info(f"✅ Successfully deleted rule: {rule_desc}")
                    else:
                        logger.error(f"❌ Failed to delete rule: {rule_desc}")
            
            # Verify deletion by re-checking rules
            updated_rules = await self.list_waf_custom_rules(zone_id)
            remaining_js_rules = [
                rule for rule in updated_rules 
                if (rule.get('action') == 'js_challenge' 
                    and rule.get('description', '').startswith(f'{platform_name}-'))
            ]
            
            if len(remaining_js_rules) == 0:
                logger.info(f"✅ All {get_platform_name()} JavaScript challenge rules disabled for zone {zone_id}")
                return True
            else:
                logger.warning(f"⚠️ {len(remaining_js_rules)} JavaScript challenge rules still remain after deletion")
                return False
                        
        except Exception as e:
            logger.error(f"❌ Error disabling JavaScript challenge: {e}")
            return False

    async def get_javascript_challenge_status(self, zone_id: str) -> Dict:
        """Get the current status of platform-tagged JavaScript challenge rules"""
        try:
            rules = await self.list_waf_custom_rules(zone_id)
            
            # Only count platform-tagged JavaScript challenge rules
            platform_name = get_platform_name()
            js_challenge_rules = [
                rule for rule in rules 
                if (rule.get('action') == 'js_challenge'
                    and rule.get('description', '').startswith(f'{platform_name}-'))
            ]
            
            if not js_challenge_rules:
                return {
                    'enabled': False,
                    'rule_count': 0,
                    'rules': []
                }
            
            # Check if any rules are enabled (conservative approach to prevent false positives)
            # Cloudflare rules default to enabled if no explicit field, so we must be explicit
            enabled_rules = []
            for rule in js_challenge_rules:
                # Only count as enabled if explicitly enabled or missing enabled field (Cloudflare default)
                if rule.get('enabled') is not False:  # True or None/missing means enabled
                    enabled_rules.append(rule)
            
            return {
                'enabled': len(enabled_rules) > 0,
                'rule_count': len(js_challenge_rules),
                'enabled_count': len(enabled_rules),
                'rules': js_challenge_rules
            }
                        
        except Exception as e:
            logger.error(f"❌ Error getting JavaScript challenge status: {e}")
            return {
                'enabled': False,
                'rule_count': 0,
                'rules': [],
                'error': str(e)
            }

    def format_waf_rule_display(self, rule: Dict) -> str:
        """Format WAF rule for display"""
        action = rule.get('action', 'unknown')
        description = rule.get('description', 'No description')
        expression = rule.get('expression', 'No expression')
        enabled = rule.get('enabled') is not False  # Cloudflare defaults to enabled
        
        status_icon = "✅" if enabled else "❌"
        action_display = {
            'js_challenge': '🔐 JavaScript Challenge',
            'managed_challenge': '🛡️ Managed Challenge',
            'challenge': '⚠️ Legacy Challenge',
            'block': '🚫 Block',
            'log': '📝 Log Only'
        }.get(action, f'❓ {action.title()}')
        
        return f"{status_icon} <b>{action_display}</b>\n📝 {description}\n🎯 Expression: <code>{expression}</code>"
    
    async def list_proxyable_records(self, zone_id: str) -> List[Dict]:
        """Get A/AAAA/CNAME records that can potentially be proxied"""
        try:
            if not self.email or not self.api_key:
                return []
            
            # Get all DNS records for the zone
            all_records = await self.list_dns_records(zone_id)
            
            # Filter for proxyable record types only
            proxyable_types = {'A', 'AAAA', 'CNAME'}
            proxyable_records = []
            
            for record in all_records:
                record_type = record.get('type', '').upper()
                if record_type in proxyable_types:
                    proxyable_records.append(record)
            
            logger.info(f"Found {len(proxyable_records)} proxyable records in zone {zone_id}")
            return proxyable_records
            
        except Exception as e:
            logger.error(f"❌ Error listing proxyable records: {e}")
            return []
    
    def is_record_proxy_eligible(self, record: Dict) -> Dict:
        """Check if a DNS record is safe to proxy with detailed reasoning"""
        try:
            record_type = record.get('type', '').upper()
            record_name = record.get('name', '')
            record_content = record.get('content', '')
            
            # Only A, AAAA, and CNAME records can be proxied
            if record_type not in {'A', 'AAAA', 'CNAME'}:
                return {
                    'eligible': False,
                    'reason': f'{record_type} records cannot be proxied',
                    'category': 'invalid_type'
                }
            
            # Check for service hostnames that shouldn't be proxied
            service_hostnames = {
                'mail', 'smtp', 'imap', 'pop', 'pop3', 'ftp', 'sftp',
                'autodiscover', 'autoconfig', 'cpanel', 'webmail',
                'ns1', 'ns2', 'ns3', 'ns4'  # nameservers
            }
            
            # Extract hostname part (remove domain suffix)
            hostname_parts = record_name.lower().split('.')
            if hostname_parts and hostname_parts[0] in service_hostnames:
                return {
                    'eligible': False,
                    'reason': f'Service hostname {hostname_parts[0]} should not be proxied',
                    'category': 'service_hostname'
                }
            
            # For A and AAAA records, check if IP is public
            if record_type in {'A', 'AAAA'}:
                from handlers import is_ip_proxyable  # Import here to avoid circular import
                
                if not is_ip_proxyable(record_content):
                    return {
                        'eligible': False,
                        'reason': f'IP address {record_content} is not publicly routable',
                        'category': 'private_ip'
                    }
            
            # For CNAME records, basic validation
            elif record_type == 'CNAME':
                if not record_content or record_content.lower() in service_hostnames:
                    return {
                        'eligible': False,
                        'reason': f'CNAME target {record_content} appears to be a service hostname',
                        'category': 'service_target'
                    }
            
            # If we get here, the record is eligible for proxying
            return {
                'eligible': True,
                'reason': f'{record_type} record with public destination can be safely proxied',
                'category': 'eligible'
            }
            
        except Exception as e:
            logger.error(f"❌ Error checking proxy eligibility: {e}")
            return {
                'eligible': False,
                'reason': f'Error checking eligibility: {str(e)}',
                'category': 'error'
            }
    
    async def update_record_proxied(self, zone_id: str, record_id: str, proxied: bool) -> Dict:
        """Toggle proxy status for a specific DNS record"""
        try:
            if not self.email or not self.api_key:
                return {'success': False, 'errors': [{'message': 'Cloudflare credentials not configured'}]}
            
            # First get the current record to preserve all settings
            current_record = await self.get_dns_record(zone_id, record_id)
            if not current_record:
                return {'success': False, 'errors': [{'message': 'DNS record not found'}]}
            
            # Check if record is eligible for proxying
            if proxied:  # Only check when enabling proxy
                eligibility = self.is_record_proxy_eligible(current_record)
                if not eligibility['eligible']:
                    return {
                        'success': False,
                        'errors': [{'message': f"Record cannot be proxied: {eligibility['reason']}"}]
                    }
            
            # Update the record with new proxy status, preserving all other fields
            updated_data = {
                'type': current_record.get('type'),
                'name': current_record.get('name'),
                'content': current_record.get('content'),
                'ttl': current_record.get('ttl', 300),
                'proxied': proxied
            }
            
            # Add priority if it's an MX record
            if current_record.get('type') == 'MX':
                updated_data['priority'] = current_record.get('priority')
            
            client = await self.get_client()
            response = await client.put(
                f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}",
                headers=self.headers,
                json=updated_data
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    proxy_status = "enabled" if proxied else "disabled"
                    record_name = current_record.get('name', 'unknown')
                    logger.info(f"✅ Proxy {proxy_status} for record: {record_name}")
                    return {'success': True, 'result': data.get('result', {})}
                else:
                    errors = data.get('errors', [])
                    logger.error(f"❌ Failed to update proxy status: {errors}")
                    return {'success': False, 'errors': errors}
            else:
                logger.error(f"❌ Proxy update request failed: HTTP {response.status_code}")
                try:
                    error_data = response.json()
                    errors = error_data.get('errors', [{'message': f'HTTP {response.status_code} error'}])
                except:
                    errors = [{'message': f'HTTP {response.status_code} error'}]
                return {'success': False, 'errors': errors}
                
        except Exception as e:
            logger.error(f"❌ Error updating record proxy status: {e}")
            return {'success': False, 'errors': [{'message': str(e)}]}
    
    async def get_web_records_for_proxy(self, zone_id: str, domain_name: str) -> List[Dict]:
        """Get standard web records (@ and www) that should be proxied for web features"""
        try:
            proxyable_records = await self.list_proxyable_records(zone_id)
            web_records = []
            
            # Target records: root domain and www subdomain
            target_names = {domain_name, f"www.{domain_name}"}
            
            for record in proxyable_records:
                record_name = record.get('name', '')
                record_type = record.get('type', '').upper()
                
                # Only consider A, AAAA, and CNAME records for main web traffic
                if record_type in {'A', 'AAAA', 'CNAME'} and record_name in target_names:
                    # Check if eligible for proxying
                    eligibility = self.is_record_proxy_eligible(record)
                    if eligibility['eligible']:
                        web_records.append({
                            **record,
                            'proxy_eligible': True,
                            'eligibility_reason': eligibility['reason']
                        })
                    else:
                        web_records.append({
                            **record,
                            'proxy_eligible': False,
                            'eligibility_reason': eligibility['reason']
                        })
            
            logger.info(f"Found {len(web_records)} web records for domain {domain_name}")
            return web_records
            
        except Exception as e:
            logger.error(f"❌ Error getting web records: {e}")
            return []

