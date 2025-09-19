"""
All command and callback handlers for Telegram Bot
Enhanced DNS flows with progressive disclosure UX patterns
"""

import logging
import os
import hashlib
import time
import secrets
import string
import asyncio
import ipaddress
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import ContextTypes
from typing import Optional, Dict, List, Any, Tuple, Literal
from database import (
    get_or_create_user, get_user_domains, save_domain, save_cloudflare_zone, 
    execute_update, execute_query, get_user_wallet_balance, debit_wallet_balance,
    credit_user_wallet, get_user_wallet_transactions, reserve_wallet_balance,
    finalize_wallet_reservation, get_cloudflare_zone, get_domain_provider_id,
    update_domain_nameservers, get_domain_nameservers, get_domain_auto_proxy_enabled,
    set_domain_auto_proxy_enabled, accept_user_terms, has_user_accepted_terms,
    get_or_create_user_with_status, create_hosting_subscription_with_id,
    create_cpanel_account, get_hosting_subscription_details, get_domain_by_name,
    log_domain_search, create_registration_intent, update_intent_status,
    finalize_domain_registration, get_active_registration_intent, check_domain_ownership_state,
    create_hosting_intent, update_hosting_intent_status, finalize_hosting_provisioning,
    get_active_hosting_intent, get_hosting_intent_by_id,
    # DNS Optimistic Concurrency Control functions
    get_dns_record_version, update_dns_record_version, check_dns_record_conflict,
    check_zone_creation_lock, create_zone_with_lock, get_zone_by_domain_id
)
from services.cloudflare import CloudflareService
from services.openprovider import OpenProviderService
from services.payment_provider import create_payment_address, check_payment_status, get_current_provider_name
from services.cpanel import CPanelService
from brand_config import (
    get_welcome_message, get_platform_name, get_dns_management_intro,
    get_service_error_message, get_payment_success_message, 
    get_domain_success_message, format_branded_message, BrandConfig
)
from admin_handlers import (
    handle_admin_broadcast, handle_admin_credit_wallet, handle_cancel_broadcast,
    execute_admin_credit, show_admin_credit_search, handle_admin_credit_user_search,
    handle_admin_credit_amount
)
from pricing_utils import format_money, calculate_marked_up_price
from crypto_config import crypto_config
from message_utils import (
    escape_html, format_bold, format_code_block, format_inline_code,
    create_success_message, create_error_message, create_info_message,
    create_warning_message, create_contact_support_message, get_platform_name as get_platform_name_html,
    render_crypto_payment, t_fmt
)
from services.registration_orchestrator import start_domain_registration as orchestrator_start_registration
from localization import (
    t, t_for_user, resolve_user_language, t_html, t_html_for_user,
    set_user_language_preference, get_supported_languages, is_language_supported
)

logger = logging.getLogger(__name__)

import html
import re
from qrcode import QRCode  # type: ignore[attr-defined]
from io import BytesIO

# ====================================================================
# SMART AUTO-APPLY DNS RECORD MANAGEMENT SYSTEM
# ====================================================================

class AutoApplySession:
    """
    AutoApplySession Manager for DNS records with debounced auto-apply logic.
    Provides real-time validation and automatic change application after validation.
    """
    
    def __init__(self, user_id: int, domain: str, record_id: str, record_type: str):
        self.user_id = user_id
        self.domain = domain
        self.record_id = record_id
        self.record_type = record_type.upper()
        self.original_state = {}
        self.draft_state = {}
        self.dirty_fields = set()
        self.last_change_time = 0
        self.apply_delay = 1.0  # 1 second delay
        self.is_applying = False
        self.apply_task = None
        self.validation_errors = {}
        # DNS Version Control for Optimistic Concurrency
        self.original_etag = None
        self.last_known_modified = None
        self.has_version_conflict = False
        self.conflict_resolution_needed = False
        
    async def set_original_state(self, record_data: Dict):
        """Initialize with current record state from API and version tracking"""
        # Normalize types to ensure consistent state management
        normalized_data = self._normalize_record_data(record_data)
        self.original_state = normalized_data.copy()
        self.draft_state = normalized_data.copy()
        self.dirty_fields.clear()
        
        # Initialize version control - get existing version data
        try:
            version_data = await get_dns_record_version(self.record_id)
            if version_data:
                self.original_etag = version_data.get('version_etag')
                self.last_known_modified = version_data.get('last_modified_at')
                logger.debug(f"📝 Loaded DNS version: {self.record_id} etag:{self.original_etag[:8] if self.original_etag else 'None'}...")
            else:
                # First time tracking this record - generate initial etag from content
                import hashlib
                content_str = str(sorted(normalized_data.items()))
                self.original_etag = hashlib.md5(content_str.encode()).hexdigest()
                logger.debug(f"📝 New DNS version tracking: {self.record_id} etag:{self.original_etag[:8]}...")
        except Exception as e:
            logger.warning(f"Failed to load DNS version for {self.record_id}: {e}")
            # Fall back to content-based etag
            import hashlib
            content_str = str(sorted(normalized_data.items()))
            self.original_etag = hashlib.md5(content_str.encode()).hexdigest()
        
        # Reset conflict flags
        self.has_version_conflict = False
        self.conflict_resolution_needed = False
        
    def update_field(self, field: str, value: str) -> Dict[str, Any]:
        """Update a field and trigger debounced validation/apply"""
        # Normalize the value to proper type
        normalized_value = self._normalize_field_value(field, value)
        
        # Update draft state
        old_value = self.draft_state.get(field)
        self.draft_state[field] = normalized_value
        
        # Track dirty fields by comparing with original state
        if normalized_value != self.original_state.get(field):
            self.dirty_fields.add(field)
        else:
            self.dirty_fields.discard(field)
            
        # Update change time for debouncing
        self.last_change_time = time.time()
        
        # Cancel any existing apply task
        if self.apply_task and not self.apply_task.done():
            self.apply_task.cancel()
        
        # Schedule new auto-apply task if there are changes
        if self.dirty_fields:
            self.apply_task = asyncio.create_task(self._schedule_auto_apply())
        
        # Return immediate validation results
        return self.validate_current_state()
    
    def validate_current_state(self) -> Dict[str, Any]:
        """Validate current draft state and return validation results"""
        self.validation_errors.clear()
        
        # Record type specific validation
        if self.record_type == "A":
            self._validate_a_record()
        elif self.record_type == "CNAME":
            self._validate_cname_record()
        elif self.record_type == "MX":
            self._validate_mx_record()
        elif self.record_type == "TXT":
            self._validate_txt_record()
        elif self.record_type == "AAAA":
            self._validate_aaaa_record()
            
        return {
            'valid': len(self.validation_errors) == 0,
            'errors': self.validation_errors,
            'dirty_fields': list(self.dirty_fields),
            'has_changes': len(self.dirty_fields) > 0
        }
    
    def _validate_a_record(self):
        """Validate A record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        proxied = self.draft_state.get('proxied', False)  # Now normalized to bool
        
        # IP address validation
        if not content:
            self.validation_errors['content'] = "IP address is required"
        else:
            try:
                ip = ipaddress.ip_address(content)
                if ip.version != 4:
                    self.validation_errors['content'] = "IPv4 address required for A records"
                elif proxied and not is_ip_proxyable(content):
                    self.validation_errors['content'] = get_proxy_restriction_message(content)
            except (ipaddress.AddressValueError, ValueError):
                self.validation_errors['content'] = "Invalid IP address format"
                
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
        elif ttl > 86400:
            self.validation_errors['ttl'] = "TTL cannot exceed 86400 seconds (24 hours)"
    
    def _validate_aaaa_record(self):
        """Validate AAAA record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        
        # IPv6 address validation
        if not content:
            self.validation_errors['content'] = "IPv6 address is required"
        else:
            try:
                ip = ipaddress.ip_address(content)
                if ip.version != 6:
                    self.validation_errors['content'] = "IPv6 address required for AAAA records"
            except (ipaddress.AddressValueError, ValueError):
                self.validation_errors['content'] = "Invalid IPv6 address format"
                
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
    
    def _validate_cname_record(self):
        """Validate CNAME record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        
        # Target domain validation
        if not content:
            self.validation_errors['content'] = "Target domain is required"
        elif not is_valid_domain(content):
            self.validation_errors['content'] = "Target must be a valid domain name"
            
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
    
    def _validate_mx_record(self):
        """Validate MX record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        priority = self.draft_state.get('priority', 10)  # Now normalized to int
        
        # Mail server validation
        if not content:
            self.validation_errors['content'] = "Mail server is required"
        elif not is_valid_domain(content):
            self.validation_errors['content'] = "Mail server must be a valid domain name"
            
        # Priority validation (priority is now already an int)
        if priority < 0 or priority > 65535:
            self.validation_errors['priority'] = "Priority must be between 0 and 65535"
            
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
    
    def _validate_txt_record(self):
        """Validate TXT record fields"""
        content = self.draft_state.get('content', '')
        ttl = self.draft_state.get('ttl', 300)  # Now normalized to int
        
        # Content validation
        if not content:
            self.validation_errors['content'] = "TXT content is required"
        elif len(content) > 4096:
            self.validation_errors['content'] = "TXT content cannot exceed 4096 characters"
            
        # TTL validation (ttl is now already an int)
        if ttl < 1:
            self.validation_errors['ttl'] = "TTL must be 1 (Auto) or higher"
    
    async def should_auto_apply(self) -> bool:
        """Check if auto-apply should be triggered (debounced)"""
        if not self.dirty_fields or self.is_applying:
            return False
            
        # Check if enough time has passed since last change
        time_since_change = time.time() - self.last_change_time
        if time_since_change < self.apply_delay:
            return False
            
        # Validate before applying
        validation = self.validate_current_state()
        return validation['valid'] and validation['has_changes']
    
    async def auto_apply_changes(self, context) -> Dict[str, Any]:
        """Apply changes automatically with optimistic concurrency control"""
        if self.is_applying:
            return {'success': False, 'error': 'Already applying changes'}
            
        self.is_applying = True
        
        try:
            # STEP 1: Check for version conflicts before applying changes
            if self.original_etag:
                has_conflict, current_etag = await check_dns_record_conflict(self.record_id, self.original_etag)
                if has_conflict:
                    self.has_version_conflict = True
                    self.conflict_resolution_needed = True
                    logger.warning(f"🔄 DNS conflict detected: {self.record_id}, expected {self.original_etag[:8]}..., current {current_etag[:8] if current_etag else 'None'}...")
                    return {
                        'success': False,
                        'error': 'Version conflict detected',
                        'conflict': True,
                        'current_etag': current_etag,
                        'expected_etag': self.original_etag,
                        'message': 'Another user has modified this DNS record. Please refresh and try again.'
                    }
            
            # STEP 2: Get zone information
            cf_zone = await get_cloudflare_zone(self.domain)
            if not cf_zone:
                return {'success': False, 'error': 'DNS zone not found'}
            
            # STEP 3: Apply changes via CloudflareService
            cloudflare = CloudflareService()
            zone_id = cf_zone['cf_zone_id']
            
            # Prepare record data based on type
            record_data = self._prepare_record_data()
            
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=self.record_id,
                **record_data
            )
            
            if result and result.get('success'):
                # STEP 4: Success - update version tracking and clear state
                changes_applied = list(self.dirty_fields)
                
                # Generate new etag for the updated record
                import hashlib
                content_str = str(sorted(self.draft_state.items()))
                new_etag = hashlib.md5(content_str.encode()).hexdigest()
                content_hash = hashlib.sha256(content_str.encode()).hexdigest()
                
                # STEP 5: Update DNS record version tracking with CAS semantics
                try:
                    # Use Compare-And-Set to prevent race conditions
                    cas_result = await update_dns_record_version(
                        record_id=self.record_id,
                        zone_id=zone_id,
                        record_type=self.record_type,
                        version_etag=new_etag,
                        content_hash=content_hash,
                        record_data=self.draft_state,
                        expected_etag=self.original_etag  # CAS: ensure version hasn't changed
                    )
                    
                    if cas_result.get('success'):
                        logger.debug(f"✅ DNS version CAS SUCCESS: {self.record_id} -> {new_etag[:8]}...")
                    elif cas_result.get('conflict'):
                        # CRITICAL: CAS CONFLICT after Cloudflare update!
                        # This means another session modified the record AFTER our Cloudflare change
                        current_etag = cas_result.get('current_etag')
                        logger.error(f"🚨 POST-APPLY CAS CONFLICT: {self.record_id}")
                        logger.error(f"   Expected: {self.original_etag[:8] if self.original_etag else 'None'}...")
                        logger.error(f"   Current:  {current_etag[:8] if current_etag else 'None'}...")
                        logger.error(f"   New:      {new_etag[:8]}...")
                        logger.error(f"   ⚠️ Cloudflare updated but version tracking failed - manual reconciliation needed")
                        
                        # Set conflict state but don't fail the entire operation
                        # The Cloudflare change was successful, just version tracking conflicted
                        self.has_version_conflict = True
                        self.conflict_resolution_needed = True
                        
                        return {
                            'success': True,  # Cloudflare change succeeded
                            'result': result.get('result', {}),
                            'changes_applied': changes_applied,
                            'new_etag': new_etag,
                            'warning': 'DNS record updated successfully, but version conflict detected - please refresh',
                            'version_conflict': True,
                            'version_conflict_details': {
                                'expected_etag': self.original_etag,
                                'current_etag': current_etag,
                                'message': 'Another user modified this record concurrently. Please refresh to see latest version.'
                            }
                        }
                    else:
                        # CAS failed for other reasons
                        error_msg = cas_result.get('error', 'Unknown CAS error')
                        logger.error(f"🚫 DNS version CAS ERROR: {self.record_id}: {error_msg}")
                        # Continue - don't fail the entire operation for version tracking issues
                        
                except Exception as version_error:
                    logger.error(f"🚫 DNS version tracking exception: {self.record_id}: {version_error}")
                    # Continue - don't fail the entire operation for version tracking issues
                
                # ONLY update original state if CAS was successful (no conflicts)
                if not self.has_version_conflict:
                    # Update original state to match applied state
                    self.original_state.update(self.draft_state)
                    self.original_etag = new_etag
                    self.dirty_fields.clear()
                    self.has_version_conflict = False
                    self.conflict_resolution_needed = False
                    
                    return {
                        'success': True,
                        'result': result.get('result', {}),
                        'changes_applied': changes_applied,
                        'new_etag': new_etag
                    }
                else:
                    # CAS conflict was already handled above - session remains in conflict state
                    # Return success since Cloudflare update succeeded, just with conflict warning
                    return {
                        'success': True,
                        'result': result.get('result', {}),
                        'changes_applied': changes_applied,
                        'version_conflict': True,
                        'warning': 'Changes applied but version conflict detected'
                    }
            else:
                # API failed - keep draft state for retry
                errors = result.get('errors', [{'message': 'Unknown error'}]) if result else [{'message': 'API call failed'}]
                return {
                    'success': False,
                    'error': errors[0].get('message', 'Update failed'),
                    'api_errors': errors
                }
                
        except Exception as e:
            logger.error(f"Auto-apply error for {self.record_type} record {self.record_id}: {e}")
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}'
            }
        finally:
            self.is_applying = False
    
    def _normalize_record_data(self, record_data: Dict) -> Dict:
        """Normalize record data to consistent types"""
        normalized = record_data.copy()
        
        # Normalize TTL to integer
        if 'ttl' in normalized:
            try:
                normalized['ttl'] = int(normalized['ttl'])
            except (ValueError, TypeError):
                normalized['ttl'] = 300  # Default TTL
        
        # Normalize proxied to boolean
        if 'proxied' in normalized:
            if isinstance(normalized['proxied'], str):
                normalized['proxied'] = normalized['proxied'].lower() == 'true'
            elif not isinstance(normalized['proxied'], bool):
                normalized['proxied'] = bool(normalized['proxied'])
        
        # Normalize priority to integer for MX records
        if 'priority' in normalized:
            try:
                normalized['priority'] = int(normalized['priority'])
            except (ValueError, TypeError):
                normalized['priority'] = 10  # Default priority
        
        # Ensure content is always a string
        if 'content' in normalized:
            normalized['content'] = str(normalized['content'])
        
        # Ensure name is always a string
        if 'name' in normalized:
            normalized['name'] = str(normalized['name'])
            
        return normalized
    
    def _normalize_field_value(self, field: str, value: str):
        """Normalize a single field value to the appropriate type"""
        if field == 'ttl':
            try:
                return int(value)
            except (ValueError, TypeError):
                return 300  # Default TTL
        elif field == 'proxied':
            if isinstance(value, str):
                return value.lower() == 'true'
            return bool(value)
        elif field == 'priority':
            try:
                return int(value)
            except (ValueError, TypeError):
                return 10  # Default priority
        else:
            # All other fields remain as strings
            return str(value)
    
    async def _schedule_auto_apply(self):
        """Schedule auto-apply after debounce delay"""
        try:
            # Wait for debounce delay
            await asyncio.sleep(self.apply_delay)
            
            # Validate before applying
            validation = self.validate_current_state()
            if validation['valid'] and validation['has_changes']:
                logger.info(f"Auto-applying changes for {self.record_type} record {self.record_id}")
                result = await self.auto_apply_changes(None)
                
                if result and result.get('success'):
                    logger.info(f"Auto-apply successful for {self.record_type} record {self.record_id}")
                else:
                    error_msg = result.get('error', 'Unknown error') if result else 'No result returned'
                    logger.warning(f"Auto-apply failed for {self.record_type} record {self.record_id}: {error_msg}")
            else:
                logger.debug(f"Skipping auto-apply for {self.record_type} record {self.record_id}: validation failed or no changes")
                
        except asyncio.CancelledError:
            logger.debug(f"Auto-apply cancelled for {self.record_type} record {self.record_id}")
        except Exception as e:
            logger.error(f"Error in auto-apply scheduling for {self.record_type} record {self.record_id}: {e}")
    
    def _prepare_record_data(self) -> Dict:
        """Prepare record data for API call based on record type"""
        base_data = {
            'record_type': self.record_type,
            'name': self.draft_state.get('name', ''),
            'content': self.draft_state.get('content', ''),
            'ttl': int(self.draft_state.get('ttl', 300))
        }
        
        # Add type-specific fields
        if self.record_type == 'A':
            base_data['proxied'] = self.draft_state.get('proxied', 'false') == 'true'
        elif self.record_type == 'MX':
            base_data['priority'] = int(self.draft_state.get('priority', 10))
            
        return base_data
    
    def revert_to_original(self):
        """Revert draft state back to original state"""
        self.draft_state = self.original_state.copy()
        self.dirty_fields.clear()
        self.validation_errors.clear()
    
    def get_changes_summary(self) -> List[str]:
        """Get human-readable summary of changes"""
        changes = []
        for field in self.dirty_fields:
            old_value = self.original_state.get(field, '')
            new_value = self.draft_state.get(field, '')
            
            # Format values for display
            if field == 'ttl':
                old_display = "Auto" if old_value == '1' else f"{old_value}s"
                new_display = "Auto" if new_value == '1' else f"{new_value}s"
                changes.append(f"TTL: {old_display} → {new_display}")
            elif field == 'proxied':
                old_display = "🟠 Proxied" if old_value == 'true' else "⚪ Direct"
                new_display = "🟠 Proxied" if new_value == 'true' else "⚪ Direct"
                changes.append(f"Proxy: {old_display} → {new_display}")
            elif field == 'content':
                if self.record_type == 'A':
                    changes.append(f"IP: {old_value} → {new_value}")
                elif self.record_type == 'CNAME':
                    changes.append(f"Target: {old_value} → {new_value}")
                elif self.record_type == 'MX':
                    changes.append(f"Server: {old_value} → {new_value}")
                else:
                    changes.append(f"Content: {old_value} → {new_value}")
            elif field == 'priority':
                changes.append(f"Priority: {old_value} → {new_value}")
            else:
                changes.append(f"{field.title()}: {old_value} → {new_value}")
                
        return changes


class DNSAutoApplyManager:
    """Global manager for DNS auto-apply sessions"""
    
    def __init__(self):
        self.sessions = {}  # user_id:record_id -> AutoApplySession
        
    def get_session(self, user_id: int, domain: str, record_id: str, record_type: str) -> AutoApplySession:
        """Get or create auto-apply session for a DNS record"""
        session_key = f"{user_id}:{record_id}"
        
        if session_key not in self.sessions:
            self.sessions[session_key] = AutoApplySession(user_id, domain, record_id, record_type)
            
        return self.sessions[session_key]
    
    def cleanup_session(self, user_id: int, record_id: str):
        """Clean up session when editing is complete"""
        session_key = f"{user_id}:{record_id}"
        if session_key in self.sessions:
            del self.sessions[session_key]
    
    async def process_pending_applies(self, context):
        """Process any pending auto-applies across all sessions"""
        for session in list(self.sessions.values()):
            if await session.should_auto_apply():
                await session.auto_apply_changes(context)

# Global DNS auto-apply manager instance
dns_auto_apply_manager = DNSAutoApplyManager()


# Enhanced validation functions
def validate_dns_record_field(record_type: str, field: str, value: str) -> Dict[str, Any]:
    """Enhanced field-level validation for DNS records"""
    errors = {}
    
    if record_type.upper() == 'A' and field == 'content':
        # A record IP validation
        try:
            ip = ipaddress.ip_address(value)
            if ip.version != 4:
                errors[field] = "IPv4 address required for A records"
        except (ipaddress.AddressValueError, ValueError):
            errors[field] = "Invalid IP address format"
    
    elif record_type.upper() == 'AAAA' and field == 'content':
        # AAAA record IPv6 validation
        try:
            ip = ipaddress.ip_address(value)
            if ip.version != 6:
                errors[field] = "IPv6 address required for AAAA records"
        except (ipaddress.AddressValueError, ValueError):
            errors[field] = "Invalid IPv6 address format"
    
    elif record_type.upper() == 'CNAME' and field == 'content':
        # CNAME target validation
        if not is_valid_domain(value):
            errors[field] = "Target must be a valid domain name"
    
    elif record_type.upper() == 'MX' and field == 'content':
        # MX server validation
        if not is_valid_domain(value):
            errors[field] = "Mail server must be a valid domain name"
    
    elif field == 'ttl':
        # TTL validation for all record types
        try:
            ttl_int = int(value)
            if ttl_int < 1:
                errors[field] = "TTL must be 1 (Auto) or higher"
            elif ttl_int > 86400:
                errors[field] = "TTL cannot exceed 86400 seconds"
        except (ValueError, TypeError):
            errors[field] = "TTL must be a valid number"
    
    elif field == 'priority' and record_type.upper() == 'MX':
        # MX priority validation
        try:
            priority_int = int(value)
            if priority_int < 0 or priority_int > 65535:
                errors[field] = "Priority must be between 0 and 65535"
        except (ValueError, TypeError):
            errors[field] = "Priority must be a valid number"
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }

# Auto-apply feedback function
async def auto_apply_with_feedback(query, context, session: AutoApplySession):
    """Apply changes with real-time feedback updates"""
    try:
        # Brief delay to allow debouncing
        await asyncio.sleep(0.5)
        
        # Re-check if we should still apply (user might have made more changes)
        if not await session.should_auto_apply():
            return
            
        # Apply changes
        result = await session.auto_apply_changes(context)
        
        if result['success']:
            logger.info(f"Auto-applied DNS changes for {session.record_type} record {session.record_id}")
            
            # Get current wizard state to refresh the UI
            wizard_state = context.user_data.get('dns_wizard')
            if wizard_state and wizard_state.get('record_id') == session.record_id:
                # Refresh the editing interface to show success state
                if session.record_type == 'A':
                    await continue_a_record_edit_wizard(query, context, wizard_state)
                elif session.record_type == 'CNAME':
                    await continue_cname_record_edit_wizard(query, wizard_state)
                elif session.record_type == 'TXT':
                    await continue_txt_record_edit_wizard(query, wizard_state)
                elif session.record_type == 'MX':
                    await continue_mx_record_edit_wizard(query, wizard_state)
                    
        else:
            logger.error(f"Auto-apply failed for {session.record_type} record {session.record_id}: {result['error']}")
            
            # Get user language for localized buttons
            user = query.from_user
            user_lang = await resolve_user_language(user.id, user.language_code) if user else 'en'
            
            # Show error message with retry option
            error_message = f"""
❌ Auto-Apply Failed

{result['error']}

Changes have been reverted. You can modify the record and it will auto-apply when valid.
"""
            
            keyboard = [
                [InlineKeyboardButton(t('buttons.try_again', user_lang), callback_data=f"dns:{session.domain}:edit:{session.record_id}")],
                [InlineKeyboardButton(t('buttons.back_to_record', user_lang), callback_data=f"dns:{session.domain}:record:{session.record_id}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            try:
                await safe_edit_message(query, error_message, reply_markup=reply_markup)
            except Exception as e:
                logger.error(f"Error showing auto-apply feedback: {e}")
                
    except Exception as e:
        logger.error(f"Error in auto_apply_with_feedback: {e}")

# ====================================================================
# END AUTO-APPLY SYSTEM
# ====================================================================

def is_ip_proxyable(ip_str):
    """Check if an IP address can be proxied by Cloudflare (must be public)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # IPv4 checks
        if ip.version == 4:
            # Private networks (RFC 1918)
            if ip.is_private:
                return False
            # Loopback (127.x.x.x)
            if ip.is_loopback:
                return False
            # Link-local (169.254.x.x)
            if ip.is_link_local:
                return False
            # Multicast
            if ip.is_multicast:
                return False
            # Reserved/unspecified
            if ip.is_reserved or ip.is_unspecified:
                return False
            # Test networks (RFC 3927, RFC 5737)
            test_networks = [
                ipaddress.IPv4Network('192.0.2.0/24'),    # TEST-NET-1
                ipaddress.IPv4Network('198.51.100.0/24'), # TEST-NET-2
                ipaddress.IPv4Network('203.0.113.0/24'),  # TEST-NET-3
            ]
            for test_net in test_networks:
                if ip in test_net:
                    return False
                    
        # IPv6 checks
        elif ip.version == 6:
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return False
            if ip.is_reserved or ip.is_unspecified:
                return False
                
        # If we get here, it's a public IP
        return True
        
    except (ipaddress.AddressValueError, ValueError):
        # Invalid IP format
        return False

def get_proxy_restriction_message(ip_str):
    """Get user-friendly message explaining why an IP cannot be proxied"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        if ip.is_private:
            return f"🚫 Private IP Cannot Use Proxy\n\n{ip_str} is a private address not reachable from internet.\n\nUse a public IP or select Direct mode."
        elif ip.is_loopback:
            return f"🚫 Localhost Cannot Use Proxy\n\n{ip_str} is only reachable locally.\n\nUse a public server IP instead."
        elif ip.is_link_local:
            return f"🚫 Link-Local Cannot Use Proxy\n\n{ip_str} is only valid within local network.\n\nUse a public server IP instead."
        else:
            return f"🚫 Reserved IP Cannot Use Proxy\n\n{ip_str} is a reserved address.\n\nUse a public server IP instead."
            
    except (ipaddress.AddressValueError, ValueError):
        return f"❌ Invalid IP Format\n\n{ip_str} is not a valid IP address.\n\nEnter a valid IPv4 or IPv6 address."

async def get_available_names_for_record_type(domain, record_type, zone_id):
    """Get available DNS names for a specific record type based on existing records"""
    try:
        cloudflare = CloudflareService()
        existing_records = await cloudflare.list_dns_records(zone_id)
        
        if not existing_records:
            # No existing records, all names available
            common_names = ['@', 'www', 'mail', 'blog', 'app', 'api', 'ftp']
            return [{'name': name, 'display': name if name != '@' else f'@ (root)', 'description': _get_name_description(name, domain)} for name in common_names]
        
        # Group existing records by name
        records_by_name = {}
        for record in existing_records:
            name = record.get('name', '')
            # Normalize root domain name to @
            if name == domain:
                name = '@'
            elif name.endswith(f'.{domain}'):
                name = name[:-len(f'.{domain}')]
            
            if name not in records_by_name:
                records_by_name[name] = []
            records_by_name[name].append(record.get('type', ''))
        
        # Determine available names based on record type
        available_names = []
        common_names = ['@', 'www', 'mail', 'blog', 'app', 'api', 'ftp', 'shop']
        
        for name in common_names:
            existing_types = records_by_name.get(name, [])
            
            if record_type == 'CNAME':
                # CNAME can only exist if NO other records exist at this name
                if not existing_types:
                    available_names.append({
                        'name': name,
                        'display': name if name != '@' else f'@ (root)',
                        'description': _get_name_description(name, domain)
                    })
            else:
                # A, TXT, MX can coexist with each other but not with CNAME
                if 'CNAME' not in existing_types:
                    available_names.append({
                        'name': name,
                        'display': name if name != '@' else f'@ (root)',
                        'description': _get_name_description(name, domain)
                    })
        
        return available_names
        
    except Exception as e:
        logger.error(f"Error getting available names: {e}")
        # Fallback to basic options
        return [{'name': 'www', 'display': 'www', 'description': f'www.{domain}'}]

def _get_name_description(name, domain):
    """Get user-friendly description for DNS name"""
    if name == '@':
        return f'{domain} (root domain)'
    elif name == 'www':
        return f'www.{domain} (website)'
    elif name == 'mail':
        return f'mail.{domain} (email server)'
    elif name == 'blog':
        return f'blog.{domain} (blog subdomain)'
    elif name == 'app':
        return f'app.{domain} (application)'
    elif name == 'api':
        return f'api.{domain} (API endpoint)'
    elif name == 'ftp':
        return f'ftp.{domain} (file transfer)'
    elif name == 'shop':
        return f'shop.{domain} (online store)'
    else:
        return f'{name}.{domain}'

def is_valid_domain(domain_name):
    """Validate if string is a proper domain name with comprehensive RFC compliance"""
    import idna
    
    if not domain_name or not isinstance(domain_name, str):
        return False
    
    # Clean and normalize input
    domain_name = domain_name.strip()
    if not domain_name:
        return False
    
    # Handle IDN (Internationalized Domain Names) conversion
    try:
        # Convert Unicode domain to ASCII (punycode)
        ascii_domain = idna.encode(domain_name, uts46=True).decode('ascii')
    except (idna.core.IDNAError, UnicodeError, UnicodeDecodeError):
        return False
    
    # Use ASCII version for validation
    domain_to_validate = ascii_domain.lower()
    
    # RFC 1035/1123 total length limit (253 characters)
    if len(domain_to_validate) > 253 or len(domain_to_validate) < 3:
        return False
    
    # Check for invalid patterns
    if '..' in domain_to_validate or domain_to_validate.startswith('.') or domain_to_validate.endswith('.'):
        return False
    
    # Split into labels and validate each
    labels = domain_to_validate.split('.')
    if len(labels) < 2:
        return False
    
    # Validate each label
    for label in labels:
        # RFC 1123 label length limit (63 characters per label)
        if len(label) > 63 or len(label) == 0:
            return False
        
        # Labels cannot start or end with hyphens
        if label.startswith('-') or label.endswith('-'):
            return False
        
        # Check for valid characters only (a-z, 0-9, hyphens)
        if not re.match(r'^[a-z0-9-]+$', label):
            return False
    
    # TLD cannot be all numeric and must be at least 2 characters (standard practice)
    tld = labels[-1]
    if tld.isdigit():
        return False
    
    # TLD must be at least 2 characters (no single character TLDs allowed)
    if len(tld) < 2:
        return False
    
    # Check subdomain level limit (max 10 levels as per OpenProvider)
    if len(labels) > 11:  # 10 subdomains + 1 TLD = 11 total parts
        return False
    
    return True

def get_domain_validation_error(domain_name) -> str:
    """Get specific error message for domain validation failure"""
    # For detailed validation errors, use OpenProvider's validation function
    try:
        from services.openprovider import OpenProviderService
        service = OpenProviderService()
        validation_result = service.validate_domain_rfc_compliant(domain_name)
        
        if not validation_result['valid']:
            return validation_result['error']
        else:
            return "Domain is valid"
            
    except Exception as e:
        # Fallback to basic error messages if OpenProvider service fails
        if not domain_name or not isinstance(domain_name, str):
            return "Domain name is required"
        
        domain_name = domain_name.strip()
        if not domain_name:
            return "Domain name cannot be empty"
        
        if len(domain_name) > 253:
            return f"Domain name too long: {len(domain_name)} characters (maximum: 253)"
        
        if len(domain_name) < 3:
            return "Domain name too short (minimum: 3 characters like 'a.b')"
        
        if '..' in domain_name:
            return "Domain name cannot contain consecutive dots"
        
        if domain_name.startswith('.') or domain_name.endswith('.'):
            return "Domain name cannot start or end with a dot"
        
        if '.' not in domain_name:
            return "Domain must contain at least one dot (e.g., 'example.com')"
        
        return "Invalid domain format"

def is_valid_nameserver(nameserver):
    """Validate if a string is a valid nameserver"""
    if not nameserver or len(nameserver) > 253:
        return False
    
    # Nameserver must be a valid domain name (FQDN)
    nameserver_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(nameserver_pattern, nameserver.strip().lower()))

async def _get_nameservers_python_fallback(domain_name: str) -> list:
    """Fallback method to get nameservers using Python socket when dig is not available"""
    import socket
    import asyncio
    
    try:
        # Run DNS query in executor to avoid blocking
        loop = asyncio.get_event_loop()
        
        def _dns_query():
            try:
                # Get nameserver records using socket library
                import dns.resolver
                answers = dns.resolver.resolve(domain_name, 'NS')
                return [str(answer).rstrip('.') for answer in answers]
            except ImportError:
                # If dnspython is not available, use socket approach
                try:
                    # This is a simplified approach - in production you might want more robust DNS resolution
                    import subprocess
                    # Use nslookup as a last resort (also check if available)
                    result = subprocess.run(['nslookup', '-type=NS', domain_name], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        # Parse nslookup output for nameservers
                        lines = result.stdout.split('\n')
                        nameservers = []
                        for line in lines:
                            if 'nameserver' in line.lower() and '=' in line:
                                ns = line.split('=')[-1].strip().rstrip('.')
                                if ns:
                                    nameservers.append(ns)
                        return nameservers
                except:
                    pass
                return []
        
        # Execute DNS query with timeout
        nameservers = await asyncio.wait_for(
            loop.run_in_executor(None, _dns_query), 
            timeout=5.0
        )
        
        return nameservers if nameservers else []
        
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"Python DNS fallback failed for {domain_name}: {e}")
        return []

def detect_nameserver_provider(nameservers):
    """Detect if nameservers are from Cloudflare or external provider"""
    if not nameservers:
        return "unknown", "No nameservers found"
    
    cloudflare_ns_patterns = [
        'cloudflare.com',
        'ns.cloudflare.com',
        '.cloudflare.com'
    ]
    
    # Check if any nameserver contains cloudflare patterns
    for ns in nameservers:
        ns_lower = ns.lower()
        for pattern in cloudflare_ns_patterns:
            if pattern in ns_lower:
                return "cloudflare", "Cloudflare DNS"
    
    # Check for common providers
    common_providers = {
        'google': ['ns-cloud'],
        'namecheap': ['registrar-servers.com'],
        'godaddy': ['domaincontrol.com'],
        'amazon': ['awsdns'],
        'digitalocean': ['digitalocean.com']
    }
    
    for provider, patterns in common_providers.items():
        for ns in nameservers:
            ns_lower = ns.lower()
            for pattern in patterns:
                if pattern in ns_lower:
                    return "external", f"{provider.title()} DNS"
    
    return "external", "Custom DNS"

def extract_provider_key(provider_name: str) -> str:
    """Extract provider key from detected provider name for consistent matching"""
    if not provider_name:
        return ""
    
    provider_lower = provider_name.lower()
    
    # Map provider names to consistent keys
    if 'godaddy' in provider_lower:
        return 'godaddy'
    elif 'namecheap' in provider_lower:
        return 'namecheap'
    elif 'google' in provider_lower:
        return 'google domains'
    elif 'cloudflare' in provider_lower:
        return 'cloudflare'
    elif 'amazon' in provider_lower or 'aws' in provider_lower:
        return 'amazon'
    elif 'digitalocean' in provider_lower:
        return 'digitalocean'
    else:
        return provider_lower.replace(' dns', '').replace(' nameservers', '').strip()

async def analyze_domain_nameservers(domain_name: str) -> dict:
    """Analyze domain nameservers for hosting setup automation"""
    try:
        import socket
        import asyncio
        import shutil
        
        # Get current nameservers using async dig or fallback to Python DNS
        nameservers = []
        
        # Check if dig command is available
        if shutil.which('dig'):
            try:
                # Use async subprocess to prevent blocking
                process = await asyncio.create_subprocess_exec(
                    'dig', '+short', 'NS', domain_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Wait for completion with timeout
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=8.0
                )
                
                if process.returncode == 0 and stdout:
                    stdout_text = stdout.decode('utf-8').strip()
                    if stdout_text:
                        nameservers = [ns.strip().rstrip('.') for ns in stdout_text.split('\n') if ns.strip()]
                        
            except (asyncio.TimeoutError, OSError, UnicodeDecodeError) as e:
                logger.warning(f"dig command failed for {domain_name}: {e}")
                nameservers = []
        else:
            # Fallback: dig not available, try Python socket-based DNS lookup
            try:
                nameservers = await _get_nameservers_python_fallback(domain_name)
            except Exception as e:
                logger.warning(f"Python DNS fallback failed for {domain_name}: {e}")
                nameservers = []
        
        # Final fallback to stored nameservers if all methods fail
        if not nameservers:
            try:
                nameservers = await get_domain_nameservers(domain_name) or []
            except Exception as e:
                logger.warning(f"Database nameserver lookup failed for {domain_name}: {e}")
                nameservers = []
        
        # Detect provider and get analysis
        provider_type, provider_name = detect_nameserver_provider(nameservers)
        
        # Get hosting nameservers (this would be your hosting provider's nameservers)
        hosting_nameservers = get_hosting_nameservers()
        
        # Check if domain is already using hosting nameservers
        is_hosting_configured = False
        if nameservers and hosting_nameservers:
            hosting_ns_set = set(ns.lower() for ns in hosting_nameservers)
            current_ns_set = set(ns.lower() for ns in nameservers)
            is_hosting_configured = hosting_ns_set <= current_ns_set
        
        return {
            'domain': domain_name,
            'current_nameservers': nameservers,
            'provider_type': provider_type,
            'provider_name': provider_name,
            'hosting_nameservers': hosting_nameservers,
            'is_hosting_configured': is_hosting_configured,
            'needs_nameserver_change': not is_hosting_configured
        }
        
    except Exception as e:
        logger.error(f"Error analyzing nameservers for {domain_name}: {e}")
        return {
            'domain': domain_name,
            'current_nameservers': [],
            'provider_type': 'unknown',
            'provider_name': 'Unknown',
            'hosting_nameservers': get_hosting_nameservers(),
            'is_hosting_configured': False,
            'needs_nameserver_change': True,
            'error': str(e)
        }

def get_hosting_nameservers() -> list:
    """Get the nameservers that should be used for hosting"""
    # Get hosting nameservers from environment or config
    import os
    
    # Try to get from environment variables first
    env_nameservers = os.environ.get('HOSTING_NAMESERVERS', '')
    if env_nameservers:
        nameservers = [ns.strip() for ns in env_nameservers.split(',') if ns.strip()]
        if nameservers:
            return nameservers
    
    # Fallback to production-ready nameservers (use actual ones when available)
    # TODO: Replace with actual hosting provider nameservers
    default_nameservers = [
        'ns1.hostbay.com',
        'ns2.hostbay.com'
    ]
    
    logger.info(f"Using default nameservers: {default_nameservers}. Configure HOSTING_NAMESERVERS environment variable for production.")
    return default_nameservers

async def generate_hosting_nameserver_guidance(domain_name: str, analysis: dict, plan_name: str) -> str:
    """Generate comprehensive nameserver setup guidance for hosting"""
    try:
        current_ns = analysis.get('current_nameservers', [])
        provider_name = analysis.get('provider_name', 'Unknown Provider')
        hosting_ns = analysis.get('hosting_nameservers', [])
        is_configured = analysis.get('is_hosting_configured', False)
        
        if is_configured:
            return f"""
✅ <b>Nameserver Configuration: Ready</b>

Your domain is already configured to use our hosting nameservers:
{chr(10).join(f"• {escape_html(ns)}" for ns in hosting_ns)}

After purchasing hosting, your domain will be automatically connected to your new hosting account.
"""
        
        if not current_ns:
            return f"""
⚠️ <b>Nameserver Configuration Required</b>

We couldn't detect current nameservers for your domain. After purchasing hosting, you'll need to:

1. <b>Access Your Domain Registrar</b>
2. <b>Update Nameservers</b> to:
{chr(10).join(f"   • {escape_html(ns)}" for ns in hosting_ns)}
3. <b>Wait for Propagation</b> (usually 24-48 hours)

We'll provide detailed instructions after purchase.
"""
        
        # Generate provider-specific instructions
        # Extract provider name from detected provider (e.g., "GoDaddy DNS" -> "godaddy")
        provider_key = extract_provider_key(provider_name)
        if provider_key in ['godaddy', 'namecheap', 'google domains']:
            provider_instructions = get_provider_specific_instructions(provider_key, hosting_ns)
        else:
            provider_instructions = get_generic_nameserver_instructions(hosting_ns)
        
        return f"""
🔧 <b>Nameserver Configuration Required</b>

<b>Current Provider:</b> {escape_html(provider_name)}
<b>Current Nameservers:</b>
{chr(10).join(f"• {escape_html(ns)}" for ns in current_ns[:3])}

<b>Required Nameservers for Hosting:</b>
{chr(10).join(f"• {escape_html(ns)}" for ns in hosting_ns)}

{provider_instructions}

⏱️ <b>Propagation Time:</b> 24-48 hours after nameserver change
"""
        
    except Exception as e:
        logger.error(f"Error generating nameserver guidance: {e}")
        return f"""
⚠️ <b>Nameserver Setup Required</b>

After purchasing hosting, you'll need to update your domain's nameservers to:
{chr(10).join(f"• {escape_html(ns)}" for ns in get_hosting_nameservers())}

We'll provide detailed setup instructions after purchase.
"""

def get_provider_specific_instructions(provider: str, hosting_ns: list) -> str:
    """Get provider-specific nameserver change instructions"""
    escaped_nameservers = ', '.join(escape_html(ns) for ns in hosting_ns)
    
    instructions = {
        'godaddy': f"""
<b>GoDaddy Instructions:</b>
1. Log in to your GoDaddy account
2. Go to "My Products" → "DNS"
3. Find your domain and click "Manage"
4. Scroll to "Nameservers" section
5. Select "I'll use my own nameservers"
6. Enter: {escaped_nameservers}
7. Click "Save"
""",
        'namecheap': f"""
<b>Namecheap Instructions:</b>
1. Log in to your Namecheap account
2. Go to "Domain List" → find your domain
3. Click "Manage" next to your domain
4. Go to "Nameservers" tab
5. Select "Custom DNS"
6. Enter: {escaped_nameservers}
7. Click the checkmark to save
""",
        'google domains': f"""
<b>Google Domains Instructions:</b>
1. Log in to your Google Domains account
2. Find your domain and click "Manage"
3. Go to "DNS" tab
4. Scroll to "Name servers"
5. Select "Use custom name servers"
6. Enter: {escaped_nameservers}
7. Click "Save"
"""
    }
    
    return instructions.get(provider, get_generic_nameserver_instructions(hosting_ns))

def get_generic_nameserver_instructions(hosting_ns: list) -> str:
    """Get generic nameserver change instructions"""
    return f"""
<b>General Instructions:</b>
1. <b>Access Your Domain Registrar</b> control panel
2. <b>Find DNS/Nameserver Settings</b> for your domain
3. <b>Change to Custom Nameservers:</b>
{chr(10).join(f"   • {escape_html(ns)}" for ns in hosting_ns)}
4. <b>Save Changes</b> and wait for propagation

💡 <b>Need Help?</b> Contact your registrar's support if you can't find these settings.
"""

async def show_hosting_management(query, subscription_id: str):
    """Show individual hosting account management interface"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting account not found or access denied.")
            return
        
        domain_name = subscription.get('domain_name', 'Unknown')
        plan_name = subscription.get('plan_name', 'Unknown')
        status = subscription.get('status', 'unknown')
        cpanel_username = subscription.get('cpanel_username', 'Not assigned')
        created_date = subscription.get('created_at', '')
        
        # Format creation date
        if created_date:
            try:
                from datetime import datetime
                if isinstance(created_date, str):
                    created_date = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                formatted_date = created_date.strftime('%B %d, %Y')
            except:
                formatted_date = str(created_date)[:10]
        else:
            formatted_date = 'Unknown'
        
        # Get user language for localized buttons
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Status indicator and available actions
        if status == 'active':
            status_icon = "🟢"
            status_text = "Active"
            action_buttons = [
                [InlineKeyboardButton(t('buttons.suspend_account', user_lang), callback_data=f"suspend_hosting_{subscription_id}")],
                [InlineKeyboardButton(t('buttons.restart_services', user_lang), callback_data=f"restart_hosting_{subscription_id}")]
            ]
        elif status == 'suspended':
            status_icon = "🔴"
            status_text = "Suspended"
            action_buttons = [
                [InlineKeyboardButton(t('buttons.unsuspend_account', user_lang), callback_data=f"unsuspend_hosting_{subscription_id}")]
            ]
        elif status == 'pending':
            status_icon = "🟡"
            status_text = "Pending Setup"
            action_buttons = []
        else:
            status_icon = "⚪"
            status_text = status.title()
            action_buttons = []
        
        message = f"""
🏠 <b>Hosting Management</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Plan:</b> {plan_name}
<b>Status:</b> {status_icon} {status_text}
<b>cPanel Username:</b> <code>{cpanel_username}</code>
<b>Created:</b> {formatted_date}

{get_hosting_status_description(status)}
"""
        
        keyboard = []
        
        # Add management actions
        keyboard.extend(action_buttons)
        
        # Add information buttons
        keyboard.extend([
            [InlineKeyboardButton(t('buttons.account_details', user_lang), callback_data=f"hosting_details_{subscription_id}")],
            [InlineKeyboardButton(t('buttons.cpanel_login', user_lang), callback_data=f"cpanel_login_{subscription_id}")],
            [InlineKeyboardButton(t('buttons.usage_stats', user_lang), callback_data=f"hosting_usage_{subscription_id}")]
        ])
        
        # Navigation
        keyboard.extend([
            [InlineKeyboardButton(t('buttons.back_to_my_hosting', user_lang), callback_data="my_hosting")],
            [InlineKeyboardButton(t('buttons.main_menu', user_lang), callback_data="main_menu")]
        ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing hosting management: {e}")
        await safe_edit_message(query, "❌ Error loading hosting. Try again.")

async def show_hosting_details(query, subscription_id: str):
    """Show detailed hosting account information"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting account not found or access denied.")
            return
        
        domain_name = subscription.get('domain_name', 'Not assigned')
        plan_name = subscription.get('plan_name', 'Unknown')
        status = subscription.get('status', 'unknown')
        server_ip = subscription.get('server_ip', 'Not assigned')
        created_at = subscription.get('created_at')
        next_billing = subscription.get('next_billing_date')
        
        # Format dates
        formatted_created = created_at.strftime("%B %d, %Y") if created_at else "Unknown"
        formatted_billing = next_billing.strftime("%B %d, %Y") if next_billing else "Unknown"
        
        message = f"""
📊 <b>Account Details</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Plan:</b> {plan_name}
<b>Server IP:</b> <code>{server_ip}</code>
<b>Status:</b> {status.title()}
<b>Created:</b> {formatted_created}
<b>Next Billing:</b> {formatted_billing}

💡 All technical details for your hosting account.
"""
        
        # Get user language for localized buttons
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        keyboard = [
            [InlineKeyboardButton(t('buttons.back_to_management', user_lang), callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing hosting details: {e}")
        await safe_edit_message(query, "❌ Error loading details. Try again.")

async def show_cpanel_login(query, subscription_id: str):
    """Show cPanel login credentials with copy functionality"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting account not found or access denied.")
            return
        
        domain_name = subscription.get('domain_name', 'hostingbay.sbs')
        cpanel_username = subscription.get('cpanel_username', 'Not assigned')
        cpanel_password = subscription.get('cpanel_password', 'Not assigned')
        server_ip = subscription.get('server_ip', 'Not assigned')
        
        # Construct cPanel URL
        cpanel_url = f"https://{domain_name}:2083" if domain_name != 'Not assigned' else f"https://{server_ip}:2083"
        
        message = f"""
🔧 <b>cPanel Login</b>

<b>🌐 URL:</b> <code>{cpanel_url}</code>
<b>👤 Username:</b> <code>{cpanel_username}</code>
<b>🔑 Password:</b> <code>{cpanel_password}</code>
<b>🖥️ Server:</b> <code>{server_ip}</code>

💡 Tap any credential above to copy to clipboard
💾 Save these credentials securely!
"""
        
        # Get user language for localized buttons
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        keyboard = [
            [InlineKeyboardButton(t('buttons.back_to_management', user_lang), callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing cPanel login: {e}")
        await safe_edit_message(query, "❌ Error loading credentials. Try again.")

async def show_hosting_usage(query, subscription_id: str):
    """Show hosting usage statistics"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting account not found or access denied.")
            return
        
        domain_name = subscription.get('domain_name', 'Not assigned')
        plan_name = subscription.get('plan_name', 'Unknown')
        
        # For now, show placeholder usage stats (can be enhanced with real cPanel API integration)
        message = f"""
📈 <b>Usage Statistics</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Plan:</b> {plan_name}

<b>📦 Disk Usage:</b> 0.1 GB / 5.0 GB (2%)
<b>📊 Bandwidth:</b> 0.5 GB / 50 GB (1%)
<b>📁 Files:</b> 12 / Unlimited
<b>📧 Email Accounts:</b> 1 / Unlimited
<b>🗂️ Databases:</b> 0 / 10

<b>⏱️ Uptime:</b> 99.9%
<b>🔄 Last Updated:</b> Just now

💡 Usage statistics update hourly.
"""
        
        # Get user language for localized buttons
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        keyboard = [
            [InlineKeyboardButton(t('buttons.back_to_management', user_lang), callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing hosting usage: {e}")
        await safe_edit_message(query, "❌ Error loading usage. Try again.")

def get_hosting_status_description(status: str) -> str:
    """Get description for hosting status"""
    descriptions = {
        'active': "✅ Your hosting account is active and fully operational. All services are running normally.",
        'suspended': "⚠️ Your hosting account has been suspended. Website and email services are currently unavailable.",
        'pending': "⏳ Your hosting account is being set up. This usually takes 10-15 minutes.",
        'expired': "⚠️ Your hosting account has expired. Please renew to restore services.",
        'cancelled': "❌ Your hosting account has been cancelled."
    }
    return descriptions.get(status, "ℹ️ Status information not available.")

async def suspend_hosting_account(query, subscription_id: str):
    """Show confirmation for hosting account suspension"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting account not found or access denied.")
            return
        
        domain_name = subscription.get('domain_name', 'Unknown')
        plan_name = subscription.get('plan_name', 'Unknown')
        
        message = f"""
⚠️ <b>Suspend Hosting Account</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Plan:</b> {plan_name}

<b>⚠️ Warning:</b> Suspending this account will:
• Stop all website services
• Disable email accounts
• Make the website inaccessible
• Prevent FTP access

Files and databases will be preserved and can be restored when unsuspended.

Are you sure you want to suspend this hosting account?
"""
        
        # Get user language for localized buttons
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        keyboard = [
            [InlineKeyboardButton(t('buttons.yes_suspend', user_lang), callback_data=f"confirm_suspend_{subscription_id}")],
            [InlineKeyboardButton(t('buttons.cancel', user_lang), callback_data=f"cancel_suspend_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error showing suspension confirmation: {e}")
        await safe_edit_message(query, "❌ Error loading confirmation. Try again.")

async def confirm_hosting_suspension(query, subscription_id: str):
    """Execute hosting account suspension"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details, update_hosting_subscription_status
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting account not found or access denied.")
            return
        
        domain_name = subscription.get('domain_name', 'Unknown')
        cpanel_username = subscription.get('cpanel_username')
        
        # Show processing message
        message_text, parse_mode = t_html('hosting_management.suspending_account', await resolve_user_language(query.from_user.id), domain=domain_name)
        await safe_edit_message(query, message_text, parse_mode=parse_mode)
        
        # Attempt to suspend via cPanel API
        suspension_success = False
        if cpanel_username:
            try:
                suspension_success = await cpanel.suspend_account(cpanel_username)
            except Exception as e:
                logger.error(f"Error suspending cPanel account {cpanel_username}: {e}")
        
        # Update database status regardless of cPanel API result
        await update_hosting_subscription_status(int(subscription_id), 'suspended')
        
        # Show result message
        if suspension_success:
            message = f"""
✅ <b>Account Suspended Successfully</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Status:</b> 🔴 Suspended

The hosting account has been suspended via cPanel. All services are now inactive.

You can unsuspend the account at any time to restore services.
"""
        else:
            message = f"""
⚠️ <b>Account Marked as Suspended</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Status:</b> 🔴 Suspended

The account has been marked as suspended in our system. 
Note: cPanel suspension may require manual intervention.

You can attempt to unsuspend the account at any time.
"""
        
        keyboard = [
            [InlineKeyboardButton("▶️ Unsuspend Account", callback_data=f"unsuspend_hosting_{subscription_id}")],
            [InlineKeyboardButton("⬅️ Back to Management", callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error confirming hosting suspension: {e}")
        await safe_edit_message(query, "❌ Error processing suspension. Please try again.")

async def unsuspend_hosting_account(query, subscription_id: str):
    """Execute hosting account unsuspension"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details, update_hosting_subscription_status
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting account not found or access denied.")
            return
        
        domain_name = subscription.get('domain_name', 'Unknown')
        cpanel_username = subscription.get('cpanel_username')
        
        # Show processing message
        message_text, parse_mode = t_html('hosting_management.unsuspending_account', await resolve_user_language(query.from_user.id), domain=domain_name)
        await safe_edit_message(query, message_text, parse_mode=parse_mode)
        
        # Attempt to unsuspend via cPanel API
        unsuspension_success = False
        if cpanel_username:
            try:
                unsuspension_success = await cpanel.unsuspend_account(cpanel_username)
            except Exception as e:
                logger.error(f"Error unsuspending cPanel account {cpanel_username}: {e}")
        
        # Update database status regardless of cPanel API result
        await update_hosting_subscription_status(int(subscription_id), 'active')
        
        # Show result message
        if unsuspension_success:
            message = f"""
✅ <b>Account Unsuspended Successfully</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Status:</b> 🟢 Active

The hosting account has been unsuspended via cPanel. All services are now restored.

Your website and email services should be available within a few minutes.
"""
        else:
            message = f"""
⚠️ <b>Account Marked as Active</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Status:</b> 🟢 Active

The account has been marked as active in our system.
Note: cPanel unsuspension may require manual intervention.

Please contact support if services are not restored within 15 minutes.
"""
        
        keyboard = [
            [InlineKeyboardButton("⏸️ Suspend Account", callback_data=f"suspend_hosting_{subscription_id}")],
            [InlineKeyboardButton("⬅️ Back to Management", callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error unsuspending hosting account: {e}")
        await safe_edit_message(query, "❌ Error processing unsuspension. Please try again.")

async def restart_hosting_services(query, subscription_id: str):
    """Restart hosting services for an account"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting account not found or access denied.")
            return
        
        domain_name = subscription.get('domain_name', 'Unknown')
        cpanel_username = subscription.get('cpanel_username')
        
        # Show processing message
        message_text, parse_mode = t_html('hosting_management.restarting_services', await resolve_user_language(query.from_user.id), domain=domain_name)
        await safe_edit_message(query, message_text, parse_mode=parse_mode)
        
        # Attempt to restart services via cPanel API
        restart_success = False
        if cpanel_username:
            try:
                restart_success = await cpanel.restart_services(cpanel_username)
            except Exception as e:
                logger.error(f"Error restarting services for cPanel account {cpanel_username}: {e}")
        
        # Show result message
        if restart_success:
            message = f"""
✅ <b>Services Restarted Successfully</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Status:</b> 🔄 Services Restarted

The following services have been restarted:
• Web Server (Apache/Nginx)
• Email Services
• Database Services
• FTP Services

Your website and services should be fully operational within 1-2 minutes.
"""
        else:
            message = f"""
⚠️ <b>Restart Request Processed</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Status:</b> 🔄 Restart Requested

The restart request has been processed.
Note: Service restart may require manual intervention or may take a few minutes.

Please contact support if services are not restored within 10 minutes.
"""
        
        keyboard = [
            [InlineKeyboardButton("⬅️ Back to Management", callback_data=f"manage_hosting_{subscription_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error restarting hosting services: {e}")
        await safe_edit_message(query, "❌ Error processing service restart. Please try again.")

async def check_hosting_status(query, subscription_id: str):
    """Check current hosting account status"""
    user = query.from_user
    
    try:
        from database import get_or_create_user, get_hosting_subscription_details
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get hosting subscription details
        subscription = await get_hosting_subscription_details(int(subscription_id), db_user['id'])
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting account not found or access denied.")
            return
        
        domain_name = subscription.get('domain_name', 'Unknown')
        cpanel_username = subscription.get('cpanel_username')
        current_status = subscription.get('status', 'unknown')
        
        # Show checking message
        message_text, parse_mode = t_html('hosting_management.checking_domain_status', await resolve_user_language(query.from_user.id), domain=domain_name)
        await safe_edit_message(query, message_text, parse_mode=parse_mode)
        
        # Get real-time status from cPanel API
        live_status = None
        status_details = {}
        
        if cpanel_username:
            try:
                status_result = await cpanel.check_account_status(cpanel_username)
                if status_result:
                    live_status = status_result.get('status')
                    status_details = status_result.get('details', {})
            except Exception as e:
                logger.error(f"Error checking cPanel account status {cpanel_username}: {e}")
        
        # Format status display
        if live_status == 'active':
            status_icon = "🟢"
            status_text = "Active"
            status_desc = "All services are running normally"
        elif live_status == 'suspended':
            status_icon = "🔴"
            status_text = "Suspended"
            status_desc = "Account is suspended - services are inactive"
        elif live_status == 'pending':
            status_icon = "🟡"
            status_text = "Pending"
            status_desc = "Account setup is in progress"
        else:
            status_icon = "⚪"
            status_text = current_status.title() if current_status else "Unknown"
            status_desc = "Status could not be determined from server"
        
        # Build status details
        details_text = ""
        if status_details:
            details_text = "\n\n<b>Service Details:</b>\n"
            for service, status in status_details.items():
                service_icon = "🟢" if status == "running" else "🔴" if status == "stopped" else "🟡"
                details_text += f"• {service_icon} {service.title()}: {status.title()}\n"
        
        message = f"""
🔍 <b>Hosting Status Check</b>

<b>Domain:</b> <code>{domain_name}</code>
<b>Status:</b> {status_icon} {status_text}

{status_desc}{details_text}

<i>Last checked: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</i>
"""
        
        # Status-specific action buttons
        if live_status == 'active':
            action_buttons = [
                [InlineKeyboardButton("⏸️ Suspend Account", callback_data=f"suspend_hosting_{subscription_id}")],
                [InlineKeyboardButton("🔄 Restart Services", callback_data=f"restart_hosting_{subscription_id}")]
            ]
        elif live_status == 'suspended':
            action_buttons = [
                [InlineKeyboardButton("▶️ Unsuspend Account", callback_data=f"unsuspend_hosting_{subscription_id}")]
            ]
        else:
            action_buttons = []
        
        action_buttons.append([InlineKeyboardButton("⬅️ Back to Management", callback_data=f"manage_hosting_{subscription_id}")])
        
        reply_markup = InlineKeyboardMarkup(action_buttons)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error checking hosting status: {e}")
        await safe_edit_message(query, "❌ Error checking hosting status. Please try again.")

async def recheck_hosting_nameservers(query, plan_id: str, domain_name: str):
    """Recheck nameserver configuration for hosting domain"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        plan_price = plan.get('monthly_price', 0)
        
        # Show checking message
        await safe_edit_message(query, f"🔄 Re-analyzing nameserver configuration for {domain_name}...")
        
        # Re-analyze nameserver configuration
        nameserver_analysis = await analyze_domain_nameservers(domain_name)
        
        # Generate updated nameserver setup guidance
        setup_guidance = await generate_hosting_nameserver_guidance(domain_name, nameserver_analysis, plan_name)
        
        message_text = f"""
🔗 Connect Existing Domain: {domain_name}

Hosting Plan:
• Plan: {plan_name}
• Price: ${plan_price}/month
• Domain: {domain_name} (your existing domain)

{setup_guidance}

Ready to proceed with {plan_name} hosting?
"""
        
        keyboard = [
            [InlineKeyboardButton(f"✅ Purchase Hosting - ${plan_price}/month", callback_data=f"confirm_hosting_existing_{plan_id}:{domain_name}")],
            [InlineKeyboardButton("🔍 Check Nameservers Again", callback_data=f"recheck_ns_{plan_id}:{domain_name}")],
            [InlineKeyboardButton("⬅️ Back to Domain Options", callback_data=f"collect_domain_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message_text, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error rechecking hosting nameservers: {e}")
        await safe_edit_message(query, "❌ Error checking nameservers. Please try again.")

def format_nameserver_display(nameservers, max_display=2):
    """Format nameservers for display in UI"""
    if not nameservers:
        return "None configured"
    
    if len(nameservers) <= max_display:
        return "\n".join([f"• <code>{ns}</code>" for ns in nameservers])
    else:
        displayed = nameservers[:max_display]
        remaining = len(nameservers) - max_display
        result = "\n".join([f"• <code>{ns}</code>" for ns in displayed])
        result += f"\n• ... and {remaining} more"
        return result

class WizardQueryAdapter:
    """Adapter for DNS wizard to interface with safe_edit_message"""
    def __init__(self, bot, chat_id, message_id, user_id):
        self.bot = bot
        self.chat_id = chat_id
        self.message_id = message_id
        self.user_id = user_id
        
        # Create from_user object
        class User:
            def __init__(self, user_id):
                self.id = user_id
        
        self.from_user = User(user_id)
        
        # Create message object
        class Message:
            def __init__(self, chat_id, message_id):
                self.chat = type('Chat', (), {'id': chat_id})()
                self.message_id = message_id
        
        self.message = Message(chat_id, message_id)
        self.inline_message_id = None
    
    async def edit_message_text(self, text, reply_markup=None, parse_mode=None):
        """Edit message text through bot"""
        return await self.bot.edit_message_text(
            chat_id=self.chat_id,
            message_id=self.message_id,
            text=text,
            reply_markup=reply_markup,
            parse_mode=parse_mode
        )

def escape_content_for_display(content: str, mode: str = "full") -> Tuple[str, Literal["HTML", "Markdown"]]:
    """Safely escape content for display in messages
    
    Args:
        content: The content to escape
        mode: "full" for confirmation/edit screens (preserves exact content, returns HTML)
              "summary" for lists/previews (safe truncation for Markdown)
    """
    if not content:
        return "(empty)", "Markdown"
    
    if mode == "full":
        # For confirmations - HTML mode with exact content preservation
        escaped_content = html.escape(content)
        return f"<pre><code>{escaped_content}</code></pre>", "HTML"
    else:
        # For summaries - safe truncation preserving critical DNS characters
        # Keep underscores and brackets but escape problematic Markdown chars
        safe_content = content.replace('`', "'").replace('*', '∗').replace('[', '(').replace(']', ')')
        if len(safe_content) > 80:
            return f"{safe_content[:80]}...(truncated)", "Markdown"
        return safe_content, "Markdown"

async def store_callback_token(user_id: int, callback_data: str) -> str:
    """Store callback data in database and return secure token"""
    # Generate cryptographically secure random token
    token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    
    # Set expiration time (1 hour from now)
    expires_at = datetime.now() + timedelta(hours=1)
    
    # Store in database
    await execute_update(
        "INSERT INTO callback_tokens (token, user_id, callback_data, expires_at) VALUES (%s, %s, %s, %s)",
        (token, user_id, callback_data, expires_at)
    )
    
    logger.info(f"Stored callback token: {len(callback_data)} chars -> c:{token}")
    return f"c:{token}"

async def compress_callback(callback_data: str, context) -> str:
    """Compress long callback data to stay under Telegram's 64-byte limit using database storage"""
    if len(callback_data) <= 60:  # Safe margin
        return callback_data
    
    # Get user_id from context
    user_id = context._user_id if hasattr(context, '_user_id') else None
    if not user_id and hasattr(context, 'user_data') and 'user_id' in context.user_data:
        user_id = context.user_data['user_id']
    
    if not user_id:
        logger.warning("No user_id available for callback compression, using fallback")
        return callback_data[:60]  # Truncate as fallback
    
    # Always use database storage for reliability
    try:
        token = await store_callback_token(user_id, callback_data)
        logger.info(f"Compressed callback: {len(callback_data)} chars -> {token}")
        return token
    except Exception as e:
        logger.error(f"Error storing callback token: {e}")
        # Fallback to truncation
        return callback_data[:60]

async def cleanup_expired_tokens():
    """Clean up expired callback tokens from database"""
    try:
        result = await execute_update(
            "DELETE FROM callback_tokens WHERE expires_at < NOW()"
        )
        if result > 0:
            logger.info(f"Cleaned up {result} expired callback tokens")
    except Exception as e:
        logger.error(f"Error cleaning up expired tokens: {e}")

async def retrieve_callback_token(user_id: int, token: str) -> Optional[str]:
    """Retrieve callback data from database by token"""
    result = await execute_query(
        "SELECT callback_data FROM callback_tokens WHERE token = %s AND user_id = %s AND expires_at > NOW()",
        (token, user_id)
    )
    
    if result:
        # Clean up expired tokens while we're here
        await execute_update(
            "DELETE FROM callback_tokens WHERE expires_at < NOW()"
        )
        return result[0]['callback_data']
    else:
        logger.error(f"Callback token not found or expired: {token}")
        return None

async def decompress_callback(callback_data: Optional[str], context) -> str:
    """Decompress callback data from token with database-first approach"""
    if not callback_data or not callback_data.startswith("c:"):
        return callback_data or "error:no_callback_data"
    
    token = callback_data[2:]  # Remove "c:" prefix
    
    # Get user_id from context
    user_id = context._user_id if hasattr(context, '_user_id') else None
    if not user_id and hasattr(context, 'user_data') and 'user_id' in context.user_data:
        user_id = context.user_data['user_id']
    
    # Try database first (primary storage)
    if user_id:
        try:
            result = await retrieve_callback_token(user_id, token)
            if result:
                logger.info(f"Decompressed callback from database: {callback_data} -> {len(result)} chars")
                return result
        except Exception as e:
            logger.error(f"Error retrieving callback from database: {e}")
    
    # Fallback to context storage (for backward compatibility)
    callback_states = context.user_data.get('callback_states', {})
    
    if token in callback_states:
        stored = callback_states[token]
        if isinstance(stored, dict):
            # Check expiration
            if stored.get('expires', 0) > time.time():
                original = stored['data']
                logger.info(f"Decompressed callback from context: {callback_data} -> {len(original)} chars")
                return original
            else:
                # Remove expired token
                del callback_states[token]
        else:
            # Old format
            original = stored
            logger.info(f"Decompressed callback (legacy): {callback_data} -> {len(original)} chars")
            return original
    
    # Final fallback
    logger.error(f"Callback token not found: {callback_data}")
    return "error:token_not_found"

# Global dictionary to store content hashes per message
_message_content_hashes = {}

async def safe_edit_message(query, message, reply_markup=None, parse_mode='HTML'):
    """Centralized safe message editing with deduplication"""
    try:
        # Enhanced logging for debugging - handle both regular and inline messages
        user = query.from_user
        if query.message:
            message_key = f"{query.message.chat.id}_{query.message.message_id}"
        else:
            message_key = query.inline_message_id or "unknown_inline"
        logger.info(f"Attempting message edit for user {user.id if user else 'unknown'}, message {message_key}")
        
        # Create content hash to check for duplicates
        content_hash = hashlib.md5(f"{message}_{reply_markup}".encode()).hexdigest()
        
        # Use message ID as key for storing last content hash
        last_hash = _message_content_hashes.get(message_key)
        
        if last_hash == content_hash:
            logger.info(f"Prevented duplicate message edit for message {message_key}")
            return True
        
        # Attempt the edit with timeout protection to prevent event loop issues
        logger.info(f"Executing message edit for user {user.id if user else 'unknown'}")
        await asyncio.wait_for(
            query.edit_message_text(message, reply_markup=reply_markup, parse_mode=parse_mode),
            timeout=15.0  # 15 second timeout to prevent event loop hanging
        )
        
        # Store the content hash to prevent future duplicates
        _message_content_hashes[message_key] = content_hash
        logger.info(f"Message edit successful for user {user.id if user else 'unknown'}")
        
        # Clean up old hashes to prevent memory leak (keep only last 1000 entries)
        if len(_message_content_hashes) > 1000:
            # Remove oldest entries
            keys_to_remove = list(_message_content_hashes.keys())[:-500]
            for key in keys_to_remove:
                del _message_content_hashes[key]
        
        return True
        
    except Exception as e:
        user = query.from_user
        if query.message:
            message_key = f"{query.message.chat.id}_{query.message.message_id}"
        else:
            message_key = query.inline_message_id or "unknown_inline"
        error_msg = str(e)
        if "Message is not modified" in error_msg or "exactly the same" in error_msg:
            logger.info(f"Message content identical for user {user.id if user else 'unknown'}, message {message_key}")
            return True
        else:
            logger.warning(f"Message edit failed for user {user.id if user else 'unknown'}: {e}")
            
            # FALLBACK: Try to send a new message if editing fails
            try:
                if query.message and query.message.chat:
                    # Send new message to the chat
                    await query.message.chat.send_message(
                        text=message, 
                        reply_markup=reply_markup, 
                        parse_mode=parse_mode
                    )
                    logger.info(f"Fallback: Sent new message for user {user.id if user else 'unknown'} after edit failed")
                    return True
                else:
                    logger.error(f"Cannot send fallback message - no chat context for user {user.id if user else 'unknown'}")
                    raise e
            except Exception as fallback_error:
                logger.error(f"Fallback message send also failed for user {user.id if user else 'unknown'}: {fallback_error}")
                raise e

# Initialize services
cloudflare = CloudflareService()
openprovider = OpenProviderService()
cpanel = CPanelService()

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command with terms acceptance check and routing"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in start command")
        return
    
    try:
        # PERFORMANCE OPTIMIZATION: Single query for all user data
        user_data = await get_or_create_user_with_status(
            telegram_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name
        )
        
        terms_accepted = user_data['terms_accepted_bool']
        logger.info(f"🔍 TERMS CHECK: User {user.id} ({user.username}) terms_accepted = {terms_accepted}")
        
        if terms_accepted:
            # User has already accepted terms, show dashboard directly
            await show_dashboard(update, context, user_data)
            logger.info(f"✅ DASHBOARD: User {user.id} started bot - showing dashboard (terms already accepted)")
        else:
            # User has not accepted terms, show terms acceptance screen
            await show_terms_acceptance(update, context)
            logger.info(f"📋 TERMS: User {user.id} started bot - showing terms acceptance")
            
    except Exception as e:
        logger.error(f"Error in start command: {e}")
        
        # Fallback to original welcome message on error
        welcome_message = get_welcome_message()
        keyboard = [
            [InlineKeyboardButton("🔍 Search", callback_data="search_domains"), InlineKeyboardButton("🌐 Domains", callback_data="my_domains")],
            [InlineKeyboardButton("💰 Wallet", callback_data="wallet_main"), InlineKeyboardButton("🏠 Hosting", callback_data="hosting_main")],
            [InlineKeyboardButton("👤 Profile", callback_data="profile_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        try:
            await message.reply_text(welcome_message, reply_markup=reply_markup)
        except Exception as fallback_error:
            logger.error(f"Error in start command fallback: {fallback_error}")

async def show_terms_acceptance(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """OPTIMIZED: Show terms and conditions acceptance screen (text only)"""
    import time
    start_time = time.perf_counter()
    
    user = update.effective_user
    
    if not user:
        logger.error("Missing user in show_terms_acceptance")
        return
    
    # Get user language with caching optimization
    user_lang = await resolve_user_language(user.id, user.language_code)
    platform_name = get_platform_name()
    
    # Translated terms message with proper placeholder substitution
    terms_title = t_fmt('terms.title', user_lang, platform_name=platform_name)
    terms_content = t_fmt('terms.content', user_lang)
    terms_message = terms_title + "\n\n" + terms_content

    keyboard = [
        [InlineKeyboardButton(t('buttons.accept', user_lang), callback_data="terms:accept"),
         InlineKeyboardButton(t('buttons.view_full', user_lang), callback_data="terms:view")],
        [InlineKeyboardButton(t('buttons.decline', user_lang), callback_data="terms:decline")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Get chat_id once for all attempts
    chat_id = update.effective_chat.id if update.effective_chat else user.id
    
    try:
        await context.bot.send_message(
            chat_id=chat_id,
            text=terms_message,
            reply_markup=reply_markup
        )
        elapsed = (time.perf_counter() - start_time) * 1000
        logger.info(f"⚡ TERMS SENT: User {user.id} in {elapsed:.1f}ms")
        
    except Exception as e:
        logger.error(f"Error sending terms message: {e}")
        # Final fallback with no formatting
        try:
            terms_title = t_fmt('terms.title', user_lang, platform_name=platform_name)
            terms_content = t_fmt('terms.content', user_lang)
            plain_message = terms_title + "\n\n" + terms_content
            
            await context.bot.send_message(
                chat_id=chat_id,
                text=plain_message,
                reply_markup=reply_markup
            )
        except Exception as fallback_error:
            logger.error(f"Error in terms fallback: {fallback_error}")

async def handle_terms_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle terms acceptance/decline callbacks"""
    query = update.callback_query
    user = update.effective_user
    
    if not query or not user:
        logger.error("Missing query or user in handle_terms_callback")
        return
    
    try:
        await query.answer()
        
        if query.data == "terms:accept":
            # Check if user has already accepted terms to prevent duplicate processing
            already_accepted = await has_user_accepted_terms(user.id)
            
            if already_accepted:
                # Duplicate callback - user already accepted terms, just show dashboard
                logger.info(f"User {user.id} - duplicate terms:accept callback ignored (already accepted)")
                await show_dashboard(update, context)
                return
            
            # Accept terms and create/update user
            db_user = await get_or_create_user(
                telegram_id=user.id,
                username=user.username,
                first_name=user.first_name,
                last_name=user.last_name
            )
            
            # Mark terms as accepted
            success = await accept_user_terms(user.id)
            
            if success:
                # Show success message and go to dashboard
                user_lang = await resolve_user_language(user.id, user.language_code)
                success_message = t_fmt('terms.accepted', user_lang)
                
                try:
                    await query.edit_message_text(
                        text=success_message
                    )
                except Exception as edit_error:
                    logger.warning(f"Could not edit message, sending new one: {edit_error}")
                    # Fallback to sending new message if edit fails
                    await context.bot.send_message(
                        chat_id=user.id,
                        text=success_message
                    )
                
                # Wait a moment then show dashboard
                await asyncio.sleep(1.5)
                await show_dashboard(update, context)
                
                logger.info(f"User {user.id} accepted terms successfully")
            else:
                try:
                    await query.edit_message_text(
                        text="❌ Error accepting terms. Please try again."
                    )
                except Exception as edit_error:
                    logger.warning(f"Could not edit message, sending new one: {edit_error}")
                    # Fallback to sending new message if edit fails
                    await context.bot.send_message(
                        chat_id=user.id,
                        text="❌ Error accepting terms. Please try again."
                    )
                
        elif query.data == "terms:decline":
            decline_message = f"""❌ Terms Declined

You need to accept our terms to use {get_platform_name()}.

You can restart anytime with /start to accept terms."""
            
            try:
                await query.edit_message_text(
                    text=decline_message
                )
            except Exception as edit_error:
                logger.warning(f"Could not edit message, sending new one: {edit_error}")
                # Fallback to sending new message if edit fails
                await context.bot.send_message(
                    chat_id=user.id,
                    text=decline_message
                )
            
        elif query.data == "terms:view":
            # Show full terms using localization system with proper placeholder substitution
            user_lang = await resolve_user_language(user.id, user.language_code)
            terms_title = t_fmt('terms.title', user_lang)
            terms_content = t_fmt('terms.content', user_lang)
            full_terms = f"{terms_title}\n\n{terms_content}"
            
            keyboard = [
                [InlineKeyboardButton(t('buttons.accept', user_lang), callback_data="terms:accept")],
                [InlineKeyboardButton(t('buttons.decline', user_lang), callback_data="terms:decline")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            try:
                await query.edit_message_text(
                    text=full_terms,
                    reply_markup=reply_markup
                )
            except Exception as edit_error:
                logger.warning(f"Could not edit message, sending new one: {edit_error}")
                # Fallback to sending new message if edit fails
                await context.bot.send_message(
                    chat_id=user.id,
                    text=full_terms,
                    reply_markup=reply_markup
                )
            
    except Exception as e:
        logger.error(f"Error in handle_terms_callback: {e}")

async def show_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE, user_data: Optional[Dict] = None):
    """Show main dashboard with wallet balance and menu options - Production-ready with event loop protection"""
    user = update.effective_user
    query = update.callback_query
    
    if not user:
        logger.error("Missing user in show_dashboard")
        return
    
    # PRODUCTION FIX: Add timeout and async protection for event loop stability
    async def _safe_dashboard_operation():
        # PERFORMANCE OPTIMIZATION: Use provided user_data or fetch if not provided
        if user_data is None:
            # Fallback to original queries with timeout protection
            try:
                db_user = await asyncio.wait_for(
                    get_or_create_user(
                        telegram_id=user.id,
                        username=user.username,
                        first_name=user.first_name,
                        last_name=user.last_name
                    ),
                    timeout=10.0  # 10 second timeout to prevent hanging
                )
                wallet_balance = await asyncio.wait_for(
                    get_user_wallet_balance(user.id),
                    timeout=10.0  # 10 second timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Database timeout for user {user.id}, using fallback")
                # Use fallback values if database is slow/unavailable
                db_user = {'id': user.id}
                wallet_balance = 0.0
            except Exception as db_error:
                logger.warning(f"Database error for user {user.id}: {db_error}, using fallback")
                # Use fallback values if database error
                db_user = {'id': user.id}
                wallet_balance = 0.0
        else:
            # Use provided user_data (from optimized query)
            db_user = user_data
            wallet_balance = user_data['wallet_balance_float']
        
        balance_display = format_money(wallet_balance)
        platform_name = get_platform_name()
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Check if user is admin
        admin_user_id = os.getenv('ADMIN_USER_ID')
        is_admin = admin_user_id and admin_user_id.isdigit() and user.id == int(admin_user_id)
        
        # Create dashboard message with translations
        dashboard_message = t_fmt('dashboard.title', user_lang) + "\n\n"
        # Use t_html for safe user name display
        welcome_text, _ = t_html('dashboard.welcome_back', user_lang, name=user.first_name or 'User')
        dashboard_message += welcome_text + "\n\n"
        dashboard_message += t('dashboard.balance', user_lang, balance=balance_display) + "\n\n"
        dashboard_message += t('dashboard.what_to_do', user_lang)

        keyboard = [
            [InlineKeyboardButton(t('buttons.search_domains', user_lang), callback_data="search_domains")],
            [InlineKeyboardButton(t('buttons.my_domains', user_lang), callback_data="my_domains")],
            [InlineKeyboardButton(t('buttons.wallet', user_lang), callback_data="wallet_main"), InlineKeyboardButton(t('buttons.hosting_from_price', user_lang, price="50"), callback_data="unified_hosting_plans")],
            [InlineKeyboardButton(t('buttons.profile', user_lang), callback_data="profile_main")],
            [InlineKeyboardButton(t('buttons.contact_support', user_lang), callback_data="contact_support")]
        ]
        
        # Add admin commands for admin users
        if is_admin:
            dashboard_message += "\n\n" + t('admin.admin_panel', user_lang)
            keyboard.append([InlineKeyboardButton(t('buttons.broadcast_message', user_lang), callback_data="admin_broadcast")])
            keyboard.append([InlineKeyboardButton(t('buttons.credit_user_wallet', user_lang), callback_data="admin_credit_wallet")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # PRODUCTION FIX: Send or edit message with timeout and retry protection
        if query:
            try:
                await asyncio.wait_for(
                    safe_edit_message(query, dashboard_message, reply_markup),
                    timeout=15.0  # 15 second timeout for Telegram operations
                )
            except asyncio.TimeoutError:
                logger.warning(f"Telegram edit timeout for user {user.id}, trying fallback")
                # Fallback to sending new message if edit times out
                await asyncio.wait_for(
                    context.bot.send_message(
                        chat_id=user.id,
                        text=dashboard_message,
                        reply_markup=reply_markup
                    ),
                    timeout=15.0
                )
        else:
            # Direct message with timeout protection
            if update.message:
                await asyncio.wait_for(
                    update.message.reply_text(
                        text=dashboard_message,
                        reply_markup=reply_markup
                    ),
                    timeout=15.0
                )
            else:
                await asyncio.wait_for(
                    context.bot.send_message(
                        chat_id=user.id,
                        text=dashboard_message,
                        reply_markup=reply_markup
                    ),
                    timeout=15.0
                )
        
        logger.info(f"Dashboard shown to user {user.id} with balance {balance_display}")
    
    try:
        # PRODUCTION FIX: Run the entire operation with overall timeout protection
        await asyncio.wait_for(_safe_dashboard_operation(), timeout=30.0)
        
    except asyncio.TimeoutError:
        logger.error(f"⚠️ PRODUCTION: Dashboard operation timed out for user {user.id} - using emergency fallback")
        # Emergency fallback for total timeout
        await _emergency_dashboard_fallback(update, context, user)
        
    except Exception as e:
        logger.error(f"⚠️ PRODUCTION: Dashboard error for user {user.id}: {e} - using emergency fallback")
        # Emergency fallback for any other error
        await _emergency_dashboard_fallback(update, context, user)

async def _emergency_dashboard_fallback(update: Update, context: ContextTypes.DEFAULT_TYPE, user):
    """Emergency fallback dashboard when main dashboard fails - Production resilience"""
    try:
        user_lang = await resolve_user_language(user.id, user.language_code)
        error_message = t_fmt('dashboard.title', user_lang) + " " + t('dashboard.what_to_do', user_lang)
        
        keyboard = [
            [InlineKeyboardButton(t('buttons.search', user_lang), callback_data="search_domains"), InlineKeyboardButton(t('buttons.my_domains', user_lang), callback_data="my_domains")],
            [InlineKeyboardButton(t('buttons.wallet', user_lang), callback_data="wallet_main"), InlineKeyboardButton(t('buttons.hosting', user_lang), callback_data="hosting_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        query = update.callback_query
        if query:
            # Try to edit first, with timeout
            try:
                await asyncio.wait_for(
                    safe_edit_message(query, error_message, reply_markup),
                    timeout=10.0
                )
            except:
                # If edit fails, send new message
                await asyncio.wait_for(
                    context.bot.send_message(
                        chat_id=user.id,
                        text=error_message,
                        reply_markup=reply_markup
                    ),
                    timeout=10.0
                )
        else:
            # Send direct message with timeout
            await asyncio.wait_for(
                context.bot.send_message(
                    chat_id=user.id,
                    text=error_message,
                    reply_markup=reply_markup
                ),
                timeout=10.0
            )
        
        logger.info(f"✅ PRODUCTION: Emergency dashboard fallback successful for user {user.id}")
        
    except Exception as fallback_error:
        logger.error(f"❌ CRITICAL: Emergency dashboard fallback failed for user {user.id}: {fallback_error}")
        # Last resort - try to send just a simple text message
        try:
            user_lang = await resolve_user_language(user.id, user.language_code)
            await asyncio.wait_for(
                context.bot.send_message(
                    chat_id=user.id,
                    text=t_fmt('dashboard.title', user_lang) + " " + t('errors.general', user_lang)
                ),
                timeout=5.0
            )
        except Exception as final_error:
            logger.error(f"❌ CRITICAL: Final emergency message failed for user {user.id}: {final_error}")

async def domain_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /domain command - show user's domains"""
    user = update.effective_user
    
    if not user:
        logger.error("Missing user in domain command")
        return
    
    try:
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get user's domains
        domains = await get_user_domains(db_user['id'])
        
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        if not domains:
            message = t('dashboard.no_domains', user_lang)
            keyboard = [
                [InlineKeyboardButton(t('buttons.search_domains', user_lang), callback_data="search_domains")],
                [InlineKeyboardButton(t('buttons.back', user_lang), callback_data="main_menu")]
            ]
        else:
            message = t('dashboard.domains_list', user_lang) + f" ({len(domains)} total)\n\n"
            keyboard = []
            
            for domain in domains[:10]:  # Show max 10 domains
                domain_name = domain['domain_name']
                status = domain.get('status', 'unknown')
                
                # Add status indicator
                if status == 'active':
                    indicator = "🟢"
                elif status == 'pending':
                    indicator = "🟡"
                else:
                    indicator = "🔴"
                
                message += f"{indicator} <code>{domain_name}</code> - {status.title()}\n"
                keyboard.append([InlineKeyboardButton(t('buttons.manage', user_lang, name=domain_name), callback_data=f"domain_manage_{domain['id']}")])
            
            if len(domains) > 10:
                message += "\n" + t('dashboard.more_domains', user_lang, count=len(domains) - 10)
            
            keyboard.append([InlineKeyboardButton(t('buttons.register_new_domain', user_lang), callback_data="search_domains")])
            keyboard.append([InlineKeyboardButton(t('buttons.back', user_lang), callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        effective_message = update.effective_message
        if effective_message:
            await effective_message.reply_text(message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error in domain command: {e}")
        effective_message = update.effective_message
        if effective_message:
            user_lang = await resolve_user_language(user.id, user.language_code)
            await effective_message.reply_text(t('errors.general', user_lang))

async def dns_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /dns command"""
    effective_message = update.effective_message
    if not effective_message:
        logger.error("Missing message in dns command")
        return
    
    user = update.effective_user
    if not user:
        logger.error("Missing user in dns_command")
        return
    user_lang = await resolve_user_language(user.id, user.language_code)
        
    message_text = get_dns_management_intro()
    keyboard = [
        [InlineKeyboardButton(t('buttons.my_domains', user_lang), callback_data="my_domains")],
        [InlineKeyboardButton(t('buttons.back', user_lang), callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await effective_message.reply_text(message_text, reply_markup=reply_markup)

async def wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /wallet command"""
    await show_wallet_interface_message(update)

async def show_wallet_interface_message(update: Update):
    """Show wallet interface for direct message"""
    user = update.effective_user
    effective_message = update.effective_message
    
    if not user or not effective_message:
        logger.error("Missing user or message in wallet interface")
        return
    
    try:
        user_record = await get_or_create_user(user.id)
        balance = await get_user_wallet_balance(user.id)
        
        # Get recent transactions
        transactions = await get_user_wallet_transactions(user_record['id'], 5)
        
        # Format transaction history
        transaction_history = ""
        if transactions:
            for tx in transactions[:3]:  # Only show 3 recent
                amount = float(tx['amount'])
                date = tx['created_at'].strftime('%m/%d')
                emoji = "➕" if amount > 0 else "➖"
                tx_type = tx['transaction_type'] or 'transaction'
                
                # Extract simple type from verbose descriptions
                if 'domain' in tx_type.lower():
                    simple_type = 'Domain'
                elif 'deposit' in tx_type.lower() or 'crypto' in tx_type.lower():
                    simple_type = 'Deposit'
                elif 'credit' in tx_type.lower():
                    simple_type = 'Credit'
                elif 'refund' in tx_type.lower():
                    simple_type = 'Refund'
                else:
                    simple_type = tx_type.title()[:8]  # Truncate to 8 chars max
                
                transaction_history += f"{emoji} {format_money(abs(amount), 'USD', include_currency=True)} - {simple_type} ({date})\n"
        else:
            transaction_history = "\nNo transactions yet"
        
        # Get brand config for dynamic support contact
        config = BrandConfig()
        
        message = f"""
💰 Wallet

Balance: {format_money(balance, 'USD', include_currency=True)}
{transaction_history}

Need help with payments? Contact {config.support_contact}"""
        
        keyboard = [
            [InlineKeyboardButton("💳 Add Funds", callback_data="wallet_deposit")],
            [InlineKeyboardButton("📊 Transaction History", callback_data="wallet_history")],
            [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await effective_message.reply_text(message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing wallet interface: {e}")
        if effective_message:
            await effective_message.reply_text("❌ Error\n\nCould not load wallet information.")

async def credit_wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to credit wallet balance with enhanced security validation"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in credit wallet command")
        return
    
    # SECURITY: Multi-layer admin validation
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit():
        user_lang = await resolve_user_language(user.id, user.language_code)
        await message.reply_text(t('admin.broadcast_disabled', user_lang))
        logger.warning(f"🚫 ADMIN COMMAND: Attempted use of disabled credit_wallet command by user {user.id}")
        return
    
    if user.id != int(admin_user_id):
        await message.reply_text("🚫 Access Denied\n\nUnauthorized access attempt logged.")
        logger.error(f"🚫 SECURITY BREACH: Unauthorized credit_wallet command attempt by user {user.id} (admin ID: {admin_user_id})")
        return
    
    try:
        if not context.args or len(context.args) < 2:
            await message.reply_text(
                "📋 Usage: <code>/credit_wallet &lt;user_id&gt; &lt;amount&gt;</code>"
            )
            return
        
        # Enhanced input validation
        try:
            target_user_id = int(context.args[0])
            amount = float(context.args[1])
        except (ValueError, IndexError) as ve:
            await message.reply_text(
                "❌ Invalid Input\n\n"
                "User ID must be a number and amount must be a valid decimal."
            )
            logger.warning(f"🚫 ADMIN VALIDATION: Invalid input in credit_wallet by admin {user.id}: {context.args}")
            return
        
        # CRITICAL: Administrative safety bounds
        if amount <= 0:
            await message.reply_text("❌ Invalid Amount\n\nAmount must be positive.")
            logger.warning(f"🚫 ADMIN VALIDATION: Non-positive amount attempted by admin {user.id}: {amount}")
            return
        
        if amount > 10000.00:  # $10,000 limit for safety
            await message.reply_text(
                "🚫 Amount Too Large\n\n"
                "Maximum credit amount is $10,000.00 per operation.\n"
                "For larger amounts, use multiple operations."
            )
            logger.error(f"🚫 ADMIN VALIDATION: Excessive amount attempted by admin {user.id}: ${amount}")
            return
        
        # Get and validate target user
        user_record = await get_or_create_user(target_user_id)
        if not user_record:
            await message.reply_text("❌ User Not Found\n\nCould not find or create user record.")
            logger.error(f"🚫 ADMIN ERROR: Failed to get user record for {target_user_id}")
            return
        
        # Check current balance to prevent excessive accumulation
        current_balance = await get_user_wallet_balance(target_user_id)
        if current_balance + amount > 50000.00:  # $50,000 total balance limit
            await message.reply_text(
                f"🚫 Balance Limit Exceeded\n\n"
                f"Current Balance: {format_money(current_balance, 'USD', include_currency=True)}\n"
                f"Requested Credit: {format_money(amount, 'USD', include_currency=True)}\n"
                f"Would Result In: {format_money(current_balance + amount, 'USD', include_currency=True)}\n\n"
                f"Maximum wallet balance is $50,000.00"
            )
            logger.warning(f"🚫 ADMIN VALIDATION: Credit would exceed balance limit for user {target_user_id}: ${current_balance + amount}")
            return
        
        # Perform atomic credit operation
        await message.reply_text("💳 Processing Admin Credit...")
        
        # Use unified credit function with admin defaults
        success = await credit_user_wallet(
            user_id=user_record['id'],
            amount_usd=amount,
            provider="admin",
            txid=f"admin_{int(time.time())}_{user.id}",
            order_id=f"admin_credit_{int(time.time())}"
        )
        
        if success:
            new_balance = await get_user_wallet_balance(target_user_id)
            await message.reply_text(
                f"✅ Wallet Credited Successfully\n\n"
                f"👤 Target User ID: {target_user_id}\n"
                f"💰 Amount Credited: {format_money(amount, 'USD', include_currency=True)}\n"
                f"📊 Previous Balance: {format_money(current_balance, 'USD', include_currency=True)}\n"
                f"🔄 New Balance: {format_money(new_balance, 'USD', include_currency=True)}\n\n"
                f"🔒 Admin: {user.id}\n"
                f"🕐 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )
            logger.info(f"✅ ADMIN CREDIT: ${amount:.2f} credited to user {target_user_id} by admin {user.id}. New balance: ${new_balance:.2f}")
        else:
            await message.reply_text(
                "❌ Credit Failed\n\n"
                "Could not credit wallet. Check logs for details."
            )
            logger.error(f"🚫 ADMIN ERROR: Failed to credit ${amount:.2f} to user {target_user_id} by admin {user.id}")
            
    except Exception as e:
        logger.error(f"🚫 ADMIN ERROR: Exception in credit_wallet_command by admin {user.id}: {e}")
        await message.reply_text(
            "❌ System Error\n\n"
            "An unexpected error occurred. Please check the command format and try again."
        )

async def send_broadcast(broadcast_message: str, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Shared broadcast helper function with batching and retry logic.
    Used by both /broadcast command and button interface.
    """
    import asyncio
    from database import get_all_user_telegram_ids
    
    user = update.effective_user
    
    # Validate message
    if len(broadcast_message.strip()) == 0:
        return {
            'success': False,
            'error': "Empty message",
            'message': "❌ Empty Message\n\nPlease provide a message to broadcast."
        }
    
    if len(broadcast_message) > 4096:  # Telegram message limit
        return {
            'success': False,
            'error': "Message too long",
            'message': "❌ Message Too Long\n\nMessage must be under 4096 characters."
        }
    
    # Get all user telegram IDs
    user_ids = await get_all_user_telegram_ids()
    
    if not user_ids:
        return {
            'success': False,
            'error': "No users found",
            'message': "⚠️ No Users Found\n\nNo users available for broadcasting."
        }
    
    total_users = len(user_ids)
    batch_size = 30
    delay_between_batches = 1  # seconds
    max_retries = 3
    
    # Determine if we should send or edit message
    if hasattr(update, 'message') and update.message:
        # From command - reply to the message
        status_msg = await update.message.reply_text(
            f"📢 Broadcasting Started\n\n"
            f"👥 Target Users: {total_users}\n"
            f"📦 Batch Size: {batch_size}\n"
            f"⏱️ Delay: {delay_between_batches}s between batches\n"
            f"🔄 Max Retries: {max_retries}\n\n"
            f"Message:\n{broadcast_message[:200]}{'...' if len(broadcast_message) > 200 else ''}"
        )
    else:
        # From button interface - send new message
        if not user:
            return {
                'success': False,
                'error': "User not found",
                'message': "❌ Error\n\nUser information not available."
            }
        
        status_msg = await context.bot.send_message(
            chat_id=user.id,
            text=f"📢 Broadcasting Started\n\n"
            f"👥 Target Users: {total_users}\n"
            f"📦 Batch Size: {batch_size}\n"
            f"⏱️ Delay: {delay_between_batches}s between batches\n"
            f"🔄 Max Retries: {max_retries}\n\n"
            f"Message:\n{broadcast_message[:200]}{'...' if len(broadcast_message) > 200 else ''}"
        )
    
    # Process in batches
    total_sent = 0
    total_failed = 0
    batch_number = 0
    
    for i in range(0, total_users, batch_size):
        batch_number += 1
        batch_users = user_ids[i:i + batch_size]
        batch_sent = 0
        batch_failed = 0
        
        logger.info(f"📢 BROADCAST: Processing batch {batch_number} with {len(batch_users)} users")
        
        # Send to each user in batch with retry logic
        for user_telegram_id in batch_users:
            retry_count = 0
            sent_successfully = False
            
            while retry_count < max_retries and not sent_successfully:
                try:
                    await context.bot.send_message(
                        chat_id=user_telegram_id,
                        text=broadcast_message
                    )
                    batch_sent += 1
                    sent_successfully = True
                    logger.debug(f"📢 BROADCAST: Message sent to user {user_telegram_id}")
                    
                except Exception as e:
                    retry_count += 1
                    logger.warning(f"📢 BROADCAST: Failed to send to user {user_telegram_id} (attempt {retry_count}/{max_retries}): {e}")
                    
                    if retry_count < max_retries:
                        await asyncio.sleep(0.1)  # Brief pause before retry
            
            if not sent_successfully:
                batch_failed += 1
                logger.error(f"📢 BROADCAST: Failed to send to user {user_telegram_id} after {max_retries} attempts")
        
        total_sent += batch_sent
        total_failed += batch_failed
        
        # Update status
        progress = f"📊 Batch {batch_number} Complete\n"
        progress += f"✅ Sent: {batch_sent}/{len(batch_users)}\n"
        progress += f"❌ Failed: {batch_failed}\n"
        progress += f"📈 Total Progress: {total_sent}/{total_users}"
        
        try:
            await status_msg.edit_text(
                f"📢 Broadcasting in Progress...\n\n"
                f"👥 Target Users: {total_users}\n"
                f"📦 Current Batch: {batch_number}\n\n"
                f"{progress}"
            )
        except Exception:
            pass  # Ignore edit failures
        
        # Delay between batches (except for last batch)
        if i + batch_size < total_users:
            logger.info(f"📢 BROADCAST: Waiting {delay_between_batches}s before next batch...")
            await asyncio.sleep(delay_between_batches)
    
    # Final status
    success_rate = (total_sent / total_users * 100) if total_users > 0 else 0
    final_message = f"🎯 Broadcast Complete!\n\n"
    final_message += f"✅ Successfully Sent: {total_sent}\n"
    final_message += f"❌ Failed: {total_failed}\n"
    final_message += f"📊 Success Rate: {success_rate:.1f}%\n"
    final_message += f"📦 Total Batches: {batch_number}\n\n"
    final_message += f"Message: {broadcast_message[:150]}{'...' if len(broadcast_message) > 150 else ''}"
    
    await status_msg.edit_text(final_message)
    
    logger.info(f"✅ BROADCAST COMPLETE: Admin {user.id if user else 'unknown'} sent message to {total_sent}/{total_users} users ({success_rate:.1f}% success)")
    
    return {
        'success': True,
        'total_sent': total_sent,
        'total_failed': total_failed,
        'success_rate': success_rate
    }

async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to broadcast message to all users with batching and retry logic"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in broadcast command")
        return
    
    # SECURITY: Multi-layer admin validation
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit():
        user_lang = await resolve_user_language(user.id, user.language_code)
        await message.reply_text(t('admin.broadcast_disabled', user_lang))
        logger.warning(f"🚫 ADMIN COMMAND: Attempted use of disabled broadcast command by user {user.id}")
        return
    
    if user.id != int(admin_user_id):
        await message.reply_text("🚫 Access Denied\n\nUnauthorized access attempt logged.")
        logger.error(f"🚫 SECURITY BREACH: Unauthorized broadcast command attempt by user {user.id} (admin ID: {admin_user_id})")
        return
    
    try:
        if not context.args:
            await message.reply_text(
                "📢 Usage: /broadcast <message>"
            )
            return
        
        # Get broadcast message
        broadcast_message = ' '.join(context.args)
        
        # Use shared broadcast function
        result = await send_broadcast(broadcast_message, update, context)
        
        if not result['success']:
            await message.reply_text(result['message'])
        
    except Exception as e:
        logger.error(f"🚫 ADMIN ERROR: Exception in broadcast_command by admin {user.id}: {e}")
        await message.reply_text(
            "❌ Broadcast Failed\n\nCritical error occurred. Check logs for details."
        )

async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cancel command to exit broadcast mode"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in cancel command")
        return
    
    try:
        # Check if user is admin
        admin_user_id = os.getenv('ADMIN_USER_ID')
        if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
            await message.reply_text(
                "🚫 Access Denied\n\nOnly admin can use this command."
            )
            logger.warning(f"🚫 SECURITY: Non-admin user {user.id} attempted to use /cancel command")
            return
        
        # Check if awaiting broadcast
        if context.user_data and context.user_data.get('awaiting_broadcast'):
            # Clear broadcast flag
            del context.user_data['awaiting_broadcast']
            
            await message.reply_text(
                "🚫 Broadcast Cancelled\n\nBroadcast mode deactivated.\n\nYou can start a new broadcast anytime from the admin panel."
            )
            logger.info(f"📢 ADMIN: User {user.id} cancelled broadcast mode via /cancel command")
        else:
            await message.reply_text(
                "ℹ️ No Active Operation\n\nThere is no active operation to cancel."
            )
            logger.info(f"📢 ADMIN: User {user.id} used /cancel but no active broadcast mode")
            
    except Exception as e:
        logger.error(f"Error in cancel_command: {e}")
        await message.reply_text(
            "❌ Error\n\nCould not process cancel command."
        )

# Admin credit text handling moved to admin_handlers.py to avoid conflicts

# Duplicate admin helper functions removed - consolidated in admin_handlers.py


async def handle_admin_broadcast_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    High-priority text handler for admin broadcast messages.
    Only processes messages when admin is in broadcast mode.
    """
    user = update.effective_user
    message = update.effective_message
    
    logger.info(f"🔍 BROADCAST HANDLER: Called for user {user.id if user else 'None'}")
    
    if not user or not message or not message.text:
        logger.info(f"🔍 BROADCAST HANDLER: Missing data - user: {user is not None}, message: {message is not None}")
        return False  # Let other handlers process this
    
    # Check if user is admin
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        logger.info(f"🔍 BROADCAST HANDLER: Not admin - user {user.id} vs admin {admin_user_id}")
        return False  # Not admin - let other handlers process
    
    logger.info(f"🔍 BROADCAST HANDLER: Admin confirmed - checking states")
    logger.info(f"🔍 BROADCAST HANDLER: context.user_data = {context.user_data}")
    
    # CRITICAL FIX: Check if user is in credit mode first - yield to credit handler
    if context.user_data and context.user_data.get('admin_credit_state'):
        logger.info(f"🔍 BROADCAST HANDLER: User in credit mode - yielding to credit handler")
        return False  # User is in credit mode - let credit handler process this
    
    # Check if awaiting broadcast
    if not context.user_data or not context.user_data.get('awaiting_broadcast'):
        return False  # Not in broadcast mode - let other handlers process
    
    try:
        # Handle /cancel command to exit broadcast mode
        if message.text.strip().lower() in ['/cancel', 'cancel']:
            # Clear broadcast flag
            if context.user_data and 'awaiting_broadcast' in context.user_data:
                del context.user_data['awaiting_broadcast']
            
            await message.reply_text(
                "🚫 Broadcast Cancelled\n\nBroadcast mode deactivated."
            )
            logger.info(f"📢 ADMIN: User {user.id} cancelled broadcast via /cancel")
            return True  # Message handled
        
        broadcast_message = message.text.strip()
        
        # Clear broadcast flag first
        if context.user_data and 'awaiting_broadcast' in context.user_data:
            del context.user_data['awaiting_broadcast']
        
        # Use shared broadcast function  
        result = await send_broadcast(broadcast_message, update, context)
        
        if not result['success']:
            await message.reply_text(result['message'])
        
        logger.info(f"📢 ADMIN TEXT: User {user.id} sent broadcast via text input: '{broadcast_message[:50]}{'...' if len(broadcast_message) > 50 else ''}'")
        return True  # Message handled
        
    except Exception as e:
        logger.error(f"Error in handle_admin_broadcast_text: {e}")
        # Clear broadcast flag on error
        if context.user_data and 'awaiting_broadcast' in context.user_data:
            del context.user_data['awaiting_broadcast']
        
        await message.reply_text(
            "❌ Broadcast Failed\n\nAn error occurred. Broadcast mode deactivated."
        )
        return True  # Message handled

async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /search command"""
    message = update.effective_message
    if not message:
        logger.error("Missing message in search command")
        return
        
    args = context.args
    
    if not args:
        user = update.effective_user
        if not user:
            logger.error("Missing user in search_command")
            return
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        help_text = t('search.help_title', user_lang) + "\n\n"
        help_text += t('search.help_description', user_lang) + "\n\n"
        help_text += t('search.help_usage', user_lang) + "\n\n"
        help_text += t('search.help_note', user_lang)
        
        keyboard = [
            [InlineKeyboardButton(t('buttons.back', user_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await message.reply_text(help_text, reply_markup=reply_markup)
        return
    
    domain_name = ' '.join(args).lower().strip()
    
    # Validate domain before calling OpenProvider
    if not is_valid_domain(domain_name):
        await message.reply_text(
            f"❌ Invalid domain: {domain_name}"
        )
        return
        
    searching_msg = await message.reply_text(f"🔄 Searching {domain_name}...")
    
    # Perform actual domain search
    try:
        availability = await openprovider.check_domain_availability(domain_name)
        
        if availability is None:
            # API error or no response - provide helpful fallback
            response_text = f"""
⚠️ Search Unavailable: {domain_name}

Service temporarily down. Try again in a few minutes.
"""
            keyboard = [
                [InlineKeyboardButton("🔄 Try Again", callback_data="search_domains")],
                [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
            ]
        elif availability.get('available'):
            # Domain is available - extract marked-up pricing
            price_info = availability.get('price_info', {})
            create_price = price_info.get('create_price', 0)
            currency = price_info.get('currency', 'USD')  # Now returns USD from markup system
            is_premium = availability.get('premium', False)
            
            # Format pricing display (price is already marked-up and in USD)
            if create_price > 0:
                price_display = f"{format_money(create_price, currency, include_currency=True)}/year"
                
                # Add markup indicator if markup was applied
                pricing_breakdown = price_info.get('pricing_breakdown', {})
                if pricing_breakdown.get('markup_applied', False):
                    base_price = pricing_breakdown.get('base_price_usd', 0)
                    markup = pricing_breakdown.get('actual_markup', 0)
                    if markup > 0:
                        price_display += f" (includes {format_money(markup, currency, include_currency=True)} service fee)"
            else:
                price_display = "Contact for pricing"
            
            response_text = f"""
✅ {domain_name} Available

{'Premium' if is_premium else 'Standard'} domain
{price_display}
"""
            keyboard = [
                [InlineKeyboardButton(f"🛒 Register {domain_name}", callback_data=f"register_{domain_name}")],
                [InlineKeyboardButton("🔍 Search Another", callback_data="search_domains")],
                [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
            ]
        else:
            # Domain is not available
            response_text = f"""
❌ {domain_name} Unavailable

Already registered. Try .net, .org, or .io
"""
            keyboard = [
                [InlineKeyboardButton("🔍 Search Another", callback_data="search_domains")],
                [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        if searching_msg:
            await searching_msg.edit_text(response_text, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error searching domain {domain_name}: {e}")
        if searching_msg:
            await searching_msg.edit_text("❌ Error searching domain. Please try again.")

async def profile_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /profile command with localization and community engagement"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in profile command")
        return
    
    try:
        # Get user language for localized response
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Get user data for wallet balance and terms status
        user_data = await get_or_create_user(user.id, user.username, user.first_name, user.language_code)
        wallet_balance = await get_user_wallet_balance(user.id)
        has_accepted_terms = await has_user_accepted_terms(user.id)
        
        # Build profile information using localized strings
        username_display = f"@{user.username}" if user.username else "Not set"
        full_name = f"{user.first_name or ''} {user.last_name or ''}".strip() or "Not set"
        
        # Get brand configuration for community engagement
        config = BrandConfig()
        
        # Build profile sections
        profile_parts = []
        
        # Profile title
        title_text, _ = t_html('profile.title', user_lang)
        profile_parts.append(title_text)
        profile_parts.append("")
        
        # Telegram details section
        telegram_details, _ = t_html('profile.telegram_details', user_lang)
        profile_parts.append(telegram_details)
        
        username_text, _ = t_html('profile.username', user_lang, username=user.username or "Not set")
        profile_parts.append(username_text)
        
        name_text, _ = t_html('profile.name', user_lang, name=full_name)
        profile_parts.append(name_text)
        
        user_id_text, _ = t_html('profile.user_id', user_lang, user_id=user.id)
        profile_parts.append(user_id_text)
        profile_parts.append("")
        
        # Account status section
        account_status_text, _ = t_html('profile.account_status', user_lang)
        profile_parts.append(account_status_text)
        
        wallet_text, _ = t_html('profile.wallet_balance', user_lang, balance=format_money(wallet_balance))
        profile_parts.append(wallet_text)
        
        terms_status = "✅" if has_accepted_terms else "⏳"
        terms_text, _ = t_html('profile.terms_status', user_lang, status=terms_status)
        profile_parts.append(terms_text)
        profile_parts.append("")
        
        # Available features section
        features_text, _ = t_html('profile.features', user_lang)
        profile_parts.append(features_text)
        
        feature_domains, _ = t_html('profile.feature_domains', user_lang)
        profile_parts.append(feature_domains)
        
        feature_dns, _ = t_html('profile.feature_dns', user_lang)
        profile_parts.append(feature_dns)
        
        feature_hosting, _ = t_html('profile.feature_hosting', user_lang)
        profile_parts.append(feature_hosting)
        
        feature_crypto, _ = t_html('profile.feature_crypto', user_lang)
        profile_parts.append(feature_crypto)
        profile_parts.append("")
        
        # Community engagement section with configurable branding
        community_engagement, _ = t_html('profile.community_engagement', user_lang, 
                                        hostbay_channel=config.hostbay_channel,
                                        hostbay_email=config.hostbay_email,
                                        support_contact=config.support_contact)
        profile_parts.append(community_engagement)
        
        # Join all parts into final profile info
        profile_info = "\n".join(profile_parts)
        
        # Create keyboard with localized back button
        keyboard = [
            [InlineKeyboardButton(t('buttons.back', user_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await message.reply_text(profile_info, reply_markup=reply_markup, parse_mode=ParseMode.HTML)
        logger.info(f"✅ Profile command completed for user {user.id} in language {user_lang}")
        
    except Exception as e:
        logger.error(f"Error in profile command for user {user.id}: {e}")
        # Fallback error message
        error_msg = "❌ Error loading profile. Please try again."
        keyboard = [
            [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await message.reply_text(error_msg, reply_markup=reply_markup)

async def hosting_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /hosting command"""
    effective_message = update.effective_message
    if not effective_message:
        logger.error("Missing message in hosting command")
        return
        
    message_text = """
🏠 Hosting

Choose a plan:
"""
    keyboard = [
        [InlineKeyboardButton("📋 Plans", callback_data="hosting_plans")],
        [InlineKeyboardButton("🏠 My Hosting", callback_data="my_hosting")],
        [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await effective_message.reply_text(message_text, reply_markup=reply_markup)

async def language_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /language command - show language selection interface"""
    user = update.effective_user
    effective_message = update.effective_message
    
    if not user or not effective_message:
        logger.error("Missing user or message in language command")
        return
    
    try:
        # Get current user language for the interface message
        current_lang = await resolve_user_language(user.id, user.language_code)
        
        # Show language selection interface
        await show_language_selection(effective_message, user.id, current_lang)
        logger.info(f"✅ Language selection shown to user {user.id}")
        
    except Exception as e:
        logger.error(f"Error in language command for user {user.id}: {e}")
        
        # Fallback message in English
        await effective_message.reply_text(
            "❌ Error loading language settings. Please try again.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔄 Try Again", callback_data="language_selection")
            ]])
        )

async def show_language_selection(message_obj, user_id: int, current_lang: str = 'en'):
    """Show language selection interface with flag emojis and native names"""
    try:
        # Get localized message for current language
        message_text = await t_for_user(
            'language.select',
            user_id,
            platform_name=get_platform_name()
        )
        
        # Fallback if translation key doesn't exist
        if 'language.select' in message_text:
            message_text = "🌍 Language Selection\n\nChoose your preferred language:"
        
        # Create keyboard with language options using flags and native names
        supported_languages = get_supported_languages()
        
        # Map language codes to flag emojis and display names
        language_options = {
            'en': {'flag': '🇺🇸', 'name': 'English'},
            'fr': {'flag': '🇫🇷', 'name': 'Français'},
            'es': {'flag': '🇪🇸', 'name': 'Español'}
        }
        
        keyboard = []
        for lang_code, lang_display in supported_languages.items():
            if lang_code in language_options:
                flag = language_options[lang_code]['flag']
                name = language_options[lang_code]['name']
                
                # Add checkmark for current language
                display_text = f"{flag} {name}"
                if lang_code == current_lang:
                    display_text += " ✓"
                
                keyboard.append([InlineKeyboardButton(
                    display_text,
                    callback_data=f"language_select_{lang_code}"
                )])
        
        # Add back button
        back_text = await t_for_user('navigation.back', user_id)
        if 'navigation.back' in back_text:
            back_text = "⬅️ Back"
            
        keyboard.append([InlineKeyboardButton(back_text, callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send or edit message depending on message type
        if hasattr(message_obj, 'reply_text'):
            await message_obj.reply_text(message_text, reply_markup=reply_markup)
        else:
            await safe_edit_message(message_obj, message_text, reply_markup=reply_markup)
            
    except Exception as e:
        logger.error(f"Error showing language selection: {e}")
        
        # Ultra-simple fallback
        fallback_keyboard = [
            [InlineKeyboardButton("🇺🇸 English", callback_data="language_select_en")],
            [InlineKeyboardButton("🇫🇷 Français", callback_data="language_select_fr")],
            [InlineKeyboardButton("🇪🇸 Español", callback_data="language_select_es")],
            [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(fallback_keyboard)
        
        if hasattr(message_obj, 'reply_text'):
            await message_obj.reply_text(
                "🌍 Select your language:",
                reply_markup=reply_markup
            )
        else:
            await safe_edit_message(message_obj, "🌍 Select your language:", reply_markup=reply_markup)

async def handle_language_selection(query, lang_code: str):
    """Handle language selection callback and update user preference"""
    user = query.from_user
    if not user:
        logger.error("Missing user in language selection")
        return
    
    try:
        # Validate language code
        if not is_language_supported(lang_code):
            await safe_edit_message(
                query,
                "❌ Unsupported language. Please try again.",
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("🔄 Try Again", callback_data="language_selection")
                ]])
            )
            return
        
        # Update user language preference in database
        success = await set_user_language_preference(user.id, lang_code)
        
        if success:
            # Get language names for confirmation
            language_names = {
                'en': 'English',
                'fr': 'Français', 
                'es': 'Español'
            }
            selected_language = language_names.get(lang_code, lang_code)
            
            # Show confirmation message in newly selected language
            confirmation_text = await t_for_user(
                'success.language_changed',
                user.id,
                explicit_lang_code=lang_code,  # Force use new language immediately
                language=selected_language
            )
            
            # Fallback confirmation if translation not found
            if 'language_changed' in confirmation_text:
                confirmation_text = f"✅ Language changed to {selected_language}"
            
            # Create menu to return to main interface  
            keyboard = [
                [InlineKeyboardButton(
                    await t_for_user('buttons.main_menu', user.id, explicit_lang_code=lang_code) or "🏠 Main Menu",
                    callback_data="main_menu"
                )],
                [InlineKeyboardButton(
                    await t_for_user('commands.language', user.id, explicit_lang_code=lang_code) or "🌍 Change Language",
                    callback_data="language_selection"
                )]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await safe_edit_message(query, confirmation_text, reply_markup=reply_markup)
            logger.info(f"✅ Language updated to {lang_code} for user {user.id}")
            
        else:
            # Database update failed
            error_text = "❌ Failed to update language preference. Please try again."
            await safe_edit_message(
                query,
                error_text,
                reply_markup=InlineKeyboardMarkup([[
                    InlineKeyboardButton("🔄 Try Again", callback_data="language_selection")
                ]])
            )
            logger.error(f"❌ Failed to update language preference for user {user.id} to {lang_code}")
            
    except Exception as e:
        logger.error(f"Error handling language selection for user {user.id}: {e}")
        await safe_edit_message(
            query,
            "❌ An error occurred. Please try again.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔄 Try Again", callback_data="language_selection")
            ]])
        )

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle all inline keyboard callback queries"""
    query = update.callback_query
    if not query:
        logger.error("Missing callback query in handle_callback")
        return
    
    # Enhanced logging for debugging user interactions
    user = query.from_user
    logger.info(f"Callback received from user {user.id if user else 'unknown'}: {query.data}")
    
    # Answer callback query with error handling for expired queries
    try:
        await query.answer()
    except Exception as e:
        # Silently handle expired/old callback queries (common after bot restart)
        if "too old" in str(e).lower() or "timeout" in str(e).lower() or "invalid" in str(e).lower():
            logger.debug(f"Handled expired callback query: {e}")
        else:
            logger.warning(f"Callback answer error: {e}")
        # Continue processing the callback even if answer fails
    
    # Decompress callback data if it's compressed
    data = await decompress_callback(query.data, context)
    
    # Log callback resolution if needed
    if query.data != data or data.startswith("error:"):
        logger.info(f"Callback data resolved: {query.data} -> {data}")
    
    try:
        # Terms acceptance callbacks
        if data.startswith("terms:") or data in ["accept_terms", "decline_terms", "full_terms"]:
            logger.info(f"Routing to: handle_terms_callback")
            await handle_terms_callback(update, context)
        elif data == "main_menu":
            logger.info(f"Routing to: show_main_menu")
            await show_main_menu(query)
        elif data == "search_domains":
            logger.info(f"Routing to: show_search_interface")
            await show_search_interface(query)
        elif data == "my_domains":
            logger.info(f"Routing to: show_user_domains_complete")
            await show_user_domains_complete(query)
        elif data == "wallet_main":
            logger.info(f"Routing to: show_wallet_interface")
            await show_wallet_interface(query)
        elif data == "profile_main":
            logger.info(f"Routing to: show_profile_interface")
            await show_profile_interface(query)
        elif data == "contact_support":
            logger.info(f"Routing to: show_contact_support")
            await show_contact_support(query)
        elif data == "language_selection":
            logger.info(f"Routing to: show_language_selection")
            user = query.from_user
            if user:
                current_lang = await resolve_user_language(user.id, user.language_code)
                await show_language_selection(query, user.id, current_lang)
            else:
                await safe_edit_message(query, "❌ Error: Unable to determine user language preference.")
        elif data.startswith("language_select_"):
            # Handle language selection: language_select_{lang_code}
            lang_code = data.replace("language_select_", "")
            logger.info(f"Routing to: handle_language_selection for {lang_code}")
            await handle_language_selection(query, lang_code)
        elif data == "domain_hosting_bundle":
            await show_domain_hosting_bundle(query)
        elif data == "bundle_how_it_works":
            await show_bundle_how_it_works(query)
        elif data.startswith("bundle_plan_"):
            plan_id = data.replace("bundle_plan_", "")
            await start_bundle_domain_search(query, context, plan_id)
        elif data.startswith("confirm_bundle_"):
            # Parse: confirm_bundle_{plan_id}_{domain_name}
            parts = data.replace("confirm_bundle_", "").split("_", 1)
            if len(parts) >= 2:
                plan_id = parts[0]
                domain_name = parts[1]
                await confirm_bundle_purchase(query, plan_id, domain_name)
        elif data == "admin_broadcast":
            logger.info(f"Routing to: handle_admin_broadcast")
            await handle_admin_broadcast(query, context)
        elif data == "admin_credit_wallet":
            logger.info(f"Routing to: handle_admin_credit_wallet")
            await handle_admin_credit_wallet(update, context)
        elif data.startswith("admin_execute_credit:"):
            # Handle admin credit execution: admin_execute_credit:{user_id}:{amount}
            parts = data.split(":")
            if len(parts) >= 3:
                target_user_id = int(parts[1])
                amount = float(parts[2])
                await execute_admin_credit(query, target_user_id, amount)
        elif data == "cancel_broadcast":
            logger.info(f"Routing to: handle_cancel_broadcast")
            await handle_cancel_broadcast(query, context)
        elif data.startswith("register_"):
            domain_name = data.replace("register_", "")
            # Check if user is in unified hosting flow context
            if hasattr(context, 'user_data') and context.user_data:
                unified_flow = context.user_data.get('unified_flow')
                plan_id = context.user_data.get('unified_plan_id')
                if unified_flow == 'awaiting_new_domain' and plan_id:
                    # Route to hosting+domain bundle flow
                    logger.info(f"🔄 Redirecting register_{domain_name} to unified hosting bundle for plan {plan_id}")
                    await unified_checkout(query, 'new', plan_id, domain_name)
                    return
            # Default to domain-only registration
            await start_domain_registration(query, domain_name)
        elif data.startswith("pay_hosting_"):
            # Handle hosting payment selection: pay_hosting_{method}_{subscription_id}_{price}
            parts = data.split("_", 4)
            if len(parts) >= 5:
                payment_method = parts[2]  # wallet, btc, ltc, etc.
                subscription_id = parts[3]
                price = parts[4]
                
                if payment_method == "wallet":
                    await process_hosting_wallet_payment(query, subscription_id, price)
                else:
                    await process_hosting_crypto_payment(query, payment_method, subscription_id, price)
        elif data.startswith("pay_"):
            # Handle domain payment selection: pay_{method}_{domain}_{price}_{currency}
            parts = data.split("_", 4)
            if len(parts) >= 5:
                payment_method = parts[1]
                domain_name = parts[2]
                price = parts[3]
                currency = parts[4]
                
                # 🎯 INSTANT FEEDBACK: Show immediate payment processing message
                if payment_method == "wallet":
                    feedback_msg = f"💳 <b>Wallet Payment</b> • ${price}\n🌐 <code>{domain_name}</code>\n⏳ Verifying balance..."
                else:
                    crypto_name = payment_method.upper()
                    feedback_msg = f"₿ <b>Setting up {crypto_name} Payment...</b>\n\n"
                    feedback_msg += f"🌐 Domain: <code>{domain_name}</code>\n"
                    feedback_msg += f"💰 Amount: ${price}\n"
                    feedback_msg += f"⏳ Generating payment address..."
                
                await safe_edit_message(query, feedback_msg, parse_mode='HTML')
                
                if payment_method == "wallet":
                    await process_wallet_payment(query, domain_name, price, currency)
                else:
                    await process_crypto_payment(query, payment_method, domain_name, price, currency)
        # Removed manual payment checking - payments are processed automatically via webhooks
        elif data == "wallet_deposit":
            await show_wallet_deposit_options(query)
        elif data.startswith("deposit_"):
            # Handle crypto deposits dynamically: deposit_{crypto_code}
            crypto_code = data.replace("deposit_", "")
            if crypto_config.is_supported(crypto_code):
                await process_wallet_crypto_deposit(query, crypto_code)
            else:
                await safe_edit_message(query, f"❌ Unsupported cryptocurrency: {crypto_code}")
        elif data.startswith("check_wallet_deposit:"):
            # Handle wallet deposit status check: check_wallet_deposit:{order_id}
            order_id = data.replace("check_wallet_deposit:", "")
            await check_wallet_deposit_status(query, order_id)
        elif data.startswith("copy_address_"):
            # Handle copy address - provide immediate feedback
            address = data.replace("copy_address_", "")
            await handle_copy_address(query, address)
        elif data.startswith("copy_memo_"):
            # Handle copy memo - provide immediate feedback  
            memo = data.replace("copy_memo_", "")
            await handle_copy_memo(query, memo)
        # Removed copy username and copy password handlers as requested
        elif data.startswith("copy_server_"):
            # Handle copy hosting server
            server = data.replace("copy_server_", "")
            await handle_copy_hosting_credential(query, server, "Server")
        elif data.startswith("copy_url_"):
            # Handle copy hosting URL
            url = data.replace("copy_url_", "")
            await handle_copy_hosting_credential(query, url, "URL")
        elif data.startswith("show_wallet_qr:"):
            # Handle wallet QR code display: show_wallet_qr:{order_id}
            order_id = data.replace("show_wallet_qr:", "")
            await show_wallet_qr_code(query, order_id)
        elif data.startswith("cancel_wallet_deposit:"):
            # Handle wallet deposit cancellation: cancel_wallet_deposit:{order_id}
            order_id = data.replace("cancel_wallet_deposit:", "")
            await cancel_wallet_deposit(query, order_id)
        elif data.startswith("back_to_wallet_payment:"):
            # Handle return to wallet payment: back_to_wallet_payment:{order_id}
            order_id = data.replace("back_to_wallet_payment:", "")
            await back_to_wallet_payment(query, order_id)
        elif data == "wallet_deposit_from_qr":
            # Handle return to crypto selection from QR code photo
            await handle_wallet_deposit_from_qr(query)
        elif data.startswith("qr_back_to_payment:"):
            # Handle back to payment from domain QR code photo
            domain_name = data.replace("qr_back_to_payment:", "")
            await handle_qr_back_to_payment(query, domain_name)
        elif data == "qr_cancel_order":
            # Handle cancel order from domain QR code photo
            await handle_qr_cancel_order(query)
        elif data.startswith("cancel_wallet_deposit_from_qr:"):
            # Handle cancel deposit from QR code photo
            order_id = data.replace("cancel_wallet_deposit_from_qr:", "")
            await handle_cancel_wallet_deposit_from_qr(query, order_id)
        elif data.startswith("cancel_deposit:"):
            # Handle cancel deposit from QR code photo (shorter callback)
            order_id = data.replace("cancel_deposit:", "")
            await handle_cancel_wallet_deposit_from_qr(query, order_id)
        elif data == "wallet_history":
            await show_wallet_transaction_history(query)
        elif data.startswith("domain_manage_"):
            domain_id = data.replace("domain_manage_", "")
            await show_domain_management(query, domain_id)
        elif data.startswith("dns:"):
            # New standardized DNS callback routing: dns:{domain}:{action}[:type][:id][:page]
            await handle_dns_callback(query, context, data)
        elif data.startswith("del:"):
            # Shortened delete callback: del:{record_id}
            await handle_delete_callback(query, context, data)
        elif data.startswith("edit_mx_priority:"):
            # MX priority selection: edit_mx_priority:{record_id}:{priority}
            await handle_mx_priority_selection(query, context, data)
        elif data.startswith("dns_edit:"):
            # DNS edit callbacks: dns_edit:{domain}:{type}:{action}:{record_id}
            await handle_dns_edit_callback(query, context, data)
        elif data.startswith("edit_ttl:"):
            # TTL selection callbacks: edit_ttl:{record_id}:{ttl_value}
            await handle_ttl_selection(query, context, data)
        elif data.startswith("dns_wizard:"):
            # Handle DNS wizard callbacks: dns_wizard:{domain}:{type}:{field}:{value}
            logger.info(f"Routing to: handle_dns_wizard_callback")
            await handle_dns_wizard_callback(query, context, data)
        elif data.startswith("dns_") and ":" not in data:
            # Legacy DNS callback - redirect to new system (only for plain domain names)
            domain_name = data.replace("dns_", "")
            logger.info(f"Converting dns_ callback: {data} -> dns:{domain_name}:view")
            await handle_dns_callback(query, context, f"dns:{domain_name}:view")
        elif data == "hosting_main":
            await show_hosting_interface(query)
        elif data == "hosting_plans":
            # Legacy route - redirect to unified flow
            logger.info(f"Redirecting legacy hosting_plans to unified flow")
            await unified_hosting_flow(query)
        elif data == "my_hosting":
            await show_my_hosting(query)
        elif data.startswith("select_plan_"):
            # Legacy route - redirect to unified plan selection
            plan_id = data.replace("select_plan_", "")
            logger.info(f"Redirecting legacy select_plan_{plan_id} to unified flow")
            await handle_unified_plan_selection(query, context, plan_id)
        elif data.startswith("purchase_plan_"):
            # Legacy route - redirect to unified plan selection
            plan_id = data.replace("purchase_plan_", "")
            logger.info(f"Redirecting legacy purchase_plan_{plan_id} to unified flow")
            await handle_unified_plan_selection(query, context, plan_id)
        elif data.startswith("confirm_purchase_"):
            # Legacy route - redirect to unified plan selection
            plan_id = data.replace("confirm_purchase_", "")
            logger.info(f"Redirecting legacy confirm_purchase_{plan_id} to unified flow")
            await handle_unified_plan_selection(query, context, plan_id)
        # UNIFIED HOSTING FLOW CALLBACKS
        elif data == "unified_hosting_plans":
            await unified_hosting_flow(query)
        elif data.startswith("unified_plan_"):
            plan_id = data.replace("unified_plan_", "")
            await handle_unified_plan_selection(query, context, plan_id)
        elif data.startswith("unified_new_domain_"):
            plan_id = data.replace("unified_new_domain_", "")
            await handle_unified_new_domain(query, context, plan_id)
        elif data.startswith("unified_existing_domain_"):
            plan_id = data.replace("unified_existing_domain_", "")
            await handle_unified_existing_domain(query, context, plan_id)
        elif data.startswith("unified_hosting_only_"):
            plan_id = data.replace("unified_hosting_only_", "")
            await handle_unified_hosting_only(query, context, plan_id)
        elif data.startswith("unified_checkout_new_"):
            # Format: unified_checkout_new_{plan_id}:{domain_name}
            checkout_data = data.replace("unified_checkout_new_", "")
            if ":" in checkout_data:
                plan_id, domain_name = checkout_data.split(":", 1)
                await unified_checkout(query, 'new', plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid checkout data.")
        elif data.startswith("unified_checkout_existing_"):
            # Format: unified_checkout_existing_{plan_id}:{domain_name}
            checkout_data = data.replace("unified_checkout_existing_", "")
            if ":" in checkout_data:
                plan_id, domain_name = checkout_data.split(":", 1)
                await unified_checkout(query, 'existing', plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid checkout data.")
        elif data.startswith("unified_checkout_only_"):
            plan_id = data.replace("unified_checkout_only_", "")
            await unified_checkout(query, 'only', plan_id)
        elif data.startswith("intent_wallet_"):
            # Format: intent_wallet_{intent_id}:{price}
            wallet_data = data.replace("intent_wallet_", "")
            if ":" in wallet_data:
                intent_id, price = wallet_data.split(":", 1)
                await process_intent_wallet_payment(query, intent_id, price)
            else:
                await safe_edit_message(query, "❌ Invalid payment data.")
        elif data.startswith("unified_wallet_"):
            # Format: unified_wallet_{subscription_id}:{price}
            wallet_data = data.replace("unified_wallet_", "")
            if ":" in wallet_data:
                subscription_id, price = wallet_data.split(":", 1)
                await process_unified_wallet_payment(query, subscription_id, price)
            else:
                await safe_edit_message(query, "❌ Invalid payment data.")
        elif data.startswith("unified_crypto_"):
            # Format: unified_crypto_{crypto_type}_{subscription_id}:{price}
            crypto_data = data.replace("unified_crypto_", "")
            if "_" in crypto_data and ":" in crypto_data:
                crypto_type, rest = crypto_data.split("_", 1)
                if ":" in rest:
                    subscription_id, price = rest.split(":", 1)
                    await process_unified_crypto_payment(query, crypto_type, subscription_id, price)
                else:
                    await safe_edit_message(query, "❌ Invalid crypto payment data.")
            else:
                await safe_edit_message(query, "❌ Invalid crypto payment data.")
        elif data.startswith("intent_crypto_"):
            # Format: intent_crypto_{crypto}_{intent_id}:{price}
            crypto_data = data.replace("intent_crypto_", "")
            if ":" in crypto_data:
                crypto_intent_part, price = crypto_data.split(":", 1)
                crypto_intent_parts = crypto_intent_part.split("_")
                if len(crypto_intent_parts) >= 2:
                    crypto = crypto_intent_parts[0]
                    intent_id = "_".join(crypto_intent_parts[1:])
                    await process_intent_crypto_payment(query, intent_id, crypto, price)
                else:
                    await safe_edit_message(query, "❌ Invalid payment data. Please try again.")
            else:
                await safe_edit_message(query, "❌ Invalid payment format. Please try again.")
        elif data.startswith("unified_checkout_review_"):
            # Format: unified_checkout_review_{subscription_id}
            subscription_id = data.replace("unified_checkout_review_", "")
            await handle_unified_checkout_review(query, subscription_id)
        elif data.startswith("notify_ready_"):
            plan_id = data.replace("notify_ready_", "")
            await handle_notify_ready(query, plan_id)
        elif data.startswith("collect_domain_"):
            plan_id = data.replace("collect_domain_", "")
            await collect_hosting_domain(query, context, plan_id)
        elif data.startswith("hosting_new_domain_"):
            plan_id = data.replace("hosting_new_domain_", "")
            await start_hosting_domain_search(query, context, plan_id)
        elif data.startswith("hosting_existing_domain_"):
            plan_id = data.replace("hosting_existing_domain_", "")
            await request_existing_domain(query, context, plan_id)
        elif data.startswith("confirm_hosting_bundle_"):
            # Handle domain + hosting bundle confirmation: confirm_hosting_bundle_{plan_id}:{domain_name}
            bundle_data = data.replace("confirm_hosting_bundle_", "")
            if ":" in bundle_data:
                plan_id, domain_name = bundle_data.split(":", 1)
                await confirm_hosting_purchase(query, plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid bundle data. Please try again.")
        elif data.startswith("confirm_hosting_existing_"):
            # Handle existing domain + hosting confirmation: confirm_hosting_existing_{plan_id}:{domain_name}
            existing_data = data.replace("confirm_hosting_existing_", "")
            if ":" in existing_data:
                plan_id, domain_name = existing_data.split(":", 1)
                await confirm_hosting_purchase(query, plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid hosting data. Please try again.")
        elif data.startswith("retry_ns_update:"):
            logger.info(f"Routing to: handle_retry_nameserver_update")
            await handle_retry_nameserver_update(query, context, data)
        elif data.startswith("recheck_ns_"):
            # Handle nameserver recheck for hosting: recheck_ns_{plan_id}:{domain_name}
            ns_data = data.replace("recheck_ns_", "")
            if ":" in ns_data:
                plan_id, domain_name = ns_data.split(":", 1)
                await recheck_hosting_nameservers(query, plan_id, domain_name)
            else:
                await safe_edit_message(query, "❌ Invalid nameserver recheck data. Please try again.")
        elif data.startswith("manage_hosting_"):
            # Handle individual hosting management: manage_hosting_{subscription_id}
            subscription_id = data.replace("manage_hosting_", "")
            await show_hosting_management(query, subscription_id)
        elif data.startswith("hosting_details_"):
            # Handle hosting account details: hosting_details_{subscription_id}
            subscription_id = data.replace("hosting_details_", "")
            await show_hosting_details(query, subscription_id)
        elif data.startswith("cpanel_login_"):
            # Handle cPanel login info: cpanel_login_{subscription_id}
            subscription_id = data.replace("cpanel_login_", "")
            await show_cpanel_login(query, subscription_id)
        elif data.startswith("hosting_usage_"):
            # Handle hosting usage stats: hosting_usage_{subscription_id}
            subscription_id = data.replace("hosting_usage_", "")
            await show_hosting_usage(query, subscription_id)
        elif data.startswith("suspend_hosting_"):
            # Handle hosting suspension: suspend_hosting_{subscription_id}
            subscription_id = data.replace("suspend_hosting_", "")
            await suspend_hosting_account(query, subscription_id)
        elif data.startswith("unsuspend_hosting_"):
            # Handle hosting unsuspension: unsuspend_hosting_{subscription_id}
            subscription_id = data.replace("unsuspend_hosting_", "")
            await unsuspend_hosting_account(query, subscription_id)
        elif data.startswith("confirm_suspend_"):
            # Handle suspension confirmation: confirm_suspend_{subscription_id}
            subscription_id = data.replace("confirm_suspend_", "")
            await confirm_hosting_suspension(query, subscription_id)
        elif data.startswith("cancel_suspend_"):
            # Handle suspension cancellation: cancel_suspend_{subscription_id}
            subscription_id = data.replace("cancel_suspend_", "")
            await show_hosting_management(query, subscription_id)
        elif data.startswith("restart_hosting_"):
            # Handle hosting service restart: restart_hosting_{subscription_id}
            subscription_id = data.replace("restart_hosting_", "")
            await restart_hosting_services(query, subscription_id)
        elif data.startswith("check_hosting_status_"):
            # Handle hosting status check: check_hosting_status_{subscription_id}
            subscription_id = data.replace("check_hosting_status_", "")
            await check_hosting_status(query, subscription_id)
        else:
            await safe_edit_message(query, "❌ Unknown action. Please try again.")
            
    except Exception as e:
        user = query.from_user
        logger.error(f"Callback error for user {user.id if user else 'unknown'} with data '{data}': {e}")
        try:
            await safe_edit_message(query, "❌ An error occurred. Please try again.")
        except Exception as edit_error:
            logger.error(f"Failed to send error message to user {user.id if user else 'unknown'}: {edit_error}")

async def show_main_menu(query):
    """Show the main menu with proper localization"""
    user = query.from_user
    if not user:
        logger.error("Missing user in show_main_menu")
        return
    
    try:
        # Get user's language preference
        user_lang = await resolve_user_language(user.id, user.language_code)
        
        # Get localized main menu message
        platform_title = await t_for_user('dashboard.complete_hosting_platform', user.id, platform_name=get_platform_name())
        quick_actions_text = await t_for_user('dashboard.quick_actions', user.id)
        
        # Fallback to branded format if translation keys don't exist
        if 'dashboard.complete_hosting_platform' in platform_title or 'dashboard.quick_actions' in quick_actions_text:
            message = format_branded_message("""
🌐 {platform_name} - Complete Hosting Platform

Quick Actions:
""")
        else:
            message = f"{platform_title}\n\n{quick_actions_text}:"
        
        # Localized button texts
        search_text = await t_for_user('buttons.search_domains', user.id)
        domains_text = await t_for_user('buttons.my_domains', user.id)
        hosting_text = await t_for_user('buttons.hosting', user.id)
        wallet_text = await t_for_user('buttons.wallet', user.id)
        profile_text = await t_for_user('buttons.profile', user.id)
        
        # Fallback button texts if translations missing
        if 'buttons.' in search_text: search_text = "🔍 Search Domains"
        if 'buttons.' in domains_text: domains_text = "🌐 My Domains"
        if 'buttons.' in hosting_text: hosting_text = "🏠 Web Hosting"
        if 'buttons.' in wallet_text: wallet_text = "💰 Wallet"
        if 'buttons.' in profile_text: profile_text = "👤 Profile"
        
        keyboard = [
            [InlineKeyboardButton(search_text, callback_data="search_domains")],
            [InlineKeyboardButton(domains_text, callback_data="my_domains")],
            [InlineKeyboardButton(hosting_text, callback_data="hosting_main")],
            [InlineKeyboardButton(wallet_text, callback_data="wallet_main")],
            [InlineKeyboardButton(profile_text, callback_data="profile_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        logger.info(f"✅ Main menu shown to user {user.id} in language: {user_lang}")
        
    except Exception as e:
        logger.error(f"Error localizing main menu for user {user.id}: {e}")
        # Fallback to original hardcoded version
        message = format_branded_message("""
🌐 {platform_name} - Complete Hosting Platform

Quick Actions:
""")
        keyboard = [
            [InlineKeyboardButton("🔍 Search Domains", callback_data="search_domains")],
            [InlineKeyboardButton("🌐 My Domains", callback_data="my_domains")],
            [InlineKeyboardButton("🏠 Web Hosting", callback_data="hosting_main")],
            [InlineKeyboardButton("💰 Wallet", callback_data="wallet_main")],
            [InlineKeyboardButton("👤 Profile", callback_data="profile_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_search_interface(query):
    """Show domain search interface"""
    message = """
🔍 Domain Search

Enter a domain name to check availability.

Type domain name to check availability.
"""
    keyboard = [
        [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_user_domains(query):
    """Show user's domains - placeholder"""
    message = """
🌐 Your Domains

Loading your domains...
"""
    await safe_edit_message(query, message)

async def show_user_domains_complete(query):
    """Show complete domains management interface"""
    user = query.from_user
    
    try:
        user_record = await get_or_create_user(user.id)
        domains = await get_user_domains(user_record['id'])
        
        if not domains:
            message = """
📋 My Domains

You don't have any registered domains yet.

Get started by searching for and registering your first domain!
"""
            keyboard = [
                [InlineKeyboardButton("🔍 Search Domains", callback_data="search_domains")],
                [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
            ]
        else:
            message = f"""
📋 My Domains

You have {len(domains)} registered domain(s):

"""
            keyboard = []
            for domain in domains:
                domain_name = domain['domain_name']
                status = domain['status']
                emoji = "✅" if status == 'active' else "⏳"
                message += f"{emoji} {domain_name} ({status.title()})\n"
                keyboard.append([InlineKeyboardButton(f"🌐 {domain_name}", callback_data=f"dns_{domain_name}")])
            
            keyboard.extend([
                [InlineKeyboardButton("🔍 Register New Domain", callback_data="search_domains")],
                [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
            ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing domains interface: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load domains.")

async def show_wallet_interface(query):
    """Show wallet interface with real balance"""
    user = query.from_user
    
    try:
        user_record = await get_or_create_user(user.id)
        balance = await get_user_wallet_balance(user.id)
        
        # Get recent transactions
        transactions = await get_user_wallet_transactions(user_record['id'], 5)
        
        # Format transaction history
        transaction_history = ""
        if transactions:
            for tx in transactions[:3]:  # Only show 3 recent
                amount = float(tx['amount'])
                date = tx['created_at'].strftime('%m/%d')
                emoji = "➕" if amount > 0 else "➖"
                tx_type = tx['transaction_type'] or 'transaction'
                
                # Extract simple type from verbose descriptions
                if 'domain' in tx_type.lower():
                    simple_type = 'Domain'
                elif 'deposit' in tx_type.lower() or 'crypto' in tx_type.lower():
                    simple_type = 'Deposit'
                elif 'credit' in tx_type.lower():
                    simple_type = 'Credit'
                elif 'refund' in tx_type.lower():
                    simple_type = 'Refund'
                else:
                    simple_type = tx_type.title()[:8]  # Truncate to 8 chars max
                
                transaction_history += f"{emoji} {format_money(abs(amount), 'USD', include_currency=True)} - {simple_type} ({date})\n"
        else:
            transaction_history = "\nNo transactions yet"
        
        # Get brand config for dynamic support contact
        config = BrandConfig()
        
        message = f"""
💰 Wallet

Balance: {format_money(balance, 'USD', include_currency=True)}
{transaction_history}

Need help with payments? Contact {config.support_contact}"""
        
        keyboard = [
            [InlineKeyboardButton("💳 Add Funds", callback_data="wallet_deposit")],
            [InlineKeyboardButton("📊 Transaction History", callback_data="wallet_history")],
            [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing wallet interface: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load wallet information.")

async def show_profile_interface(query):
    """Show profile interface"""
    user = query.from_user
    config = BrandConfig()
    
    message = f"""👤 Profile

{user.first_name or ''} {user.last_name or ''}
@{user.username or 'Not set'} • ID: {user.id}

🌐 Domains • 🔧 DNS • 💰 Crypto • 🏠 Hosting

Help: {config.support_contact}"""
    
    keyboard = [
        [InlineKeyboardButton("🌍 Language Settings", callback_data="language_selection")],
        [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_contact_support(query):
    """Show contact support information"""
    platform_name = get_platform_name()
    
    # Use the new HTML-formatted message template
    message = create_contact_support_message(platform_name, query.from_user.id)
    
    # Get dynamic support contact from BrandConfig
    config = BrandConfig()
    support_url = f"https://t.me/{config.support_contact.lstrip('@')}"
    
    keyboard = [
        [InlineKeyboardButton(f"📱 Message {config.support_contact}", url=support_url)],
        [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

# UNIFIED HOSTING FLOW - Single Entry Point System
# ================================================================

async def smart_domain_handler(query, context, plan_id: str, domain_text: Optional[str] = None):
    """
    Intelligent domain scenario detection and handling
    Automatically determines: registration, existing domain, or transfer needed
    """
    user = query.from_user
    
    try:
        # Get plan information
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        plan_price = plan.get('period_price', plan.get('monthly_price', 0))
        
        if domain_text:
            # Domain provided - analyze it
            domain_name = domain_text.lower().strip()
            
            # Basic domain validation
            if not is_valid_domain(domain_name):
                await safe_edit_message(query, 
                    f"❌ Invalid domain format: {domain_name}\n\n"
                    "Please enter a valid domain name (e.g., mywebsite.com)")
                return
            
            # Check if domain is already registered
            user_record = await get_or_create_user(query.from_user.id)
            domain_status = await analyze_domain_status(domain_name, user_record['id'])
            
            if domain_status['exists']:
                # Domain exists - check ownership and DNS
                await handle_existing_domain_hosting(query, context, plan_id, domain_name, domain_status)
            else:
                # Domain available - offer registration + hosting
                await handle_new_domain_hosting(query, context, plan_id, domain_name, plan)
                
        else:
            # No domain provided - show smart domain options
            await show_smart_domain_options(query, context, plan_id, plan)
            
    except Exception as e:
        logger.error(f"Error in smart domain handler: {e}")
        await safe_edit_message(query, "❌ Error processing domain. Please try again.")

def _get_estimated_domain_price(tld: str) -> float:
    """
    Get estimated domain pricing when OpenProvider API doesn't return pricing
    """
    # Common TLD pricing estimates (in USD, wholesale rates)
    tld_estimates = {
        'com': 11.99,
        'net': 13.99,
        'org': 12.99,
        'info': 12.99,
        'biz': 13.99,
        'co': 29.99,
        'io': 49.99,
        'ai': 79.99,
        'dev': 12.99,
        'app': 17.99,
        'tech': 39.99,
        'online': 2.99,
        'site': 2.99,
        'website': 2.99,
        'store': 39.99,
        'blog': 29.99,
        'news': 25.99,
        'cloud': 19.99,
        'me': 19.99,
        'tv': 29.99,
        'cc': 29.99,
        'ws': 29.99,
        'sbs': 2.99,
        'xyz': 1.99,
        'top': 1.99,
        'click': 1.99,
        'link': 9.99,
        'pro': 15.99,
        'mobi': 19.99
    }
    
    # Return estimated price or default for unknown TLDs
    return tld_estimates.get(tld.lower(), 15.99)  # Default to $15.99 for unknown TLDs

async def analyze_domain_status(domain_name: str, user_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Comprehensive domain analysis with 3-table state management system
    Checks: ownership_state in domains table, active intents, OpenProvider availability
    Logs all searches to domain_searches table without affecting ownership state
    """
    try:
        logger.info(f"🔍 Analyzing domain: {domain_name} for user {user_id or 'unknown'}")
        
        # Check ownership state (NOT just existence in domains table)
        ownership_state = await check_domain_ownership_state(domain_name)
        
        # Check for active registration intents for this user
        active_intent = None
        if user_id:
            active_intent = await get_active_registration_intent(user_id, domain_name)
        
        if ownership_state in ['internal_owned', 'external_verified']:
            # Domain is owned - check DNS configuration
            existing_domain = await get_domain_by_name(domain_name)
            cf_zone = await get_cloudflare_zone(domain_name)
            nameservers = await get_domain_nameservers(domain_name)
            
            search_result = {
                'exists': True,
                'in_our_system': True,
                'ownership_state': ownership_state,
                'has_cloudflare': bool(cf_zone),
                'nameservers': nameservers,
                'status': 'managed_domain',
                'auto_dns_possible': bool(cf_zone),
                'dns_status': 'managed',
                'can_auto_configure': True,
                'active_intent': active_intent
            }
            
            # Log search to domain_searches table (don't affect ownership)
            if user_id:
                await log_domain_search(user_id, domain_name, search_result)
            
            return search_result
        else:
            # No ownership state - check OpenProvider for availability and log search
            logger.info(f"🔍 Checking domain availability: {domain_name}")
            
            # Check domain availability via OpenProvider
            openprovider = OpenProviderService()
            check_result = await openprovider.check_domain_availability(domain_name)
            
            if check_result and check_result.get('available', True):
                # Domain available for registration
                # Get price from provider's price_info structure
                price_info = check_result.get('price_info', {})
                provider_price = price_info.get('create_price')
                
                if provider_price is not None and provider_price > 0:
                    # Use provider pricing (already marked up)
                    registration_price = provider_price
                    base_price = price_info.get('base_price_usd', provider_price)
                    logger.info(f"✅ Domain pricing from provider: ${base_price:.2f} → ${registration_price:.2f}")
                else:
                    # Fallback: Use estimated pricing based on TLD
                    tld = domain_name.split('.')[-1] if '.' in domain_name else 'com'
                    estimated_price = _get_estimated_domain_price(tld)
                    registration_price = calculate_marked_up_price(estimated_price, 'USD')['final_price']
                    logger.warning(f"⚠️ No pricing from provider for {domain_name}, using estimated ${estimated_price:.2f} → ${registration_price:.2f}")
                
                search_result = {
                    'exists': False,
                    'in_our_system': False,
                    'ownership_state': None,
                    'has_cloudflare': False,
                    'nameservers': None,
                    'status': 'available',
                    'auto_dns_possible': True,  # Will be after registration
                    'registration_price': registration_price,
                    'dns_status': 'not_registered',
                    'can_auto_configure': True,
                    'active_intent': active_intent,
                    'available': True
                }
                
                # Log search to domain_searches table (ephemeral, does NOT affect ownership)
                if user_id:
                    await log_domain_search(user_id, domain_name, search_result)
                
                return search_result
            else:
                # Domain exists externally - check real nameservers and DNS status
                logger.info(f"🌐 Domain {domain_name} exists externally, checking DNS configuration...")
                
                # Get real nameservers for external domain
                actual_nameservers = await _get_real_nameservers(domain_name)
                
                # Check if domain is using Cloudflare nameservers
                is_using_cloudflare = _check_cloudflare_nameservers(actual_nameservers)
                
                # Try to find Cloudflare zone if using CF nameservers
                cf_zone = None
                if is_using_cloudflare:
                    try:
                        cf_service = CloudflareService()
                        zone = await cf_service.get_zone_by_name(domain_name)
                        if zone:
                            cf_zone = zone
                    except Exception as e:
                        logger.debug(f"Cloudflare zone check failed: {e}")
                
                # Determine auto-configuration possibility
                auto_dns_possible = is_using_cloudflare and bool(cf_zone)
                
                search_result = {
                    'exists': True,
                    'in_our_system': False,
                    'ownership_state': None,
                    'has_cloudflare': bool(cf_zone),
                    'nameservers': actual_nameservers,
                    'status': 'external_domain',
                    'auto_dns_possible': auto_dns_possible,
                    'dns_status': 'cloudflare_managed' if is_using_cloudflare else 'external_dns',
                    'can_auto_configure': auto_dns_possible,
                    'using_cloudflare_ns': is_using_cloudflare,
                    'registration_price': None,  # External domain - no registration needed
                    'active_intent': active_intent,
                    'available': False
                }
                
                # Log search to domain_searches table (ephemeral, does NOT affect ownership)
                if user_id:
                    await log_domain_search(user_id, domain_name, search_result)
                
                return search_result
                    
    except Exception as e:
        logger.error(f"Error analyzing domain status for {domain_name}: {e}")
        # Return safe fallback status with new schema
        fallback_result = {
            'exists': True,  # Assume exists to be safe
            'in_our_system': False,
            'ownership_state': None,
            'has_cloudflare': False,
            'nameservers': None,
            'status': 'unknown_external',
            'auto_dns_possible': False,
            'dns_status': 'unknown',
            'can_auto_configure': False,
            'active_intent': None,
            'available': False
        }
        
        # Log error case to domain_searches table for debugging
        if user_id:
            try:
                await log_domain_search(user_id, domain_name, {**fallback_result, 'error': str(e)})
            except Exception as log_error:
                logger.error(f"Failed to log error search for {domain_name}: {log_error}")
        
        return fallback_result

async def _get_real_nameservers(domain_name: str) -> List[str]:
    """Get actual nameservers for a domain using DNS resolution"""
    try:
        # Try multiple methods to get nameservers
        nameservers = []
        
        # Method 1: Use _get_nameservers_python_fallback (existing function)
        try:
            ns_list = await _get_nameservers_python_fallback(domain_name)
            if ns_list:
                nameservers.extend(ns_list)
        except Exception as e:
            logger.debug(f"Python DNS fallback failed: {e}")
        
        # Method 2: Try direct DNS query if dnspython is available
        if not nameservers:
            try:
                import dns.resolver
                answers = dns.resolver.resolve(domain_name, 'NS')
                nameservers = [str(answer).rstrip('.') for answer in answers]
            except ImportError:
                logger.debug("dnspython not available for NS lookup")
            except Exception as e:
                logger.debug(f"DNS resolver failed: {e}")
        
        # Clean and validate nameservers
        clean_ns = []
        for ns in nameservers:
            ns_clean = ns.lower().strip().rstrip('.')
            if ns_clean and is_valid_nameserver(ns_clean):
                clean_ns.append(ns_clean)
        
        # Remove duplicates while preserving order
        unique_ns = []
        for ns in clean_ns:
            if ns not in unique_ns:
                unique_ns.append(ns)
        
        logger.info(f"🔍 Found nameservers for {domain_name}: {unique_ns}")
        return unique_ns
        
    except Exception as e:
        logger.warning(f"Failed to get nameservers for {domain_name}: {e}")
        return []

def _check_cloudflare_nameservers(nameservers: List[str]) -> bool:
    """Check if nameservers are Cloudflare nameservers"""
    if not nameservers:
        return False
    
    # Common Cloudflare nameserver patterns
    cf_patterns = [
        'ns.cloudflare.com',
        '.ns.cloudflare.com',
        'cloudflare.com'
    ]
    
    cf_count = 0
    for ns in nameservers:
        ns_lower = ns.lower().strip()
        for pattern in cf_patterns:
            if pattern in ns_lower:
                cf_count += 1
                break
    
    # Consider it Cloudflare if majority of nameservers match
    is_cloudflare = cf_count >= len(nameservers) / 2
    
    if is_cloudflare:
        logger.info(f"✅ Domain uses Cloudflare nameservers: {nameservers}")
    else:
        logger.info(f"ℹ️ Domain uses external nameservers: {nameservers}")
    
    return is_cloudflare

async def show_smart_domain_options(query, context, plan_id: str, plan: Dict):
    """Show intelligent domain options based on user's needs"""
    plan_name = plan.get('plan_name', 'Unknown')
    plan_price = plan.get('period_price', plan.get('monthly_price', 0))
    display_price = plan.get('display_price', f"${plan_price}")
    
    message = f"""🏠 <b>{plan_name} Hosting</b>

<b>Plan:</b> {display_price} • {plan.get('disk_space_gb', 0)}GB • {plan.get('databases', 0)} DBs

<b>Domain:</b>
"""
    
    keyboard = [
        [InlineKeyboardButton("🆕 Register New", callback_data=f"unified_new_domain_{plan_id}")],
        [InlineKeyboardButton("🔗 Use Existing", callback_data=f"unified_existing_domain_{plan_id}")],
        [InlineKeyboardButton("📱 Hosting Only", callback_data=f"unified_hosting_only_{plan_id}")],
        [InlineKeyboardButton("⬅️ Back", callback_data="unified_hosting_plans")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def handle_new_domain_hosting(query, context, plan_id: str, domain_name: str, plan: Dict):
    """Handle new domain registration + hosting bundle"""
    plan_name = plan.get('plan_name', 'Unknown')
    plan_price = plan.get('period_price', plan.get('monthly_price', 0))
    
    # Get domain pricing
    user_record = await get_or_create_user(query.from_user.id)
    domain_status = await analyze_domain_status(domain_name, user_record['id'])
    
    # Check if domain is already managed in our system
    if domain_status.get('in_our_system', False):
        # Domain already exists in system - redirect to existing domain flow
        logger.info(f"🔄 Domain {domain_name} already managed - redirecting to existing domain flow")
        message_text, parse_mode = t_html('search.domain_already_owned', await resolve_user_language(query.from_user.id), domain=domain_name)
        await safe_edit_message(query, message_text, parse_mode=parse_mode)
        return
    
    domain_price = domain_status.get('registration_price')
    if domain_price is None:
        # Check if domain is already registered vs pricing error
        domain_status_type = domain_status.get('status', 'unknown')
        if domain_status_type == 'external_domain':
            message_text, parse_mode = t_html('search.domain_unavailable_registered', await resolve_user_language(query.from_user.id), domain=domain_name)
            await safe_edit_message(query, message_text, parse_mode=parse_mode)
        else:
            message_text, parse_mode = t_html('search.domain_pricing_unavailable', await resolve_user_language(query.from_user.id), domain=domain_name)
            await safe_edit_message(query, message_text, parse_mode=parse_mode)
        return
    total_price = plan_price + domain_price
    
    message = f"""
🆕 <b>{domain_name} + {plan_name}</b>

💰 <b>Total: ${total_price:.2f}</b>
• Domain: ${domain_price:.2f}
• Hosting: ${plan_price:.2f}

✅ Auto-setup included
"""
    
    keyboard = [
        [InlineKeyboardButton(f"🛒 Purchase Bundle (${total_price:.2f})", callback_data=f"unified_checkout_new_{plan_id}:{domain_name}")],
        [InlineKeyboardButton("🔍 Try Different Domain", callback_data=f"unified_new_domain_{plan_id}")],
        [InlineKeyboardButton("⬅️ Back to Options", callback_data=f"unified_plan_{plan_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def handle_existing_domain_hosting(query, context, plan_id: str, domain_name: str, domain_status: Dict):
    """Handle existing domain + hosting with smart DNS detection"""
    plans = cpanel.get_hosting_plans()
    plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
    
    if not plan:
        await safe_edit_message(query, "❌ Hosting plan not found.")
        return
    
    plan_name = plan.get('plan_name', 'Unknown')
    plan_price = plan.get('period_price', plan.get('monthly_price', 0))
    
    # Smart DNS configuration based on domain status
    if domain_status['in_our_system'] and domain_status['auto_dns_possible']:
        # Domain managed by us - automatic setup
        dns_setup = "🤖 <b>Automatic DNS Setup</b>\nYour domain is managed by us - DNS will be configured automatically!"
        action_text = "Configure Hosting"
    elif domain_status['auto_dns_possible']:
        # Can potentially set up DNS automatically
        dns_setup = "⚡ <b>Smart DNS Setup</b>\nWe'll attempt automatic DNS configuration for your domain."
        action_text = "Setup Hosting"
    else:
        # Manual DNS configuration required
        hosting_ns = get_hosting_nameservers()
        dns_setup = f"""
📋 <b>Manual DNS Setup Required</b>
After purchase, update your domain's nameservers to:
• {hosting_ns[0]}
• {hosting_ns[1]}

<i>We'll provide detailed instructions after purchase.</i>
"""
        action_text = "Get Hosting"
    
    message = f"""🔗 <b>{domain_name} + {plan_name}</b>

<b>Plan:</b> ${plan_price:.2f} • {plan.get('disk_space_gb', 0)}GB
<b>Domain:</b> ✅ Already registered

{dns_setup}
"""
    
    keyboard = [
        [InlineKeyboardButton(f"🛒 {action_text} (${plan_price:.2f})", callback_data=f"unified_checkout_existing_{plan_id}:{domain_name}")],
        [InlineKeyboardButton("🔄 Try Different Domain", callback_data=f"unified_existing_domain_{plan_id}")],
        [InlineKeyboardButton("⬅️ Back to Options", callback_data=f"unified_plan_{plan_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def unified_hosting_flow(query):
    """Main entry point for unified hosting flow"""
    user = query.from_user
    
    try:
        # Get user hosting subscriptions for context
        from database import get_or_create_user, get_user_hosting_subscriptions
        db_user = await get_or_create_user(telegram_id=user.id)
        subscriptions = await get_user_hosting_subscriptions(db_user['id'])
        
        # Show unified hosting interface
        plans = cpanel.get_hosting_plans()
        
        if subscriptions:
            hosting_summary = f" • <b>{len(subscriptions)} Active</b>"
        else:
            hosting_summary = ""
        
        message = f"""🏠 <b>Offshore "Never-Down" Hosting{hosting_summary}</b>

<b>Plans:</b>
"""
        
        keyboard = []
        
        # Add plan options
        for plan in plans:
            plan_name = plan.get('plan_name', 'Unknown')
            display_price = plan.get('display_price', f"${plan.get('period_price', 0)}")
            disk = plan.get('disk_space_gb', 0)
            databases = plan.get('databases', 0)
            
            message += f"\n<b>{plan_name}</b> - {display_price} • {disk}GB • {databases} DBs • ∞ Domains\n"
            
            keyboard.append([InlineKeyboardButton(
                f"🚀 Get {plan_name} Hosting", 
                callback_data=f"unified_plan_{plan.get('id', '')}"
            )])
        
        # Add management options if user has hosting
        if subscriptions:
            keyboard.append([InlineKeyboardButton("⚙️ Manage My Hosting", callback_data="my_hosting")])
        
        keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error in unified hosting flow: {e}")
        await safe_edit_message(query, "❌ Error loading hosting options. Please try again.")

# UNIFIED CHECKOUT SYSTEM
# ================================================================

async def unified_checkout(query, checkout_type: str, plan_id: str, domain_name: Optional[str] = None):
    """Unified checkout for hosting ± domain with dynamic pricing"""
    user = query.from_user
    
    # 🎯 INSTANT FEEDBACK: Show immediate processing message
    processing_msg = "🔄 <b>Processing your order...</b>\n\n"
    if checkout_type == 'new' and domain_name:
        processing_msg += f"📋 Preparing bundle: {domain_name} + hosting\n"
    else:
        processing_msg += "📋 Preparing hosting checkout...\n"
    processing_msg += "⏳ Please wait a moment..."
    
    await safe_edit_message(query, processing_msg, parse_mode='HTML')
    
    try:
        # Get plan information
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        plan_price = plan.get('period_price', plan.get('monthly_price', 0))
        
        # Calculate total based on checkout type
        if checkout_type == 'new' and domain_name:
            # 🎯 PROGRESS UPDATE: Show domain checking status
            checking_msg = f"🔄 <b>Checking domain availability...</b>\n\n"
            checking_msg += f"🌐 Analyzing: <code>{domain_name}</code>\n"
            checking_msg += f"📋 Plan: {plan_name}\n"
            checking_msg += "⏳ This may take a few seconds..."
            
            await safe_edit_message(query, checking_msg, parse_mode='HTML')
            
            # New domain + hosting bundle
            from database import get_or_create_user
            user_record = await get_or_create_user(query.from_user.id)
            domain_status = await analyze_domain_status(domain_name, user_record['id'])
            
            # Check if domain is already managed in our system
            if domain_status.get('in_our_system', False):
                # Domain already exists in system - redirect to existing domain flow
                logger.info(f"🔄 Domain {domain_name} already managed - redirecting to existing domain flow")
                await safe_edit_message(query, f"✅ {domain_name} is already in your account! Connecting to hosting...")
                # Continue as existing domain connection
                total_price = plan_price
                items = [
                    f"Connect domain: {domain_name}",
                    f"{plan_name} hosting"
                ]
                service_type = 'hosting_existing_domain'
            else:
                # Domain available for registration
                domain_price = domain_status.get('registration_price')
                if domain_price is None:
                    # Check if domain is already registered vs pricing error
                    domain_status_type = domain_status.get('status', 'unknown')
                    if domain_status_type == 'external_domain':
                        await safe_edit_message(query, "❌ Domain {} already registered. Try a different name.".format(domain_name))
                    else:
                        await safe_edit_message(query, "❌ Domain Pricing Unavailable\n\nUnable to get pricing for {}. Please try a different domain or contact support.".format(domain_name))
                    return
                total_price = plan_price + domain_price
                items = [
                    f"Domain registration: {domain_name}",
                    f"{plan_name} hosting"
                ]
                service_type = 'hosting_domain_bundle'
        elif checkout_type == 'existing' and domain_name:
            # Existing domain + hosting
            total_price = plan_price
            items = [
                f"Connect domain: {domain_name}",
                f"{plan_name} hosting"
            ]
            service_type = 'hosting_existing_domain'
        else:
            # Hosting only
            total_price = plan_price
            items = [f"{plan_name} hosting"]
            service_type = 'hosting_only'
        
        # Create hosting provision intent to prevent duplicates
        db_user = await get_or_create_user_with_status(telegram_id=user.id)
        
        # Ensure domain_name is provided for unified flow
        if not domain_name:
            domain_name = f"temp_{user.id}_{int(time.time())}"
        
        # Check for existing active hosting intent
        existing_intent = await get_active_hosting_intent(db_user['id'], domain_name)
        if existing_intent:
            # Use existing intent
            intent_id = existing_intent['id']
            logger.info(f"⚠️ Using existing hosting intent {intent_id} for {domain_name}")
        else:
            # Create new hosting provision intent
            intent_id = await create_hosting_intent(
                user_id=db_user['id'],
                domain_name=domain_name,
                hosting_plan_id=int(plan_id),
                estimated_price=total_price,  # FIX: Store total bundle price, not just hosting
                service_type=service_type  # CRITICAL: Pass service type for bundle detection
            )
        
        if not intent_id:
            await safe_edit_message(query, "❌ Error creating hosting order. Please try again.")
            return
        
        # Show payment options for hosting intent (ensure domain_name is not None)
        safe_domain_name = domain_name or f"temp_{user.id}_{int(time.time())}"
        await show_unified_payment_options_with_intent(
            query, 
            intent_id, 
            total_price, 
            plan_name, 
            safe_domain_name,
            items,
            service_type
        )
        
    except Exception as e:
        logger.error(f"Error in unified checkout: {e}")
        await safe_edit_message(query, "❌ Error processing checkout. Please try again.")

async def show_unified_payment_options(query, subscription_id: int, price: float, plan_name: str, domain_name: str, items: List[str], service_type: str):
    """Show unified payment options for hosting ± domain"""
    items_text = "\n".join([f"• {item}" for item in items])
    
    # Get user's wallet balance for validation
    try:
        user_balance = await get_user_wallet_balance(query.from_user.id)
        has_sufficient_balance = user_balance >= price
        # Show order price on button, not user balance
        price_display = format_money(price, include_currency=False)
        wallet_text = f"💰 Pay with Wallet ({price_display})"
        if not has_sufficient_balance:
            wallet_text += " ⚠️"
    except Exception as e:
        logger.warning(f"Could not retrieve wallet balance: {e}")
        price_display = format_money(price, include_currency=False)
        wallet_text = f"💰 Pay with Wallet ({price_display})"
        has_sufficient_balance = False
        user_balance = 0.0  # Set fallback for display
    
    # Format wallet balance for display
    balance_display = format_money(user_balance, 'USD', include_currency=True)
    
    message = f"""
💳 <b>Order Checkout</b>

{items_text}

💰 <b>Total: ${price:.2f}</b>
💳 <b>Wallet Balance: {balance_display}</b>

Choose payment method:
"""
    
    keyboard = [
        [InlineKeyboardButton(wallet_text, callback_data=f"unified_wallet_{subscription_id}:{price}")],
    ]
    
    # Add cryptocurrency options using unified config
    for display_text, callback_suffix, icon in crypto_config.get_payment_button_data():
        keyboard.append([InlineKeyboardButton(
            f"{display_text}", 
            callback_data=f"unified_crypto_{callback_suffix}_{subscription_id}:{price}"
        )])
    
    keyboard.append([InlineKeyboardButton("⬅️ Back to Plans", callback_data="unified_hosting_plans")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

async def show_unified_payment_options_with_intent(query, intent_id: int, price: float, plan_name: str, domain_name: str, items: List[str], service_type: str):
    """
    Show unified payment options for hosting intent (before subscription creation)
    FIXED: Implements missing function that handlers were calling
    """
    items_text = "\n".join([f"• {item}" for item in items])
    
    # Get user's wallet balance for validation
    try:
        user_balance = await get_user_wallet_balance(query.from_user.id)
        has_sufficient_balance = user_balance >= price
        # Show order price on button, not user balance
        price_display = format_money(price, include_currency=False)
        wallet_text = f"💰 Pay with Wallet ({price_display})"
        if not has_sufficient_balance:
            wallet_text += " ⚠️"
    except Exception as e:
        logger.warning(f"Could not retrieve wallet balance: {e}")
        price_display = format_money(price, include_currency=False)
        wallet_text = f"💰 Pay with Wallet ({price_display})"
        has_sufficient_balance = False
        user_balance = 0.0  # Set fallback for display
    
    # Format wallet balance for display
    balance_display = format_money(user_balance, 'USD', include_currency=True)
    
    message = f"""
💳 <b>Order Checkout</b>

{items_text}

💰 <b>Total: ${price:.2f}</b>
💳 <b>Wallet Balance: {balance_display}</b>

Choose payment method:
"""
    
    keyboard = [
        [InlineKeyboardButton(wallet_text, callback_data=f"intent_wallet_{intent_id}:{price}")],
    ]
    
    # Add cryptocurrency options using unified config  
    for display_text, callback_suffix, icon in crypto_config.get_payment_button_data():
        keyboard.append([InlineKeyboardButton(
            f"{display_text}", 
            callback_data=f"intent_crypto_{callback_suffix}_{intent_id}:{price}"
        )])
    
    keyboard.append([InlineKeyboardButton("⬅️ Back to Plans", callback_data="unified_hosting_plans")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')

# UNIFIED HOSTING CALLBACK HANDLERS
# ================================================================

async def handle_unified_plan_selection(query, context, plan_id: str):
    """Handle plan selection in unified flow"""
    plans = cpanel.get_hosting_plans()
    plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
    
    if not plan:
        await safe_edit_message(query, "❌ Hosting plan not found.")
        return
    
    await show_smart_domain_options(query, context, plan_id, plan)

async def handle_unified_new_domain(query, context, plan_id: str):
    """Handle new domain registration flow"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        display_price = plan.get('display_price', f"${plan.get('period_price', 0)}")
        
        message = f"""
🆕 <b>{plan_name} + Domain Bundle ({display_price})</b>

Enter domain name to register:
<i>Example: mywebsite.com</i>
"""
        
        # Set context for text input handling
        context.user_data['unified_flow'] = 'awaiting_new_domain'
        context.user_data['unified_plan_id'] = plan_id
        context.user_data['plan_name'] = plan_name
        
        keyboard = [
            [InlineKeyboardButton("⬅️ Back to Options", callback_data=f"unified_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        logger.info(f"User {query.from_user.id} starting unified new domain search for plan {plan_id}")
        
    except Exception as e:
        logger.error(f"Error handling unified new domain: {e}")
        await safe_edit_message(query, "❌ Error processing domain search. Please try again.")

async def handle_unified_existing_domain(query, context, plan_id: str):
    """Handle existing domain connection flow"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        display_price = plan.get('display_price', f"${plan.get('period_price', 0)}")
        
        message = f"""
🔗 <b>Connect Existing Domain + {plan_name} Hosting</b>

<b>Plan:</b> {plan_name} ({display_price})
<b>Service:</b> Connect your existing domain

<b>🌐 Your Domain:</b>
Enter the domain name you want to connect:

<i>Example: myexistingsite.com</i>

We'll analyze your domain and provide smart DNS setup instructions.
"""
        
        # Set context for text input handling
        context.user_data['unified_flow'] = 'awaiting_existing_domain'
        context.user_data['unified_plan_id'] = plan_id
        context.user_data['plan_name'] = plan_name
        
        keyboard = [
            [InlineKeyboardButton("⬅️ Back to Options", callback_data=f"unified_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        logger.info(f"User {query.from_user.id} starting unified existing domain flow for plan {plan_id}")
        
    except Exception as e:
        logger.error(f"Error handling unified existing domain: {e}")
        await safe_edit_message(query, "❌ Error processing existing domain. Please try again.")

async def handle_unified_hosting_only(query, context, plan_id: str):
    """Handle hosting-only (no domain) flow"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        plan_price = plan.get('period_price', plan.get('monthly_price', 0))
        display_price = plan.get('display_price', f"${plan_price}")
        
        message = f"""
📱 <b>Get {plan_name} Hosting</b>

<b>Plan:</b> {plan_name} ({display_price})
<b>Service:</b> Hosting only (no domain)

<b>✅ What's included:</b>
• {plan.get('disk_space_gb', 0)}GB Storage
• {plan.get('databases', 0)} Databases
• {plan.get('email_accounts', 0)} Email Accounts
• cPanel Control Panel
• Free SSL Certificate
• 24/7 Support

<b>🌐 Domain Setup:</b>
• You can add domains later
• Use subdomain for testing
• Perfect for development work

<b>💰 Price: ${plan_price:.2f}</b>
"""
        
        keyboard = [
            [InlineKeyboardButton(f"🛒 Get Hosting (${plan_price:.2f})", callback_data=f"unified_checkout_only_{plan_id}")],
            [InlineKeyboardButton("⬅️ Back to Options", callback_data=f"unified_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error handling unified hosting only: {e}")
        await safe_edit_message(query, "❌ Error processing hosting-only option. Please try again.")

async def process_unified_wallet_payment(query, subscription_id: str, price: str):
    """Process wallet payment for unified hosting order with financial safety checks"""
    user = query.from_user
    
    try:
        # Convert price to float
        amount = float(price)
        
        # CRITICAL: Financial safety validation before any operations
        from database import (
            get_or_create_user, get_user_wallet_balance, debit_wallet_balance,
            verify_financial_operation_safety
        )
        
        # Verify financial operation safety
        safety_check = verify_financial_operation_safety(
            f"Unified hosting wallet payment (User: {user.id}, Amount: ${amount:.2f})", 
            amount
        )
        if not safety_check:
            logger.error(f"🚫 Financial safety check failed for user {user.id} payment ${amount:.2f}")
            await safe_edit_message(query, "❌ Payment system temporarily unavailable. Please try again later.")
            return
        
        logger.info(f"✅ Financial safety check passed for unified wallet payment: User {user.id}, ${amount:.2f}")
        
        # Get user wallet balance
        db_user = await get_or_create_user(telegram_id=user.id)
        balance = await get_user_wallet_balance(db_user['id'])
        
        if balance < amount:
            message = f"""
❌ <b>Insufficient Balance</b>

<b>Required:</b> ${amount:.2f}
<b>Your balance:</b> ${balance:.2f}
<b>Shortage:</b> ${amount - balance:.2f}

Please add funds to your wallet first.
"""
            keyboard = [
                [InlineKeyboardButton("💰 Add Funds", callback_data="wallet_main")],
                [InlineKeyboardButton("⬅️ Back to Payment", callback_data=f"unified_checkout_review_{subscription_id}")]
            ]
        else:
            # Process wallet payment with additional logging
            logger.info(f"💳 Processing unified hosting payment: User {user.id}, Amount ${amount:.2f}, Subscription #{subscription_id}")
            success = await debit_wallet_balance(db_user['id'], amount, f"Unified hosting subscription #{subscription_id}")
            
            if success:
                # Create hosting account after successful payment
                await create_unified_hosting_account_after_payment(int(subscription_id))
                
                message = f"""
✅ <b>Payment Successful!</b>

<b>Amount charged:</b> ${amount:.2f}
<b>Payment method:</b> Wallet Balance
<b>Order ID:</b> #{subscription_id}

Your hosting account is being created now. You'll receive login details shortly!
"""
                keyboard = [
                    [InlineKeyboardButton("🏠 View My Hosting", callback_data="my_hosting")],
                    [InlineKeyboardButton("📱 Main Menu", callback_data="main_menu")]
                ]
            else:
                message = f"""
❌ <b>Payment Failed</b>

There was an error processing your wallet payment. Please try again or contact support.

<b>Order ID:</b> #{subscription_id}
"""
                keyboard = [
                    [InlineKeyboardButton("🔄 Try Again", callback_data=f"unified_wallet_{subscription_id}:{price}")],
                    [InlineKeyboardButton("💬 Contact Support", callback_data="contact_support")]
                ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
    except Exception as e:
        logger.error(f"Error processing unified wallet payment: {e}")
        await safe_edit_message(query, "❌ Error processing payment. Please try again.")

async def process_intent_crypto_payment(query, intent_id: str, crypto: str, price: str):
    """Process cryptocurrency payment for hosting provision intent"""
    user = query.from_user
    
    try:
        # Get hosting provision intent with security checks
        from database import get_hosting_intent_by_id, get_or_create_user
        
        # Get user 
        db_user = await get_or_create_user(telegram_id=user.id)
        user_id = db_user['id']
        
        # Get hosting provision intent
        intent = await get_hosting_intent_by_id(int(intent_id))
        if not intent:
            await safe_edit_message(query, "❌ Hosting order not found or expired.")
            return
        
        # Verify intent belongs to user
        if intent['user_id'] != user_id:
            logger.error(f"🚫 Security: User {user_id} tried to pay for intent {intent_id} belonging to user {intent['user_id']}")
            await safe_edit_message(query, "❌ Invalid order access.")
            return
        
        # Check if crypto is supported
        if not crypto_config.is_supported(crypto):
            await safe_edit_message(query, f"❌ Unsupported cryptocurrency: {crypto}")
            return
        
        # Process crypto payment using existing domain registration crypto flow
        domain_name = intent.get('domain_name', '')
        await process_crypto_payment(query, crypto, domain_name, price, 'USD')
        
    except Exception as e:
        logger.error(f"Error processing intent crypto payment: {e}")
        await safe_edit_message(query, "❌ Error processing payment. Please try again.")

async def process_intent_wallet_payment(query, intent_id: str, price: str):
    """Process wallet payment for hosting provision intent"""
    user = query.from_user
    
    # 🎯 INSTANT FEEDBACK: Show immediate payment processing message
    processing_msg = f"💳 <b>Wallet Payment</b> • ${price}\n📋 Order #{intent_id}\n⏳ Verifying balance..."
    
    await safe_edit_message(query, processing_msg, parse_mode='HTML')
    
    try:
        # Convert IDs
        intent_id_int = int(intent_id)
        
        # CRITICAL: Get server-side authoritative data FIRST
        from database import (
            get_or_create_user, get_user_wallet_balance, debit_wallet_balance,
            verify_financial_operation_safety, get_hosting_intent_by_id,
            finalize_hosting_provisioning, credit_user_wallet
        )
        
        # Get user 
        db_user = await get_or_create_user(telegram_id=user.id)
        user_id = db_user['id']
        
        # Get hosting provision intent with security checks
        intent = await get_hosting_intent_by_id(intent_id_int)
        if not intent:
            await safe_edit_message(query, "❌ Hosting order not found or expired.")
            return
        
        # Verify intent belongs to user
        if intent['user_id'] != user_id:
            logger.error(f"🚫 Security: User {user_id} tried to pay for intent {intent_id} belonging to user {intent['user_id']}")
            await safe_edit_message(query, "❌ Invalid order access.")
            return
        
        # SECURITY: Check intent status to prevent double-payments (accept legacy statuses)
        payable_statuses = {'pending_payment', 'pending', 'awaiting_payment', 'draft', 'pending_checkout'}
        current_status = intent.get('status')
        if current_status not in payable_statuses:
            logger.error(f"🚫 Security: Intent {intent_id} is not in payable state: {current_status}")
            await safe_edit_message(query, "❌ This order is no longer available for payment.")
            return
        
        # Auto-upgrade legacy status to standard pending_payment
        if current_status in {'pending', 'awaiting_payment', 'draft', 'pending_checkout'}:
            logger.info(f"🔄 Auto-upgrading intent {intent_id} status: {current_status} → pending_payment")
            await update_hosting_intent_status(intent_id_int, 'pending_payment')
        
        # SECURITY: Use ONLY server-side authoritative price - ignore client input completely
        amount = float(intent.get('quote_price', 0))
        if amount <= 0:
            logger.error(f"🚫 Security: Invalid intent price for {intent_id}: {amount}")
            await safe_edit_message(query, "❌ Invalid order pricing. Please try again.")
            return
        
        # SECURITY: Financial safety validation using authoritative amount
        safety_check = verify_financial_operation_safety(
            f"Intent wallet payment (User: {user.id}, Intent: {intent_id}, Amount: ${amount:.2f})", 
            amount
        )
        if not safety_check:
            logger.error(f"🚫 Financial safety check failed for user {user.id} intent payment ${amount:.2f}")
            await safe_edit_message(query, "❌ Payment system temporarily unavailable. Please try again later.")
            return
        
        logger.info(f"✅ Financial safety check passed for intent wallet payment: User {user.id}, ${amount:.2f}")
        
        # Check wallet balance against authoritative amount
        balance = await get_user_wallet_balance(user.id)
        if balance < amount:
            await safe_edit_message(query, f"❌ Insufficient wallet balance. You have ${balance:.2f}, but need ${amount:.2f}.")
            return
        
        # Debit wallet balance first (before routing to orchestrator)
        debit_success = await debit_wallet_balance(
            user_id, 
            amount, 
            f"Hosting + Domain Payment - Intent {intent_id}"
        )
        
        if not debit_success:
            await safe_edit_message(query, "❌ Payment processing failed. Please try again.")
            return
        
        logger.info(f"✅ Wallet payment successful: User {user.id} paid ${amount:.2f} for intent {intent_id}")
        
        # Create payment details for wallet payments to show correct amount in success message (matching registration fix)
        wallet_payment_details = {
            'amount_usd': amount,
            'currency': 'USD',
            'payment_method': 'wallet'
        }
        
        # Create a query adapter for the orchestrator (similar to webhook adapter)
        class HandlerQueryAdapter:
            def __init__(self, query):
                self.query = query
                self.user_id = user_id
                
            async def send_message_to_user(self, text, reply_markup=None, parse_mode='HTML'):
                """Send message via telegram query interface with HTML formatting"""
                await safe_edit_message(self.query, text, reply_markup)
        
        query_adapter = HandlerQueryAdapter(query)
        
        # Show immediate processing message
        processing_msg = f"🚀 <b>Processing your hosting order...</b>\n\n"
        processing_msg += f"✅ Payment processed: ${amount:.2f}\n"
        processing_msg += f"🔄 Starting provisioning workflow...\n"
        processing_msg += f"⏳ This may take 30-60 seconds..."
        await safe_edit_message(query, processing_msg, parse_mode='HTML')
        
        # Route through centralized orchestrator (matching registration fix pattern)
        try:
            from services.hosting_orchestrator import HostingBundleOrchestrator
            orchestrator = HostingBundleOrchestrator()
            
            # Create order_id from intent_id for orchestrator compatibility
            orchestrator_result = await orchestrator.start_hosting_bundle(
                order_id=intent_id_int,  # Use intent_id as order_id
                user_id=user_id,
                domain_name=intent.get('domain_name', ''),
                payment_details=wallet_payment_details,  # Include wallet payment details for success message
                query_adapter=query_adapter
            )
            
            # Handle orchestrator results
            if orchestrator_result.get('status') == 'already_processed':
                logger.info(f"🚫 HANDLERS: Hosting bundle already processed for intent {intent_id}")
                await safe_edit_message(query, f"ℹ️ Order Already Complete\n\nHosting order has already been processed.")
                return
            
            elif orchestrator_result.get('status') == 'duplicate_prevented':
                logger.info(f"🚫 HANDLERS: Duplicate hosting bundle prevented for intent {intent_id}")
                await safe_edit_message(query, f"ℹ️ Order In Progress\n\nHosting order is already being processed.")
                return
            
            elif orchestrator_result.get('status') == 'error':
                logger.error(f"❌ HANDLERS: Orchestrator error for intent {intent_id}: {orchestrator_result.get('error', 'Unknown error')}")
                await safe_edit_message(query, f"❌ Provisioning Error\n\nAn error occurred during hosting setup. Your payment will be refunded if applicable.")
                return
            
            elif orchestrator_result.get('success'):
                logger.info(f"✅ HANDLERS: Hosting bundle completed via orchestrator: intent {intent_id}")
                # Orchestrator already sent success notification with buttons
            else:
                logger.warning(f"⚠️ HANDLERS: Unexpected orchestrator result for intent {intent_id}: {orchestrator_result}")
                await safe_edit_message(query, f"⚠️ Order Status Unknown\n\nPlease check your hosting dashboard.")
                
        except Exception as orchestrator_error:
            logger.error(f"❌ HANDLERS: Error during orchestrated hosting provisioning for intent {intent_id}: {orchestrator_error}")
            await safe_edit_message(query, f"❌ Provisioning Error\n\nAn error occurred during hosting setup. Please contact support.")
            
    except Exception as e:
        logger.error(f"Error in intent wallet payment: {e}")
        # Try to rollback intent status if possible
        try:
            # Only try to rollback if intent_id_int was successfully defined
            if 'intent_id' in locals() and intent_id:
                intent_id_int = int(intent_id)
                await update_hosting_intent_status(intent_id_int, 'pending_payment')
        except:
            pass
        await safe_edit_message(query, "❌ Payment processing error. Please try again.")

async def process_unified_crypto_payment(query, crypto_type: str, subscription_id: str, price: str):
    """Process crypto payment for unified hosting order with financial safety checks"""
    user = query.from_user
    
    # 🎯 INSTANT FEEDBACK: Show immediate crypto payment processing message
    crypto_name = crypto_type.upper()
    processing_msg = f"₿ <b>Setting up {crypto_name} Payment...</b>\n\n"
    processing_msg += f"💰 Amount: ${price}\n"
    processing_msg += f"📋 Order: #{subscription_id}\n"
    processing_msg += f"⏳ Generating payment address..."
    
    await safe_edit_message(query, processing_msg, parse_mode='HTML')
    
    try:
        # Convert price to float
        amount = float(price)
        
        # CRITICAL: Financial safety validation before any operations
        from database import verify_financial_operation_safety
        
        # Verify financial operation safety
        safety_check = verify_financial_operation_safety(
            f"Unified hosting crypto payment (User: {user.id}, Amount: ${amount:.2f}, Type: {crypto_type})", 
            amount
        )
        if not safety_check:
            logger.error(f"🚫 Financial safety check failed for user {user.id} crypto payment ${amount:.2f} ({crypto_type})")
            await safe_edit_message(query, "❌ Payment system temporarily unavailable. Please try again later.")
            return
        
        logger.info(f"✅ Financial safety check passed for unified crypto payment: User {user.id}, ${amount:.2f} ({crypto_type})")
        
        # Get user record for database ID
        from database import get_or_create_user
        user_record = await get_or_create_user(telegram_id=user.id)
        
        # Generate payment address
        logger.info(f"💰 Generating {crypto_type.upper()} payment address for unified hosting: User {user.id}, Amount ${amount:.2f}, Subscription #{subscription_id}")
        payment_result = await create_payment_address(
            currency=crypto_type,
            order_id=f"UH{subscription_id}",
            value=amount,
            user_id=user_record['id']
        )
        
        if not payment_result:
            await safe_edit_message(query, "❌ Error generating payment address. Please try again.")
            return
        
        payment_address = payment_result['address']
        order_id = payment_result.get('order_id', f"UH{subscription_id}")
        
        # Create QR code for payment
        qr = QRCode(version=1, box_size=10, border=5)
        qr.add_data(payment_address)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_buffer = BytesIO()
        qr_img.save(qr_buffer, format='PNG')
        qr_buffer.seek(0)
        
        # Crypto display names
        crypto_names = {
            'btc': 'Bitcoin (BTC)',
            'usdt': 'USDT (TRC20)',
            'eth': 'Ethereum (ETH)',
            'ltc': 'Litecoin (LTC)',
            'doge': 'Dogecoin (DOGE)'
        }
        
        crypto_name = crypto_names.get(crypto_type, crypto_type.upper())
        
        message = f"""
💰 <b>{crypto_name} Payment</b>

<b>Amount:</b> ${amount:.2f} • <b>Order:</b> #{order_id}

<b>📱 Address:</b>
<pre>{payment_address}</pre>

Send exact amount to address above.
Payment confirms automatically.

<i>💡 Tap the address above to copy it</i>
<i>⚠️ Send only {crypto_name}!</i>
"""
        
        keyboard = [
            [InlineKeyboardButton("🔄 Change Payment Method", callback_data=f"unified_checkout_review_{subscription_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send QR code with payment details
        await query.message.reply_photo(
            photo=qr_buffer,
            caption=message,
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        
        # Edit original message to show payment initiated
        await safe_edit_message(query, "💰 Crypto payment initiated. Check the QR code below ⬇️")
        
    except Exception as e:
        logger.error(f"Error processing unified crypto payment: {e}")
        await safe_edit_message(query, "❌ Error processing crypto payment. Please try again.")

async def create_unified_hosting_account_after_payment(subscription_id: int):
    """Create hosting account AND domain (if needed) after successful payment in unified flow"""
    try:
        # Get subscription details
        from database import get_hosting_subscription_details_admin, update_hosting_subscription_status
        
        subscription = await get_hosting_subscription_details_admin(subscription_id)  # Admin context
        if not subscription:
            logger.error(f"Subscription {subscription_id} not found for account creation")
            return
        
        domain_name = subscription.get('domain_name', '')
        plan_name = subscription.get('plan_name', 'Unknown')
        service_type = subscription.get('service_type', 'hosting_only')
        user_id = subscription.get('user_id')
        
        logger.info(f"🚀 Starting unified provisioning for subscription {subscription_id}: {service_type}, domain: {domain_name}")
        
        # Step 1: Handle domain registration for new domain bundles
        domain_registration_success = True
        if service_type == 'hosting_domain_bundle' and domain_name and '.' in domain_name:
            if not user_id:
                logger.error(f"❌ Missing user_id for subscription {subscription_id}, cannot register domain {domain_name}")
                await update_hosting_subscription_status(subscription_id, 'failed')
                return
                
            logger.info(f"📝 Registering new domain: {domain_name}")
            domain_registration_success = await register_unified_domain(
                domain_name=domain_name,
                user_id=user_id,
                subscription_id=subscription_id
            )
            
            if not domain_registration_success:
                logger.error(f"❌ Domain registration failed for {domain_name}, aborting provisioning")
                await update_hosting_subscription_status(subscription_id, 'failed')
                return
        
        # Step 2: Create hosting account via cPanel  
        from services.cpanel import CPanelService
        cpanel = CPanelService()
        logger.info(f"🏠 Creating hosting account for domain: {domain_name}")
        account_details = await cpanel.create_hosting_account(
            domain=domain_name,
            plan=plan_name,
            email=f"admin@{domain_name}" if domain_name and '.' in domain_name else "admin@example.com"
        )
        
        if account_details:
            # Step 3: Save cPanel account details
            from database import create_cpanel_account
            await create_cpanel_account(
                subscription_id=subscription_id,
                username=account_details['username'],
                domain=account_details['domain'],
                server_name=account_details.get('server_name', 'hostbay-server-01'),
                ip_address=account_details.get('server_ip', account_details.get('ip_address', ''))
            )
            
            # Step 4: Configure DNS for domains to point to hosting server
            if domain_name and '.' in domain_name:
                if not user_id:
                    logger.error(f"❌ Missing user_id for subscription {subscription_id}, cannot configure DNS for domain {domain_name}")
                else:
                    logger.info(f"🌐 Configuring DNS for domain: {domain_name}")
                    await configure_unified_domain_dns(domain_name, account_details, user_id)
            
            # Step 5: Update subscription status
            from database import update_hosting_subscription_status
            await update_hosting_subscription_status(subscription_id, 'active')
            
            # Step 6: Send notification to user
            await send_unified_hosting_notification(subscription, account_details, service_type)
            
            logger.info(f"✅ Unified provisioning completed successfully for subscription {subscription_id}")
        else:
            logger.error(f"❌ Failed to create hosting account for subscription {subscription_id}")
            await update_hosting_subscription_status(subscription_id, 'failed')
            
    except Exception as e:
        logger.error(f"Error in unified provisioning for subscription {subscription_id}: {e}")
        # Update status to failed
        try:
            from database import update_hosting_subscription_status
            await update_hosting_subscription_status(subscription_id, 'failed')
        except:
            pass

async def register_unified_domain(domain_name: str, user_id: int, subscription_id: int) -> bool:
    """Register a new domain as part of unified hosting provisioning - FIXED: Create Cloudflare zone FIRST for nameservers"""
    try:
        logger.info(f"🌐 Starting domain registration: {domain_name} for user {user_id}")
        
        # Step 1: Create Cloudflare DNS zone FIRST to get nameservers
        cloudflare = CloudflareService()
        
        # Create a temporary domain entry first for zone creation
        # This is needed because cloudflare.create_zone expects a domain_id
        intent_id = await create_registration_intent(
            user_id=user_id,
            domain_name=domain_name,
            estimated_price=0.0,
            payment_data={'type': 'hosting_bundle', 'status': 'pending_zone_creation'}
        )
        
        if not intent_id:
            logger.error(f"❌ Failed to create registration intent: {domain_name}")
            return False
        
        logger.info(f"🌐 Creating Cloudflare zone first to obtain nameservers for {domain_name}")
        zone_result = await cloudflare.create_zone(domain_name, standalone=True)
        
        nameservers = None
        if zone_result and zone_result.get('success'):
            nameservers = zone_result['result'].get('name_servers', [])
            logger.info(f"✅ Cloudflare zone created with nameservers: {nameservers}")
            
            # Save Cloudflare zone to database
            from database import save_cloudflare_zone
            await save_cloudflare_zone(
                domain_name=domain_name,
                cf_zone_id=zone_result['result']['id'],
                nameservers=nameservers,
                status='active'
            )
        else:
            logger.error(f"❌ Failed to create Cloudflare zone for {domain_name}")
            # Clean up intent and return failure
            await update_intent_status(intent_id, 'failed')
            return False
        
        # Step 2: Register domain via OpenProvider WITH the Cloudflare nameservers
        from services.openprovider import OpenProviderService
        openprovider = OpenProviderService()
        
        # Verify method availability
        if not hasattr(openprovider, 'register_domain'):
            logger.error(f"❌ OpenProvider service missing register_domain method")
            logger.error(f"   Instance type: {type(openprovider)}")
            logger.error(f"   Available methods: {[method for method in dir(openprovider) if not method.startswith('_')]}")
            await update_intent_status(intent_id, 'failed')
            return False
        
        logger.info(f"🌐 Registering domain {domain_name} with nameservers: {nameservers}")
        
        # Get or create a valid contact handle
        contact_handle = await openprovider.get_or_create_contact_handle()
        if not contact_handle:
            logger.error(f"❌ Failed to get valid contact handle for domain registration: {domain_name}")
            return False
        
        logger.info(f"✅ Using contact handle: {contact_handle}")
        registration_result = await openprovider.register_domain(
            domain_name=domain_name,
            contact_handle=contact_handle,
            nameservers=nameservers  # Now using actual Cloudflare nameservers!
        )
        
        if not registration_result or not registration_result.get('success'):
            logger.error(f"❌ Domain registration failed via OpenProvider: {domain_name}")
            await update_intent_status(intent_id, 'failed')
            return False
        
        # Step 3: Finalize domain registration in database
        await update_intent_status(intent_id, 'completed', registration_result)
        provider_domain_id = registration_result.get('domain_id')
        
        if provider_domain_id:
            domain_saved = await finalize_domain_registration(
                intent_id=intent_id,
                provider_domain_id=str(provider_domain_id)
            )
            
            if not domain_saved:
                logger.error(f"❌ Failed to finalize domain registration: {domain_name}")
                return False
        else:
            logger.error(f"❌ No provider domain ID returned for {domain_name}")
            return False
        
        logger.info(f"✅ Domain registration completed successfully: {domain_name} with proper nameservers")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error registering unified domain {domain_name}: {e}")
        return False

async def configure_unified_domain_dns(domain_name: str, account_details: Dict, user_id: int):
    """Configure DNS for domains to point to our hosting server"""
    try:
        logger.info(f"🔧 Configuring DNS for domain: {domain_name}")
        
        # Check if domain uses Cloudflare and is accessible
        domain_status = await analyze_domain_status(domain_name, user_id)
        
        if domain_status.get('has_cloudflare') and domain_status.get('auto_dns_possible'):
            # Domain uses Cloudflare and we can manage it
            cloudflare = CloudflareService()
            cf_zone = await get_cloudflare_zone(domain_name)
            
            if cf_zone:
                zone_id = cf_zone['cf_zone_id']
                server_ip = account_details.get('server_ip')
                
                if server_ip:
                    # Get existing A records to update them instead of creating duplicates
                    existing_records = await cloudflare.list_dns_records(zone_id, record_type='A')
                    records_updated = 0
                    
                    # Process root domain '@' A record
                    root_record = None
                    www_record = None
                    
                    for record in existing_records:
                        record_name = record.get('name', '')
                        # Handle both '@' and the full domain name for root records
                        if record_name == '@' or record_name == domain_name:
                            root_record = record
                        elif record_name == f'www.{domain_name}' or record_name == 'www':
                            www_record = record
                    
                    # Update or create root domain A record
                    if root_record:
                        # Update existing root A record
                        result = await cloudflare.update_dns_record(
                            zone_id=zone_id,
                            record_id=root_record['id'],
                            record_type='A',
                            name='@',
                            content=server_ip,
                            ttl=300
                        )
                        if result.get('success'):
                            old_ip = root_record.get('content', 'unknown')
                            logger.info(f"✅ Updated root A record: {old_ip} -> {server_ip}")
                            records_updated += 1
                        else:
                            logger.warning(f"⚠️ Failed to update root A record: {result.get('errors', [])}")
                    else:
                        # Create new root A record
                        result = await cloudflare.create_dns_record(
                            zone_id=zone_id,
                            record_type='A',
                            name='@',
                            content=server_ip,
                            ttl=300
                        )
                        if result.get('success'):
                            logger.info(f"✅ Created root A record -> {server_ip}")
                            records_updated += 1
                        else:
                            logger.warning(f"⚠️ Failed to create root A record: {result.get('errors', [])}")
                    
                    # Update or create www subdomain A record  
                    if www_record:
                        # Update existing www A record
                        result = await cloudflare.update_dns_record(
                            zone_id=zone_id,
                            record_id=www_record['id'],
                            record_type='A',
                            name='www',
                            content=server_ip,
                            ttl=300
                        )
                        if result.get('success'):
                            old_ip = www_record.get('content', 'unknown')
                            logger.info(f"✅ Updated www A record: {old_ip} -> {server_ip}")
                            records_updated += 1
                        else:
                            logger.warning(f"⚠️ Failed to update www A record: {result.get('errors', [])}")
                    else:
                        # Create new www A record
                        result = await cloudflare.create_dns_record(
                            zone_id=zone_id,
                            record_type='A',
                            name='www',
                            content=server_ip,
                            ttl=300
                        )
                        if result.get('success'):
                            logger.info(f"✅ Created www A record -> {server_ip}")
                            records_updated += 1
                        else:
                            logger.warning(f"⚠️ Failed to create www A record: {result.get('errors', [])}")
                    
                    logger.info(f"✅ DNS configuration completed for {domain_name}: {records_updated} A records updated/created -> {server_ip}")
                else:
                    logger.warning(f"⚠️ No server IP available for DNS configuration of {domain_name}")
            else:
                logger.warning(f"⚠️ Cloudflare zone not found for {domain_name}")
        else:
            logger.info(f"ℹ️ Domain {domain_name} requires manual DNS configuration (not using Cloudflare or not accessible)")
        
    except Exception as e:
        logger.error(f"❌ Error configuring DNS for {domain_name}: {e}")

async def send_unified_hosting_notification(subscription: Dict, account_details: Dict, service_type: str = 'hosting_only'):
    """Send hosting account notification for unified flow"""
    try:
        user_id = subscription.get('user_id')
        domain_name = subscription.get('domain_name', '')
        plan_name = subscription.get('plan_name', 'Unknown')
        
        if not user_id:
            logger.error("No user_id in subscription for notification")
            return
        
        # Get user's Telegram ID
        from database import execute_query
        user_records = await execute_query("SELECT telegram_id FROM users WHERE id = %s", (user_id,))
        
        if not user_records:
            logger.error(f"User {user_id} not found for notification")
            return
        
        telegram_id = user_records[0]['telegram_id']
        
        message = f"""🎉 <b>Hosting Account Ready!</b>

<b>Plan:</b> {plan_name}
<b>Domain:</b> {domain_name}
<b>Status:</b> ✅ Active

<b>🔐 cPanel Access:</b>
<b>Username:</b> <code>{account_details['username']}</code>
<b>Password:</b> <code>{account_details['password']}</code>
<b>Login URL:</b> https://{domain_name}:2083

<b>🌐 Nameservers:</b>
{chr(10).join([f'• {ns}' for ns in account_details.get('nameservers', [])])}

<b>🚀 Next Steps:</b>
1. Update your domain's nameservers (if needed)
2. Upload your website files via cPanel
3. Configure email accounts
4. Install SSL certificate (free with your plan)

Welcome to professional hosting! 🏠"""
        
        keyboard = [
            [InlineKeyboardButton("⚙️ Manage Hosting", callback_data=f"manage_hosting_{subscription['id']}")],
            [InlineKeyboardButton("🏠 My Hosting", callback_data="my_hosting")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send notification via Telegram bot
        from telegram import Bot
        bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not bot_token:
            logger.error("TELEGRAM_BOT_TOKEN not found in environment")
            return
        bot = Bot(token=bot_token)
        await bot.send_message(
            chat_id=telegram_id,
            text=message,
            reply_markup=reply_markup,
            parse_mode='HTML'
        )
        
        logger.info(f"✅ Hosting notification sent to user {telegram_id}")
        
    except Exception as e:
        logger.error(f"Error sending unified hosting notification: {e}")

# TEXT INPUT HANDLING FOR UNIFIED FLOW
# ================================================================

async def handle_unified_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_text: str):
    """Handle text input for unified hosting flow"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        return
    
    # Check if context.user_data exists
    if not hasattr(context, 'user_data') or context.user_data is None:
        return
        
    unified_flow = context.user_data.get('unified_flow')
    plan_id = context.user_data.get('unified_plan_id')
    
    if not unified_flow or not plan_id:
        return  # Not in unified flow
    
    # Define DummyQuery class at function scope for both flows to access
    class DummyQuery:
        def __init__(self, user, message):
            self.from_user = user
            self.message = message
            self.data = None
        
        async def edit_message_text(self, text, reply_markup=None, parse_mode='HTML'):
            """Send new message for text input compatibility (user messages can't be edited)"""
            await self.message.reply_text(text, reply_markup=reply_markup, parse_mode=parse_mode)
    
    try:
        domain_name = domain_text.lower().strip()
        
        # Basic validation
        if not is_valid_domain(domain_name):
            await message.reply_text(
                f"❌ Invalid domain format: {domain_name}\n\n"
                "Please enter a valid domain name (e.g., mywebsite.com)",
                parse_mode=ParseMode.HTML
            )
            return
        
        if unified_flow == 'awaiting_new_domain':
            # Handle new domain registration with immediate feedback
            analyzing_msg = await message.reply_text(
                f"🔄 Checking {domain_name}...",
                parse_mode=ParseMode.HTML
            )
            
            plans = cpanel.get_hosting_plans()
            plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
            
            if plan:
                # Use the DummyQuery class defined at function scope
                dummy_query = DummyQuery(user, message)
                await handle_new_domain_hosting(dummy_query, context, plan_id, domain_name, plan)
                
        elif unified_flow == 'awaiting_existing_domain':
            # Handle existing domain connection with immediate feedback
            analyzing_msg = await message.reply_text(
                f"🔄 <b>Analyzing {domain_name}...</b>\n\n"
                "• Checking domain status\n"
                "• Verifying DNS records\n"
                "• Getting hosting compatibility",
                parse_mode=ParseMode.HTML
            )
            
            user_record = await get_or_create_user_with_status(user.id) 
            domain_status = await analyze_domain_status(domain_name, user_record['id'])
            
            # Use the DummyQuery class defined at function scope
            dummy_query = DummyQuery(user, message)
            await handle_existing_domain_hosting(dummy_query, context, plan_id, domain_name, domain_status)
        
        # Clear flow state (with safety check)
        if hasattr(context, 'user_data') and context.user_data is not None:
            context.user_data.pop('unified_flow', None)
            context.user_data.pop('unified_plan_id', None)
        
        logger.info(f"Unified flow text input processed: {domain_name} for plan {plan_id}")
        
    except Exception as e:
        logger.error(f"Error handling unified text input: {e}")
        await message.reply_text("❌ Error processing domain. Please try again.")

# BACKWARDS COMPATIBILITY LAYER
# ================================================================

# Hosting interface functions
async def show_hosting_interface(query):
    """Show hosting interface - UNIFIED VERSION"""
    # Redirect to new unified flow
    await unified_hosting_flow(query)

async def show_hosting_plans(query):
    """Show all available hosting plans"""
    plans = cpanel.get_hosting_plans()
    
    message = "🏠 Plans\n\nChoose:\n\n"
    keyboard = []
    
    for plan in plans:
        period_price = plan.get('period_price', plan.get('monthly_price', 0))
        display_price = plan.get('display_price', f"{period_price}/month")
        disk = plan.get('disk_space_gb', 0)
        plan_name = plan.get('plan_name', '')
        
        # Add plan summary to message
        message += f"{plan_name} - ${display_price}\n"
        message += f"📊 {disk}GB Storage • {plan.get('databases', 0)} Databases\n\n"
        
        # Add plan selection button
        keyboard.append([InlineKeyboardButton(
            f"📋 {plan_name} Plan - ${display_price}", 
            callback_data=f"select_plan_{plan.get('id', '')}"
        )])
    
    keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data="hosting_main")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_my_hosting(query):
    """Show user's hosting subscriptions"""
    user = query.from_user
    
    try:
        # Import database functions
        from database import get_or_create_user, get_user_hosting_subscriptions
        
        # Get user from database
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Get user's hosting subscriptions
        subscriptions = await get_user_hosting_subscriptions(db_user['id'])
        
        if not subscriptions:
            message = "🏠 My Hosting\n\nNo hosting yet"
            keyboard = [
                [InlineKeyboardButton("📋 Plans", callback_data="hosting_plans")],
                [InlineKeyboardButton("⬅️ Back", callback_data="hosting_main")]
            ]
        else:
            message = f"🏠 My Hosting ({len(subscriptions)} active)\n\n"
            keyboard = []
            
            for sub in subscriptions[:10]:
                plan_name = sub.get('plan_name', 'Unknown')
                domain = sub.get('domain_name', 'No domain')
                status = sub.get('status', 'unknown')
                
                # Add status indicator
                if status == 'active':
                    indicator = "🟢"
                elif status == 'pending':
                    indicator = "🟡"
                else:
                    indicator = "🔴"
                
                message += f"{indicator} {plan_name} - {domain}\n"
                message += f"Status: {status.title()}\n\n"
                
                keyboard.append([InlineKeyboardButton(
                    f"⚙️ Manage {domain}", 
                    callback_data=f"manage_hosting_{sub['id']}"
                )])
            
            keyboard.append([InlineKeyboardButton("📋 Add New Hosting", callback_data="hosting_plans")])
            keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data="hosting_main")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing user hosting: {e}")
        await safe_edit_message(query, "❌ Error loading hosting information. Please try again.")

async def show_plan_details(query, plan_id):
    """Show detailed information about a hosting plan"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        message = cpanel.format_hosting_plan(plan)
        
        keyboard = [
            [InlineKeyboardButton(f"🛒 Purchase {plan.get('plan_name', '')} Plan", callback_data=f"purchase_plan_{plan_id}")],
            [InlineKeyboardButton("⬅️ Back to Plans", callback_data="hosting_plans")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing plan details: {e}")
        await safe_edit_message(query, "❌ Error loading plan details. Please try again.")

async def start_hosting_purchase(query, plan_id):
    """Start the hosting plan purchase process"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""
🛒 Purchase {plan_name} Plan

Plan: {plan_name}
Price: ${monthly_price}/month
Setup: Instant provisioning
Payment: Cryptocurrency

Next: Choose your domain option
"""
        
        keyboard = [
            [InlineKeyboardButton(f"✅ Continue with {plan_name}", callback_data=f"collect_domain_{plan_id}")],
            [InlineKeyboardButton("⬅️ Back to Plan Details", callback_data=f"select_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error starting hosting purchase: {e}")
        await safe_edit_message(query, "❌ Error processing purchase. Please try again.")

async def collect_hosting_domain(query, context, plan_id):
    """Collect domain information for hosting plan purchase"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""
🌐 Domain for {plan_name} Plan

Choose your domain option:

🆕 Register New Domain
• Search and register a new domain
• Automatic DNS setup
• Includes domain + hosting

🔗 Use Existing Domain  
• Connect your existing domain
• Manual DNS configuration required
• Hosting only

Plan: {plan_name} (${monthly_price}/month)
"""
        
        keyboard = [
            [InlineKeyboardButton("🆕 Register New Domain", callback_data=f"hosting_new_domain_{plan_id}")],
            [InlineKeyboardButton("🔗 Use Existing Domain", callback_data=f"hosting_existing_domain_{plan_id}")],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"purchase_plan_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error collecting hosting domain: {e}")
        await safe_edit_message(query, "❌ Error processing domain selection. Please try again.")

async def start_hosting_domain_search(query, context, plan_id):
    """Start domain search for hosting package"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""
🆕 Register New Domain + {plan_name} Hosting

Search for an available domain to register with your hosting package.

Domain + Hosting Bundle:
• Domain registration 
• {plan_name} hosting plan (${monthly_price}/month)
• Automatic DNS setup
• Instant provisioning

Enter domain name to search:
"""
        
        # Store plan information in context for text input handling
        context.user_data['hosting_plan_id'] = plan_id
        context.user_data['hosting_flow'] = 'awaiting_new_domain'
        context.user_data['plan_name'] = plan_name
        context.user_data['plan_price'] = monthly_price
        
        keyboard = [
            [InlineKeyboardButton("⬅️ Back to Domain Options", callback_data=f"collect_domain_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        logger.info(f"User {query.from_user.id} starting domain search for hosting plan {plan_id} - awaiting text input")
        
    except Exception as e:
        logger.error(f"Error starting hosting domain search: {e}")
        await safe_edit_message(query, "❌ Error starting domain search. Please try again.")

async def request_existing_domain(query, context, plan_id):
    """Request existing domain for hosting package"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', 'Unknown')
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""
🔗 Connect Existing Domain + {plan_name} Hosting

Connect your existing domain to the {plan_name} hosting plan.

What you'll need:
• Your existing domain name
• Access to domain DNS settings
• Manual nameserver update required

Hosting Plan: {plan_name} (${monthly_price}/month)

Enter your existing domain name:
"""
        
        # Store plan information in context for text input handling
        context.user_data['hosting_plan_id'] = plan_id
        context.user_data['hosting_flow'] = 'awaiting_existing_domain'
        context.user_data['plan_name'] = plan_name
        context.user_data['plan_price'] = monthly_price
        
        keyboard = [
            [InlineKeyboardButton("⬅️ Back to Domain Options", callback_data=f"collect_domain_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        logger.info(f"User {query.from_user.id} requesting existing domain for hosting plan {plan_id} - awaiting text input")
        
    except Exception as e:
        logger.error(f"Error requesting existing domain: {e}")
        await safe_edit_message(query, "❌ Error processing existing domain request. Please try again.")

async def handle_hosting_domain_input(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_text: str):
    """Handle domain input for hosting plan purchase"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        return
    
    try:
        # Get hosting flow context
        user_data = context.user_data or {}
        hosting_flow = user_data.get('hosting_flow')
        plan_id = user_data.get('hosting_plan_id')
        plan_name = user_data.get('plan_name', 'Unknown')
        plan_price = user_data.get('plan_price', 0)
        
        if not plan_id or not hosting_flow:
            await message.reply_text("❌ Session expired. Please start the hosting purchase again.")
            return
        
        # Validate domain format
        domain_name = domain_text.lower().strip()
        if not is_valid_domain(domain_name):
            await message.reply_text(
                f"❌ Invalid domain format: {domain_text}\n\nPlease enter a valid domain name (e.g., mywebsite.com)"
            )
            return
        
        if hosting_flow == 'awaiting_new_domain':
            # Handle new domain registration with hosting
            await handle_new_domain_with_hosting(update, context, domain_name, plan_id, plan_name, plan_price)
        elif hosting_flow == 'awaiting_existing_domain':
            # Handle existing domain with hosting
            await handle_existing_domain_with_hosting(update, context, domain_name, plan_id, plan_name, plan_price)
        
        # Clear hosting flow context safely
        if context.user_data:
            context.user_data.pop('hosting_flow', None)
            context.user_data.pop('hosting_plan_id', None)
            context.user_data.pop('plan_name', None) 
            context.user_data.pop('plan_price', None)
        
    except Exception as e:
        logger.error(f"Error handling hosting domain input: {e}")
        if message:
            await message.reply_text("❌ Error processing domain input. Please try again.")

async def handle_new_domain_with_hosting(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_name: str, plan_id: str, plan_name: str, plan_price: float):
    """Handle new domain registration with hosting bundle"""
    message = update.effective_message
    
    try:
        # Check domain availability using existing OpenProvider integration
        from services.openprovider import OpenProviderService
        openprovider = OpenProviderService()
        
        # Show searching message
        if not message:
            logger.error("No message object available for domain search")
            return
        searching_msg = await message.reply_text(f"🔄 Checking {domain_name}...")
        
        availability = await openprovider.check_domain_availability(domain_name)
        
        if availability is None:
            await searching_msg.edit_text(f"⚠️ Domain search unavailable: {domain_name}\n\nService temporarily down. Please try again later.")
            return
        
        if availability.get('available'):
            # Domain is available - show bundle pricing
            price_info = availability.get('price_info', {})
            domain_price = price_info.get('create_price', 0)
            total_price = domain_price + plan_price
            
            message_text = f"""
✅ Domain Available: {domain_name}

🎉 Bundle Package:
• Domain: {domain_name} - {format_money(domain_price, 'USD', include_currency=True)}/year
• Hosting: {plan_name} - ${plan_price}/month
• Total: {format_money(total_price, 'USD', include_currency=True)} + ${plan_price}/month

⚡ Instant setup with automatic DNS configuration

Ready to proceed?
"""
            
            keyboard = [
                [InlineKeyboardButton(f"✅ Purchase Bundle - {format_money(total_price, 'USD', include_currency=True)}", callback_data=f"confirm_hosting_bundle_{plan_id}:{domain_name}")],
                [InlineKeyboardButton("⬅️ Back to Domain Options", callback_data=f"collect_domain_{plan_id}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await searching_msg.edit_text(message_text, reply_markup=reply_markup)
        else:
            # Domain not available
            await searching_msg.edit_text(
                f"❌ Domain Unavailable: {domain_name}\n\nThis domain is already taken. Please try another domain name."
            )
    
    except Exception as e:
        logger.error(f"Error handling new domain with hosting: {e}")
        if message:
            await message.reply_text("❌ Error checking domain availability. Please try again.")

async def handle_existing_domain_with_hosting(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_name: str, plan_id: str, plan_name: str, plan_price: float):
    """Handle existing domain with hosting plan including nameserver automation"""
    message = update.effective_message
    
    try:
        checking_msg = None
        # Show checking message
        if message:
            checking_msg = await message.reply_text(f"🔍 Analyzing nameserver configuration for {domain_name}...")
        
        # Detect current nameserver configuration
        nameserver_analysis = await analyze_domain_nameservers(domain_name)
        
        # Generate nameserver setup guidance
        setup_guidance = await generate_hosting_nameserver_guidance(domain_name, nameserver_analysis, plan_name)
        
        message_text = f"""
🔗 Connect Existing Domain: {domain_name}

Hosting Plan:
• Plan: {plan_name}
• Price: ${plan_price}/month
• Domain: {domain_name} (your existing domain)

{setup_guidance}

Ready to proceed with {plan_name} hosting?
"""
        
        keyboard = [
            [InlineKeyboardButton(f"✅ Purchase Hosting - ${plan_price}/month", callback_data=f"confirm_hosting_existing_{plan_id}:{domain_name}")],
            [InlineKeyboardButton("🔍 Check Nameservers Again", callback_data=f"recheck_ns_{plan_id}:{domain_name}")],
            [InlineKeyboardButton("⬅️ Back to Domain Options", callback_data=f"collect_domain_{plan_id}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if message and checking_msg:
            # Edit the checking message with results
            await checking_msg.edit_text(message_text, reply_markup=reply_markup)
    
    except Exception as e:
        logger.error(f"Error handling existing domain with hosting: {e}")
        if message:
            await message.reply_text("❌ Error processing existing domain. Please try again.")

async def confirm_hosting_purchase(query, plan_id, domain_name=None):
    """Handle hosting plan purchase confirmation using intent system to prevent duplicates"""
    user = query.from_user
    
    try:
        # Get user and plan details
        db_user = await get_or_create_user(telegram_id=user.id)
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        monthly_price = plan.get('monthly_price', 0)
        
        # Use provided domain or fallback to pending
        hosting_domain = domain_name if domain_name else 'pending-domain'
        
        # Check for existing active hosting intent for this domain
        existing_intent = await get_active_hosting_intent(db_user['id'], hosting_domain)
        if existing_intent:
            logger.info(f"⚠️ Active hosting intent {existing_intent['id']} already exists for {hosting_domain}")
            
            # Check if this is the same plan
            if existing_intent['hosting_plan_id'] == plan.get('id'):
                # Show payment options for existing intent
                intent_id = existing_intent['id']
                await show_hosting_payment_options_with_intent(query, intent_id, monthly_price, plan_name, hosting_domain)
                return
            else:
                # Different plan requested - inform user
                await safe_edit_message(query, f"""
⚠️ Hosting Order Already in Progress

You already have a hosting order in progress for domain: {hosting_domain}

Please complete or cancel your existing order before starting a new one.
""")
                return
        
        # Create hosting provision intent to prevent duplicate accounts
        intent_id = await create_hosting_intent(
            user_id=db_user['id'],
            domain_name=hosting_domain,
            hosting_plan_id=plan.get('id'),
            estimated_price=monthly_price,
            service_type='hosting_only'  # Single hosting plan without domain bundle
        )
        
        if intent_id:
            # Show payment options for the new intent
            await show_hosting_payment_options_with_intent(query, intent_id, monthly_price, plan_name, hosting_domain)
            logger.info(f"✅ Hosting provision intent {intent_id} created: User {user.id}, Plan {plan_name}, Domain {hosting_domain}")
            return
        else:
            # Intent creation failed
            message = f"""
⚠️ Order Issue - {plan_name}

There was an issue creating your hosting order. This may be due to:
• Duplicate order prevention 
• Database connectivity issue

Plan Details:
• Plan: {plan_name}
• Price: ${monthly_price}/month
• Domain: {hosting_domain}

Please try again or contact {BrandConfig().support_contact} if the issue persists.
"""
            keyboard = [
                [InlineKeyboardButton("🔄 Try Again", callback_data=f"confirm_purchase_{plan_id}")],
                [InlineKeyboardButton("⬅️ Back to Plans", callback_data="hosting_plans")]
            ]
            
            logger.error(f"❌ Failed to create hosting provision intent: User {user.id}, Plan {plan_name}, Domain {hosting_domain}")
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error confirming hosting purchase: {e}")
        await safe_edit_message(query, "❌ Error processing purchase confirmation. Please try again.")

async def handle_notify_ready(query, plan_id):
    """Handle notification request when payment is ready"""
    user = query.from_user
    
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Plan not found.")
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        
        message = f"""
📧 Notification Registered

You'll be notified when cryptocurrency payment processing is available for the {plan_name} plan.

Status:
• Plan: {plan_name}
• Notification: ✅ Registered
• Payment: 🔄 Coming soon

What to expect:
• Direct message when payment is ready
• Multiple cryptocurrency options
• Automatic account provisioning
• Full setup instructions

Thank you for your interest in our hosting services!
"""
        
        keyboard = [
            [InlineKeyboardButton("🏠 View My Orders", callback_data="my_hosting")],
            [InlineKeyboardButton("📋 Browse Plans", callback_data="hosting_plans")],
            [InlineKeyboardButton("📱 Main Menu", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Log notification request
        logger.info(f"📧 Notification requested: User {user.id} for plan {plan_name}")
        
    except Exception as e:
        logger.error(f"Error handling notify ready: {e}")
        await safe_edit_message(query, "❌ Error registering notification. Please try again.")

# Placeholder functions for missing handlers
async def start_domain_registration(query, domain_name):
    """Phase 2: User Profile Management & Payment Processing"""
    user = query.from_user
    
    try:
        # Get or create user in database
        user_record = await get_or_create_user(
            telegram_id=user.id,
            username=user.username,
            first_name=user.first_name,
            last_name=user.last_name
        )
        
        # Double-check domain availability 
        await safe_edit_message(query, f"🔄 Checking {domain_name}...")
        
        availability = await openprovider.check_domain_availability(domain_name)
        if not availability or not availability.get('available'):
            await safe_edit_message(query, f"❌ Domain Unavailable\n\n{domain_name} is not available for registration.")
            return
        
        # Get pricing
        price_info = availability.get('price_info', {})
        create_price = price_info.get('create_price', 0)
        currency = price_info.get('currency', 'USD')
        
        if create_price <= 0:
            await safe_edit_message(query, f"❌ Pricing Error\n\nCould not determine pricing for {domain_name}. Please try again.")
            return
        
        # Phase 2: Use shared contact system (no user input needed)
        # Skip individual contact collection, go straight to payment
        
        # Phase 3: Payment Processing - Show crypto options
        await show_payment_options(query, domain_name, create_price, currency)
        
    except Exception as e:
        logger.error(f"Error starting domain registration for {domain_name}: {e}")
        await safe_edit_message(query, f"❌ Error\n\nAn error occurred. Please try again.")

async def show_payment_options(query, domain_name, price, currency):
    """Phase 3: Payment Processing - Show all payment options"""
    user = query.from_user
    
    try:
        user_record = await get_or_create_user(user.id)
        wallet_balance = await get_user_wallet_balance(user.id)
        
        # Check if user has sufficient wallet balance
        has_sufficient_balance = wallet_balance >= float(price)
        
        message = f"""
💰 Payment Required

Domain: {domain_name}
Price: ${price} {currency}
Your Wallet Balance: {format_money(wallet_balance, 'USD', include_currency=True)}

Choose your payment method:
"""
        
        keyboard = []
        
        # Wallet balance payment option (only if sufficient balance)
        if has_sufficient_balance:
            keyboard.append([InlineKeyboardButton(f"💳 Pay with Wallet - ${price}", callback_data=f"pay_wallet_{domain_name}_{price}_{currency}")])
        else:
            keyboard.append([InlineKeyboardButton("💳 Insufficient Balance (Add Funds)", callback_data="wallet_deposit")])
        
        # Cryptocurrency payment options using unified config
        for display_text, callback_suffix, icon in crypto_config.get_payment_button_data():
            keyboard.append([InlineKeyboardButton(
                f"{display_text}", 
                callback_data=f"pay_{callback_suffix}_{domain_name}_{price}_{currency}"
            )])
        
        keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data="search_domains")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing payment options: {e}")
        
        # Enhanced error handling for network timeouts vs other errors
        if "ReadError" in str(e) or "NetworkError" in str(e) or "httpx" in str(e):
            logger.info("🔄 Network timeout in payment options - retrying...")
            try:
                # Retry payment options with simplified message on network timeout
                simplified_message = f"""
Payment Required

Domain: {domain_name}
Price: ${price} {currency}

Payment options available. Retrying...
"""
                keyboard = [[InlineKeyboardButton("Retry Payment Options", callback_data=f"register_{domain_name}")]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await safe_edit_message(query, simplified_message, reply_markup=reply_markup)
                return
            except Exception as retry_error:
                logger.debug(f"Retry also failed: {retry_error}")
        
        await safe_edit_message(query, "Error\n\nCould not load payment options.\n\nPlease try again.")

async def process_crypto_payment(query, crypto_type, domain_name, price, currency):
    """Generate BlockBee payment invoice"""
    user = query.from_user
    
    try:
        # 🎯 ENHANCED PROGRESS: Show detailed crypto payment setup
        progress_msg = f"₿ <b>Setting up {crypto_type.upper()} Payment...</b>\n\n"
        progress_msg += f"🌐 Domain: <code>{domain_name}</code>\n"
        progress_msg += f"💰 Amount: ${price}\n"
        progress_msg += f"🔄 Connecting to payment provider...\n"
        progress_msg += "⏳ This may take a few seconds..."
        
        await safe_edit_message(query, progress_msg, parse_mode='HTML')
        
        # Step 1: Get user record FIRST to get database ID
        user_record = await get_or_create_user(user.id)
        
        # Generate payment with configured provider (DynoPay/BlockBee)
        order_id = f"domain_{domain_name}_{user.id}_{int(time.time())}"
        payment_result = await create_payment_address(
            currency=crypto_type.lower(),
            order_id=order_id,
            value=float(price),
            user_id=user_record['id']
        )
        
        if not payment_result:
            await safe_edit_message(query, "Payment Error\n\nCould not generate payment address. Please try again.")
            return
        intent_id = await create_registration_intent(
            user_id=user_record['id'],
            domain_name=domain_name,
            estimated_price=float(price),
            payment_data={
                'order_id': order_id,
                'payment_address': payment_result['address'],
                'currency': currency,
                'crypto_type': crypto_type,
                'provider': payment_result.get('provider', 'unknown')
            }
        )
        
        if not intent_id:
            await safe_edit_message(query, "Registration Error\n\nCould not create registration intent. Please try again.")
            return
        
        # Step 2: Save domain order to database and get auto-generated integer ID
        order_results = await execute_query(
            "INSERT INTO domain_orders (user_id, domain_name, status, payment_address, expected_amount, currency, blockbee_order_id, intent_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (user_record['id'], domain_name, 'pending_payment', payment_result['address'], price, currency, order_id, intent_id)
        )
        
        if not order_results:
            await safe_edit_message(query, "Order Error\n\nCould not create domain order. Please try again.")
            return
        
        # Get the actual integer order ID from database
        integer_order_id = order_results[0]['id']
        logger.info(f"✅ Created domain order with integer ID: {integer_order_id} (tracking ID: {order_id})")
        
        # Step 3: Update intent status to payment_pending
        await update_intent_status(intent_id, 'payment_pending', {
            'payment_address': payment_result['address'],
            'order_id': integer_order_id,  # Use integer order ID, not string tracking ID
            'tracking_id': order_id  # Keep string for tracking purposes
        })
        
        # Show payment instructions with copy functionality
        crypto_amount_display = payment_result.get('crypto_amount', 'TBD')
        amount_text = f"{price} {currency}"
        if crypto_amount_display != 'TBD':
            amount_text += f" (≈ {crypto_amount_display} {crypto_type.upper()})"
        
        # Use the new copy-friendly formatter with QR code support
        payment_message, copy_keyboard = render_crypto_payment(
            address=payment_result['address'],
            crypto_name=f"{crypto_type.upper()}",
            amount=amount_text,
            order_id=integer_order_id,  # Use integer order ID for payment display
            expires_minutes=15
        )
        
        # Add domain context and additional action buttons
        # Check if this is a hosting bundle order
        from database import get_active_hosting_intent
        hosting_intent = await get_active_hosting_intent(user_record['id'], domain_name)
        
        if hosting_intent:
            # This is a hosting bundle - domain + hosting
            domain_info = f"\n📦 <b>Hosting + Domain Bundle:</b> {escape_html(domain_name)}\n\nOnce payment is received, your hosting and domain will be automatically provisioned!"
        else:
            # This is domain-only registration
            domain_info = f"\n🌐 <b>Domain:</b> {escape_html(domain_name)}\n\nOnce payment is received, your domain will be automatically registered!"
        
        payment_message += domain_info
        
        additional_buttons = [
            [InlineKeyboardButton("🔄 Change Payment Method", callback_data=f"register_{domain_name}")],
            [InlineKeyboardButton("❌ Cancel Order", callback_data="search_domains")],
            [InlineKeyboardButton("⬅️ Back to Domains", callback_data="my_domains")]
        ]
        
        # Combine copy buttons with action buttons
        combined_keyboard = list(copy_keyboard.inline_keyboard) + additional_buttons
        final_keyboard = InlineKeyboardMarkup(combined_keyboard)
        
        await safe_edit_message(query, payment_message, reply_markup=final_keyboard, parse_mode='HTML')
        
        logger.info(f"Payment invoice generated for {domain_name}: {payment_result['address']}")
        
    except Exception as e:
        logger.error(f"Error processing crypto payment: {e}")
        await safe_edit_message(query, "Payment Error\n\nCould not process payment. Please try again.")

# Removed check_payment_status function - payments are now processed automatically via webhooks

async def process_domain_registration(query, domain_name, order):
    """Phase 5-7: Complete domain registration after payment confirmation - ORCHESTRATOR VERSION"""
    try:
        logger.info(f"🎯 HANDLERS: Routing domain registration through orchestrator for {domain_name}")
        
        # Get user record for orchestrator
        user_record = await get_or_create_user(query.from_user.id)
        
        # Create a query adapter for the orchestrator (similar to webhook adapter)
        class HandlerQueryAdapter:
            def __init__(self, query):
                self.query = query
                self.user_id = user_record['id']
                
            async def send_message_to_user(self, text, reply_markup=None, parse_mode='HTML'):
                """Send message via telegram query interface with HTML formatting"""
                await safe_edit_message(self.query, text, reply_markup)
        
        query_adapter = HandlerQueryAdapter(query)
        
        # Create payment details for wallet payments to show correct amount in success message
        wallet_payment_details = {
            'amount_usd': order.get('expected_amount', 0),
            'currency': 'USD',
            'payment_method': 'wallet'
        }
        
        # Route through centralized orchestrator
        orchestrator_result = await orchestrator_start_registration(
            order_id=order.get('id'),
            user_id=user_record['id'],
            domain_name=domain_name,
            payment_details=wallet_payment_details,  # Include wallet payment details for success message
            query_adapter=query_adapter
        )
        
        # Handle orchestrator results
        if orchestrator_result.get('status') == 'already_processed':
            logger.info(f"🚫 HANDLERS: Domain registration already processed for {domain_name}")
            await safe_edit_message(query, f"ℹ️ Registration Already Complete\n\nDomain {domain_name} has already been processed.")
            return
        
        elif orchestrator_result.get('status') == 'duplicate_prevented':
            logger.info(f"🚫 HANDLERS: Duplicate domain registration prevented for {domain_name}")
            await safe_edit_message(query, f"ℹ️ Registration In Progress\n\nDomain {domain_name} is already being processed.")
            return
        
        elif orchestrator_result.get('status') == 'error':
            logger.error(f"❌ HANDLERS: Orchestrator error for {domain_name}: {orchestrator_result.get('error', 'Unknown error')}")
            await safe_edit_message(query, f"❌ Registration Error\n\nAn error occurred during registration.")
            # Trigger automatic refund if this was a wallet payment
            await handle_registration_failure(order)
            return
        
        elif orchestrator_result.get('success'):
            logger.info(f"✅ HANDLERS: Domain registration completed via orchestrator: {domain_name}")
            # Orchestrator already sent success notification with buttons
        else:
            logger.warning(f"⚠️ HANDLERS: Unexpected orchestrator result for {domain_name}: {orchestrator_result}")
            await safe_edit_message(query, f"⚠️ Registration Status Unknown\n\nPlease check your domains list.")
        
    except Exception as e:
        logger.error(f"❌ HANDLERS: Error during orchestrated domain registration for {domain_name}: {e}")
        await safe_edit_message(query, f"❌ Registration Error\n\nAn error occurred during registration.")
        
        # Update order status and trigger refund on exception
        try:
            await execute_update("UPDATE domain_orders SET status = 'failed' WHERE id = %s", (order['id'],))
            await handle_registration_failure(order)
        except Exception as cleanup_error:
            logger.error(f"❌ HANDLERS: Error during cleanup for {domain_name}: {cleanup_error}")

async def handle_registration_failure(order):
    """Handle automatic refund for failed domain registrations"""
    try:
        # Check if this order has a hold transaction (wallet payment)
        hold_transaction_id = order.get('hold_transaction_id')
        if hold_transaction_id:
            logger.info(f"🔄 Triggering automatic refund for failed order: {order['domain_name']}")
            success = await finalize_wallet_reservation(hold_transaction_id, success=False)
            if success:
                logger.info(f"✅ Automatic refund processed for domain: {order['domain_name']}")
            else:
                logger.error(f"❌ Automatic refund failed for domain: {order['domain_name']}")
        else:
            logger.info(f"ℹ️ No wallet payment to refund for order: {order['domain_name']}")
            
    except Exception as e:
        logger.error(f"Error handling registration failure refund: {e}")

async def process_wallet_payment(query, domain_name, price, currency):
    """Process payment using wallet balance"""
    user = query.from_user
    
    try:
        user_record = await get_or_create_user(user.id)
        wallet_balance = await get_user_wallet_balance(user.id)
        price_float = float(price)
        
        # Check if user has sufficient balance
        if wallet_balance < price_float:
            await safe_edit_message(query, 
                f"❌ Insufficient Balance\n\n"
                f"Required: ${price_float:.2f}\n"
                f"Your Balance: ${wallet_balance:.2f}\n\n"
                f"Please add funds to your wallet first."
            )
            return
        
        # Check if this is a hosting bundle order
        from database import get_active_hosting_intent
        hosting_intent = await get_active_hosting_intent(user_record['id'], domain_name)
        
        if hosting_intent:
            # This is a hosting bundle - domain + hosting
            payment_msg = f"💳 <b>Wallet Payment</b> • ${price_float:.2f}\n📦 <b>Hosting + Domain:</b> {escape_html(domain_name)}\n⏳ Processing..."
            description = f"Hosting + Domain bundle: {domain_name}"
        else:
            # This is domain-only registration  
            payment_msg = f"💳 <b>Wallet Payment</b> • ${price_float:.2f}\n🌐 <b>Domain:</b> {escape_html(domain_name)}\n⏳ Processing..."
            description = f"Domain registration: {domain_name}"
        
        await safe_edit_message(query, payment_msg, parse_mode='HTML')
        
        # Reserve wallet balance for the order
        hold_transaction_id = await reserve_wallet_balance(
            user_record['id'], 
            price_float, 
            description
        )
        
        if not hold_transaction_id:
            await safe_edit_message(query, 
                "❌ Payment Failed\n\nCould not reserve wallet balance. Please try again."
            )
            return
        
        # Create domain order with wallet payment and hold transaction ID
        await execute_update(
            "INSERT INTO domain_orders (user_id, domain_name, status, expected_amount, currency, contact_handle, hold_transaction_id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (user_record['id'], domain_name, 'paid', price_float, currency, 'wallet_payment', hold_transaction_id)
        )
        
        # Get the order we just created
        orders = await execute_query(
            "SELECT * FROM domain_orders WHERE user_id = %s AND domain_name = %s ORDER BY created_at DESC LIMIT 1",
            (user_record['id'], domain_name)
        )
        
        if orders:
            order = orders[0]
            
            # Finalize the wallet reservation (mark as completed)
            await finalize_wallet_reservation(hold_transaction_id, success=True)
            
            # Start domain registration process immediately
            await process_domain_registration(query, domain_name, order)
        else:
            await safe_edit_message(query, 
                f"❌ Payment Error\n\nOrder creation failed. Please contact {BrandConfig().support_contact}."
            )
            # Refund the reservation
            await finalize_wallet_reservation(hold_transaction_id, success=False)
        
    except Exception as e:
        logger.error(f"Error processing wallet payment: {e}")
        await safe_edit_message(query, 
            "❌ Payment Error\n\nAn error occurred processing your payment. Please try again."
        )

async def show_wallet_deposit_options(query):
    """Show options for adding funds to wallet using unified crypto config"""
    message = """
💰 Add Funds

Select your preferred cryptocurrency:

*Minimum deposit: $5 USD*
"""
    
    # Build keyboard using unified crypto configuration
    keyboard = []
    for display_text, callback_suffix, icon in crypto_config.get_payment_button_data():
        keyboard.append([InlineKeyboardButton(
            f"{icon} {display_text}", 
            callback_data=f"deposit_{callback_suffix}"
        )])
    
    keyboard.append([InlineKeyboardButton("⬅️ Back to Wallet", callback_data="wallet_main")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_wallet_transaction_history(query):
    """Show detailed wallet transaction history"""
    user = query.from_user
    
    try:
        user_record = await get_or_create_user(user.id)
        transactions = await get_user_wallet_transactions(user_record['id'], 20)
        balance = await get_user_wallet_balance(user.id)
        
        if not transactions:
            message = f"""
📊 History

Balance: {format_money(balance, 'USD', include_currency=True)}

No transactions yet
"""
        else:
            message = f"""
📊 History

Balance: {format_money(balance, 'USD', include_currency=True)}

"""
            for tx in transactions:
                amount = float(tx['amount'])
                date = tx['created_at'].strftime('%m/%d')
                emoji = "➕" if amount > 0 else "➖"
                tx_type = tx['transaction_type'] or 'transaction'
                
                # Extract simple type from verbose descriptions
                if 'domain' in tx_type.lower():
                    simple_type = 'Domain'
                elif 'deposit' in tx_type.lower() or 'crypto' in tx_type.lower():
                    simple_type = 'Deposit'
                elif 'credit' in tx_type.lower():
                    simple_type = 'Credit'
                elif 'refund' in tx_type.lower():
                    simple_type = 'Refund'
                else:
                    simple_type = tx_type.title()[:8]  # Truncate to 8 chars max
                
                message += f"{emoji} ${abs(amount):.2f} - {simple_type} ({date})\n"
        
        keyboard = [
            [InlineKeyboardButton("💳 Add Funds", callback_data="wallet_deposit")],
            [InlineKeyboardButton("⬅️ Back to Wallet", callback_data="wallet_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing transaction history: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load transaction history.")

async def process_wallet_crypto_deposit(query, crypto_type):
    """Process cryptocurrency deposit to wallet"""
    user = query.from_user
    
    try:
        await safe_edit_message(query, f"Generating {crypto_type.upper()} payment address...")
        
        # Get or create user
        user_record = await get_or_create_user(user.id)
        
        # Create a proper order record first to get integer order_id
        current_time = datetime.utcnow()
        order_result = await execute_query(
            "INSERT INTO orders (user_id, status, total_amount, currency, metadata, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (user_record['id'], 'pending', 0, 'USD', f'{{"crypto_type": "{crypto_type}", "deposit_type": "wallet"}}', current_time, current_time)
        )
        
        if not order_result:
            await safe_edit_message(query, "❌ Order Error\n\nCould not create payment order. Please try again.")
            return
            
        order_id = order_result[0]['id']  # Use integer order_id
        
        # Generate payment with configured provider (DynoPay/BlockBee)
        payment_result = await create_payment_address(
            currency=crypto_type.lower(),
            order_id=order_id,
            value=0,  # Allow any amount to be sent
            user_id=user_record['id']
        )
        
        if not payment_result:
            await safe_edit_message(query, "❌ Payment Error\n\nCould not generate payment address. Please try again.")
            return
        
        # Save wallet deposit to database (0 amount means any amount accepted)
        await execute_update(
            "INSERT INTO wallet_deposits (user_id, crypto_currency, usd_amount, payment_address, blockbee_order_id, status) VALUES (%s, %s, %s, %s, %s, %s)",
            (user_record['id'], crypto_type.upper(), 0, payment_result['address'], order_id, 'pending_payment')
        )
        
        # Show payment instructions with copy functionality
        crypto_name = {
            'btc': 'Bitcoin',
            'ltc': 'Litecoin', 
            'doge': 'Dogecoin',
            'eth': 'Ethereum',
            'usdt_trc20': 'USDT (TRC20)',
            'usdt_erc20': 'USDT (ERC20)'
        }.get(crypto_type, crypto_type.upper())
        
        # Use the new copy-friendly formatter
        payment_message, copy_keyboard = render_crypto_payment(
            address=payment_result['address'],
            crypto_name=f"{crypto_name} Deposit",
            order_id=order_id,
            expires_minutes=15
        )
        
        # Add additional action buttons to the copy keyboard
        additional_buttons = [
            [InlineKeyboardButton("❌ Cancel Funding", callback_data=f"cancel_wallet_deposit:{order_id}")],
            [InlineKeyboardButton("⬅️ Back", callback_data="wallet_deposit")]
        ]
        
        # Combine copy buttons with action buttons
        combined_keyboard = list(copy_keyboard.inline_keyboard) + additional_buttons
        final_keyboard = InlineKeyboardMarkup(combined_keyboard)
        
        await safe_edit_message(query, payment_message, reply_markup=final_keyboard, parse_mode='HTML')
        
        logger.info(f"💰 Flexible wallet deposit payment generated for user {user.id}: {payment_result['address']} (any amount)")
        
    except Exception as e:
        logger.error(f"Error processing wallet crypto deposit: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not process deposit request.")


async def handle_copy_address(query, address):
    """Handle copy address button - provide feedback to user"""
    
    # IMMEDIATE FEEDBACK: Copy action
    await query.answer("📋 Address copied to clipboard!")
    
    # Show confirmation message with address highlighted
    text = f"""📋 Address Copied!

{address}

Use this address for your crypto payment.

💡 The address has been copied to your clipboard."""
    
    keyboard = [
        [InlineKeyboardButton("⬅️ Back", callback_data="wallet_deposit")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)


async def handle_copy_memo(query, memo):
    """Handle copy memo button - provide feedback to user"""
    
    # IMMEDIATE FEEDBACK: Copy action
    await query.answer("📋 Memo copied to clipboard!")
    
    # Show confirmation message with memo highlighted
    text = f"""📋 Memo Copied!

{memo}

Include this memo/tag with your payment.

💡 The memo has been copied to your clipboard."""
    
    keyboard = [
        [InlineKeyboardButton("⬅️ Back", callback_data="wallet_deposit")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)


async def handle_copy_hosting_credential(query, credential, credential_type):
    """Handle copy hosting credential button - provide feedback to user"""
    
    # IMMEDIATE FEEDBACK: Copy action
    await query.answer(f"📋 {credential_type} copied to clipboard!")
    
    # Show confirmation message with credential highlighted
    text = f"""📋 {credential_type} Copied!

{credential}

Your hosting credential has been copied to clipboard.
💾 Save all credentials securely for future access."""
    
    keyboard = [
        [InlineKeyboardButton("⬅️ Back", callback_data="my_hosting")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)


async def show_wallet_qr_code(query, order_id):
    """Show QR code for wallet deposit payment or domain payment"""
    user = query.from_user
    
    try:
        # Get user record
        user_record = await get_or_create_user(user.id)
        
        # First try to find wallet deposit
        deposits = await execute_query(
            "SELECT * FROM wallet_deposits WHERE blockbee_order_id = %s AND user_id = %s",
            (order_id, user_record['id'])
        )
        
        if deposits:
            # Handle wallet deposit QR code
            await _show_wallet_deposit_qr(query, order_id, deposits[0])
            return
        
        # If not a wallet deposit, try domain payment
        # Check payment_intents table for domain payments
        payment_intents = await execute_query(
            "SELECT * FROM payment_intents WHERE order_id = %s AND user_id = %s",
            (order_id, user_record['id'])
        )
        
        if payment_intents:
            # Handle domain payment QR code
            await _show_domain_payment_qr(query, order_id, payment_intents[0])
            return
        
        await safe_edit_message(query, "❌ Payment Not Found\n\nPayment order not found.")
        
    except Exception as e:
        logger.error(f"Error showing QR code: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not generate QR code.")

async def _show_wallet_deposit_qr(query, order_id, deposit):
    """Show QR code for wallet deposit"""
    usd_amount = float(deposit['usd_amount'])
    crypto_currency = deposit['crypto_currency']
    payment_address = deposit['payment_address']
    
    # Generate QR code for the payment address
    qr = QRCode(version=1, box_size=10, border=5)
    qr.add_data(payment_address)
    qr.make(fit=True)
    
    qr_image = qr.make_image(fill_color="black", back_color="white")
    bio = BytesIO()
    qr_image.save(bio, format='PNG')
    bio.seek(0)
    
    # Handle flexible amount display with proper HTML formatting for tap-and-copy
    from message_utils import format_inline_code
    
    if usd_amount == 0:
        message = f"""📱 {crypto_currency} Payment

Address: {format_inline_code(payment_address)}

💰 Send any amount → Auto-credited to wallet
💡 Tap address to copy"""
    else:
        message = f"""📱 {crypto_currency} Payment

Amount: {format_money(usd_amount, 'USD', include_currency=True)}
Address: {format_inline_code(payment_address)}

💡 Tap address to copy"""
    
    keyboard = [
        [InlineKeyboardButton("⬅️ Back to Crypto Selection", callback_data="wallet_deposit_from_qr")],
        [InlineKeyboardButton("❌ Cancel Funding", callback_data=f"cancel_deposit:{order_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        # Send QR code image with timeout protection
        qr_message = await asyncio.wait_for(
            query.message.reply_photo(
                photo=bio,
                caption=message,
                reply_markup=reply_markup,
                parse_mode='HTML'
            ),
            timeout=30.0  # 30 second timeout
        )
        
        # Only delete original message AFTER successful QR send
        try:
            await query.message.delete()
        except Exception as delete_error:
            logger.warning(f"Could not delete original wallet QR message: {delete_error}")
            # Continue - QR was sent successfully, deletion failure is not critical
            
    except asyncio.TimeoutError:
        logger.warning(f"Wallet QR code upload timed out for order {order_id}")
        # Fallback: Edit original message with text-only payment info
        if usd_amount == 0:
            fallback_message = f"""⚠️ QR Code Loading...

📱 {crypto_currency} Payment Details

Address: {format_inline_code(payment_address)}

💰 Send any amount → Auto-credited to wallet
💡 Copy address above to send payment

QR code generation timed out, but you can still copy the address above."""
        else:
            fallback_message = f"""⚠️ QR Code Loading...

📱 {crypto_currency} Payment Details

Amount: {format_money(usd_amount, 'USD', include_currency=True)}
Address: {format_inline_code(payment_address)}

💡 Copy address above to send payment

QR code generation timed out, but you can still copy the address above."""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error generating wallet QR code for order {order_id}: {e}")
        # Fallback: Edit original message with text-only payment info
        if usd_amount == 0:
            fallback_message = f"""❌ QR Code Unavailable

📱 {crypto_currency} Payment Details

Address: {format_inline_code(payment_address)}

💰 Send any amount → Auto-credited to wallet
💡 Copy address above to send payment"""
        else:
            fallback_message = f"""❌ QR Code Unavailable

📱 {crypto_currency} Payment Details

Amount: {format_money(usd_amount, 'USD', include_currency=True)}
Address: {format_inline_code(payment_address)}

💡 Copy address above to send payment"""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)

async def _show_domain_payment_qr(query, order_id, payment_intent):
    """Show QR code for domain payment with timeout handling"""
    payment_address = payment_intent['payment_address']
    crypto_currency = payment_intent['crypto_currency']
    usd_amount = float(payment_intent.get('amount', 0))
    
    # Extract domain name from order_id
    domain_name = "domain"
    if order_id.startswith("domain_"):
        parts = order_id.split("_")
        if len(parts) >= 2:
            domain_name = parts[1]
    
    # Format message for domain payment
    from message_utils import format_inline_code
    
    message = f"""📱 {crypto_currency.upper()} Payment QR Code

💰 Amount: ${usd_amount:.2f} USD
📬 Address: {format_inline_code(payment_address)}
🌐 Domain: {domain_name}

💡 Scan QR code with your crypto wallet
⏰ Payment expires in 15 minutes"""
    
    keyboard = [
        [InlineKeyboardButton("⬅️ Back to Payment", callback_data=f"qr_back_to_payment:{domain_name}")],
        [InlineKeyboardButton("❌ Cancel Order", callback_data="qr_cancel_order")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        # Generate QR code for the payment address
        qr = QRCode(version=1, box_size=10, border=5)
        qr.add_data(payment_address)
        qr.make(fit=True)
        
        qr_image = qr.make_image(fill_color="black", back_color="white")
        bio = BytesIO()
        qr_image.save(bio, format='PNG')
        bio.seek(0)
        
        # Send QR code image with timeout protection
        qr_message = await asyncio.wait_for(
            query.message.reply_photo(
                photo=bio,
                caption=message,
                reply_markup=reply_markup,
                parse_mode='HTML'
            ),
            timeout=30.0  # 30 second timeout
        )
        
        # Only delete original message AFTER successful QR send
        try:
            await query.message.delete()
        except Exception as delete_error:
            logger.warning(f"Could not delete original QR message: {delete_error}")
            # Continue - QR was sent successfully, deletion failure is not critical
            
    except asyncio.TimeoutError:
        logger.warning(f"QR code upload timed out for order {order_id}")
        # Fallback: Edit original message with text-only payment info
        fallback_message = f"""⚠️ QR Code Loading...

📱 {crypto_currency.upper()} Payment Details

💰 Amount: ${usd_amount:.2f} USD
📬 Address: {format_inline_code(payment_address)}
🌐 Domain: {domain_name}

💡 Copy address above to your crypto wallet
⏰ Payment expires in 15 minutes

QR code generation timed out, but you can still copy the address above."""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error generating QR code for order {order_id}: {e}")
        # Fallback: Edit original message with text-only payment info
        fallback_message = f"""❌ QR Code Unavailable

📱 {crypto_currency.upper()} Payment Details

💰 Amount: ${usd_amount:.2f} USD
📬 Address: {format_inline_code(payment_address)}
🌐 Domain: {domain_name}

💡 Copy address above to your crypto wallet
⏰ Payment expires in 15 minutes"""
        
        await safe_edit_message(query, fallback_message, reply_markup=reply_markup)

async def cancel_wallet_deposit(query, order_id):
    """Cancel a wallet deposit"""
    user = query.from_user
    
    try:
        # Get user record
        user_record = await get_or_create_user(user.id)
        
        # Update deposit status to cancelled
        await execute_update(
            "UPDATE wallet_deposits SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE blockbee_order_id = %s AND user_id = %s",
            ('cancelled', order_id, user_record['id'])
        )
        
        message = """
❌ Funding Cancelled

Your wallet deposit has been cancelled. No payment is required.

You can start a new deposit anytime from your wallet.
"""
        
        keyboard = [
            [InlineKeyboardButton("💰 Start New Deposit", callback_data="wallet_deposit")],
            [InlineKeyboardButton("⬅️ Back to Wallet", callback_data="wallet_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        logger.info(f"💰 Wallet deposit cancelled by user {user.id}: {order_id}")
        
    except Exception as e:
        logger.error(f"Error cancelling wallet deposit: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not cancel deposit.")

async def handle_wallet_deposit_from_qr(query):
    """Handle navigation from QR code photo to crypto selection"""
    try:
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Send a new crypto selection message 
        message = """
💰 Add Funds

Select your preferred cryptocurrency:

<b>Minimum deposit: $5 USD</b>
"""
        
        # Build keyboard using unified crypto configuration
        keyboard = []
        for display_text, callback_suffix, icon in crypto_config.get_payment_button_data():
            keyboard.append([InlineKeyboardButton(
                f"{icon} {display_text}", 
                callback_data=f"deposit_{callback_suffix}"
            )])
        
        keyboard.append([InlineKeyboardButton("⬅️ Back to Wallet", callback_data="wallet_main")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send new message instead of editing
        await query.message.reply_text(message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error handling wallet deposit from QR: {e}")
        # Fallback: just send a simple message
        await query.message.reply_text("❌ Error loading crypto selection. Please try again.")

async def handle_cancel_wallet_deposit_from_qr(query, order_id):
    """Handle cancel deposit from QR code photo"""
    user = query.from_user
    
    try:
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Get user record
        user_record = await get_or_create_user(user.id)
        
        # Update deposit status to cancelled
        await execute_update(
            "UPDATE wallet_deposits SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE blockbee_order_id = %s AND user_id = %s",
            ('cancelled', order_id, user_record['id'])
        )
        
        message = """
❌ Funding Cancelled

Your wallet deposit has been cancelled. No payment is required.

You can start a new deposit anytime from your wallet.
"""
        
        keyboard = [
            [InlineKeyboardButton("💰 Start New Deposit", callback_data="wallet_deposit")],
            [InlineKeyboardButton("⬅️ Back to Wallet", callback_data="wallet_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Send new message instead of editing
        await query.message.reply_text(message, reply_markup=reply_markup)
        
        logger.info(f"💰 Wallet deposit cancelled by user {user.id}: {order_id}")
        
    except Exception as e:
        logger.error(f"Error cancelling wallet deposit from QR: {e}")
        # Fallback: just send a simple message
        await query.message.reply_text("❌ Error cancelling deposit. Please try again.")

async def back_to_wallet_payment(query, order_id):
    """Return to wallet payment details from QR code"""
    user = query.from_user
    
    try:
        # Simply redirect to crypto selection instead of showing payment details
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Show the crypto selection page where users can choose different cryptocurrencies
        await show_wallet_deposit_options(query)
        
    except Exception as e:
        logger.error(f"Error returning to wallet payment: {e}")
        # Delete QR and show crypto selection on error too
        try:
            await query.message.delete()
            await show_wallet_deposit_options(query)
        except:
            pass  # If everything fails, just let it be

async def handle_qr_back_to_payment(query, domain_name):
    """Handle back to payment from domain QR code photo message"""
    try:
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Check if user has an active hosting intent for this domain (unified flow)
        try:
            user_record = await get_or_create_user(query.from_user.id)
            active_intent = await get_active_hosting_intent(user_record['id'], domain_name)
            
            if active_intent:
                # Back to hosting intent payment options (unified flow)
                intent_id = active_intent['id']
                price = float(active_intent['estimated_price'])
                plan_name = active_intent.get('plan_name', 'Hosting Plan')
                service_type = active_intent.get('service_type', 'hosting_new_domain')
                
                if service_type in ['hosting_new_domain', 'domain_hosting_bundle']:
                    items = [f"Register domain: {domain_name}", f"{plan_name} hosting"]
                else:
                    items = [f"{plan_name} hosting"]
                
                await show_unified_payment_options_with_intent(
                    query,
                    intent_id,
                    price,
                    plan_name,
                    domain_name,
                    items,
                    service_type
                )
                return
        except Exception as intent_error:
            logger.warning(f"Could not check hosting intent for {domain_name}: {intent_error}")
        
        # Fallback to domain-only registration flow
        await start_domain_registration(query, domain_name)
        
    except Exception as e:
        logger.error(f"Error handling QR back to payment for {domain_name}: {e}")
        # If deletion fails, try to continue anyway
        try:
            await start_domain_registration(query, domain_name)
        except:
            pass  # If everything fails, just let it be

async def handle_qr_cancel_order(query):
    """Handle cancel order from domain QR code photo message"""
    try:
        # Delete the QR code photo message first
        await query.message.delete()
        
        # Call the original search domains function
        await show_search_interface(query)
        
    except Exception as e:
        logger.error(f"Error handling QR cancel order: {e}")
        # If deletion fails, try to continue anyway
        try:
            await show_search_interface(query)
        except:
            pass  # If everything fails, just let it be

async def check_wallet_deposit_status(query, order_id):
    """Check the status of a wallet deposit"""
    user = query.from_user
    
    try:
        # Get user record
        user_record = await get_or_create_user(user.id)
        
        # Check wallet deposit status
        deposits = await execute_query(
            "SELECT * FROM wallet_deposits WHERE blockbee_order_id = %s AND user_id = %s",
            (order_id, user_record['id'])
        )
        
        if not deposits:
            await safe_edit_message(query, "❌ Deposit Not Found\n\nDeposit order not found.")
            return
            
        deposit = deposits[0]
        status = deposit['status']
        usd_amount = float(deposit['usd_amount'])
        crypto_currency = deposit['crypto_currency']
        
        if status == 'pending_payment':
            if usd_amount == 0:
                message = f"⏳ Pending\n\n{crypto_currency}:\n{deposit['payment_address']}\n\nSend any amount\n💡 Tap the address above to copy it"
            else:
                message = f"⏳ Pending\n\n{crypto_currency}:\n{deposit['payment_address']}\n\nSend ${usd_amount:.2f} USD\n💡 Tap the address above to copy it"
        elif status == 'confirming':
            message = f"🔄 Confirming\n\n${usd_amount:.2f} USD ({crypto_currency})\n\nWaiting for confirmations"
        elif status == 'completed':
            message = f"✅ Completed\n\n${usd_amount:.2f} USD credited"
        else:
            config = BrandConfig()
            message = f"❌ {status.title()}\n\nContact {config.support_contact}"
        
        keyboard = [
            [InlineKeyboardButton("💰 Wallet", callback_data="wallet_main")],
            [InlineKeyboardButton("⬅️ Back", callback_data="wallet_deposit")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error checking wallet deposit status: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not check deposit status.")

async def show_domain_management(query, domain_id):
    """Placeholder for domain management"""
    await safe_edit_message(query, f"⚙️ Domain management for ID {domain_id} coming soon...")

async def show_dns_management(query, domain_id):
    """Placeholder for DNS management"""
    await safe_edit_message(query, f"⚙️ Domain management for ID {domain_id} coming soon...")

async def handle_dns_callback(query, context, callback_data):
    """
    Handle DNS callbacks with standardized routing: dns:{domain}:{action}[:type][:id][:page]
    
    Actions:
    - view: Show DNS dashboard
    - add: Add new record (requires type)
    - edit: Edit existing record (requires id)
    - delete: Delete record (requires id)
    - list: List all records
    """
    try:
        # Enhanced logging for debugging
        user = query.from_user
        logger.info(f"DNS callback processing for user {user.id if user else 'unknown'}: {callback_data}")
        
        # Parse callback: dns:{domain}:{action}[:type][:id][:page]
        parts = callback_data.split(':')
        logger.info(f"DNS callback parts: {parts}")
        
        if len(parts) < 3:
            logger.warning(f"Invalid DNS callback - insufficient parts: {callback_data}")
            await safe_edit_message(query, "❌ Invalid DNS Action\n\nPlease try again.")
            return
        
        domain = parts[1]
        action = parts[2]
        logger.info(f"DNS action parsed - domain: {domain}, action: {action}")
        
        # Route to appropriate handler
        if action == "view":
            await show_dns_dashboard(query, domain)
        elif action == "add" and len(parts) >= 4:
            record_type = parts[3]
            await start_dns_add_wizard(query, context, domain, record_type)
        elif action == "add":
            await show_dns_add_type_picker(query, domain)
        elif action == "list":
            page = int(parts[3]) if len(parts) >= 4 and parts[3].isdigit() else 1
            await show_dns_record_list(query, domain, page)
        elif action == "record" and len(parts) >= 4:
            record_id = parts[3]
            await show_dns_record_detail(query, domain, record_id)
        elif action == "edit" and len(parts) >= 4:
            record_id = parts[3]
            # Store edit context for simplified callback routing
            context.user_data['edit_context'] = {
                'domain': domain,
                'record_id': record_id
            }
            await start_dns_edit_wizard(query, context, domain, record_id)
        elif action == "delete" and len(parts) >= 4:
            record_id = parts[3]
            if len(parts) >= 5 and parts[4] == "confirm":
                await execute_dns_delete(query, context, domain, record_id)
            else:
                await confirm_dns_delete(query, context, domain, record_id)
        elif action == "nameservers":
            await show_nameserver_management(query, domain, context)
        elif action == "security":
            if len(parts) >= 4:
                setting_action = parts[3]
                if setting_action == "js_challenge" and len(parts) >= 5:
                    action = parts[4]
                    if action == "confirm_proxy" and len(parts) >= 6 and parts[5] == "on":
                        # User confirmed proxy enablement for JavaScript Challenge
                        await force_enable_proxy_and_feature(query, domain, "js_challenge")
                    else:
                        await toggle_javascript_challenge(query, domain, action)
                elif setting_action == "force_https" and len(parts) >= 5:
                    action_type = parts[4]  # This will be "on", "off", "toggle", or "confirm_proxy"
                    if action_type == "confirm_proxy" and len(parts) >= 6 and parts[5] == "on":
                        # User confirmed proxy enablement for Force HTTPS
                        await force_enable_proxy_and_feature(query, domain, "force_https")
                    else:
                        await toggle_force_https_setting(query, domain, action_type)
                elif setting_action == "auto_proxy" and len(parts) >= 5:
                    action_type = parts[4]  # This will be "on", "off", or "toggle"
                    await toggle_auto_proxy_setting(query, domain, action_type)
                else:
                    await show_security_settings(query, domain)
            else:
                await show_security_settings(query, domain)
        elif action == "ns_to_cloudflare":
            if len(parts) >= 4 and parts[3] == "confirm":
                await execute_switch_to_cloudflare_ns(query, context, domain)
            else:
                await confirm_switch_to_cloudflare_ns(query, domain)
        elif action == "ns_update" and len(parts) >= 4:
            ns_data = parts[3]  # This will be a compressed callback token
            await execute_nameserver_update(query, context, domain, ns_data)
        else:
            logger.warning(f"Unknown DNS action '{action}' for domain '{domain}' in callback: {callback_data}")
            await safe_edit_message(query, "❌ Unknown DNS Action\n\nPlease try again.")
            
    except Exception as e:
        logger.error(f"Error handling DNS callback {callback_data}: {e}")
        await safe_edit_message(query, "❌ DNS Error\n\nCould not process action. Please try again.")

async def show_dns_dashboard(query, domain_name):
    """Show enhanced DNS dashboard with record counts and clear actions"""
    user = query.from_user
    
    # Immediate response for better UX with unique identifier
    await safe_edit_message(query, f"🔄 DNS Dashboard - {domain_name}\n\nLoading records overview and zone configuration...")
    
    try:
        user_record = await get_or_create_user(user.id)
        
        # Check if user owns this domain
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain_name for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain_name}")
            return
        
        # Get current DNS records and nameserver info
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        # Get nameservers from database first (reflects actual registrar config)
        nameservers = await get_domain_nameservers(domain_name)
        
        # Fallback to Cloudflare API if no stored nameservers exist
        if not nameservers:
            zone_info = await cloudflare.get_zone_info(zone_id)
            nameservers = zone_info.get('name_servers', []) if zone_info else []
            logger.info(f"Using Cloudflare API nameservers for {domain_name} (no stored nameservers found)")
        else:
            logger.info(f"Using stored nameservers for {domain_name}: {nameservers}")
        
        # Detect nameserver provider and format display
        provider_type, provider_name = detect_nameserver_provider(nameservers)
        nameserver_display = format_nameserver_display(nameservers, max_display=2)
        
        # Provider status indicator - simplified
        if provider_type == "cloudflare":
            provider_status = "Cloudflare"
        elif provider_type == "external":
            provider_status = f"{provider_name}"
        else:
            provider_status = "Unknown Provider"
        
        # Only fetch and display DNS records if using Cloudflare nameservers
        record_counts = {}
        preview_records = []
        dns_records = []
        
        if provider_type == "cloudflare":
            dns_records = await cloudflare.list_dns_records(zone_id)
            
            # Count records by type
            for record in dns_records:
                record_type = record.get('type', 'Unknown')
                record_counts[record_type] = record_counts.get(record_type, 0) + 1
                if len(preview_records) < 3:  # Show max 3 records in preview
                    name = record.get('name', 'Unknown')
                    content = record.get('content', 'Unknown')
                    # Simplified display without excessive emojis
                    preview_records.append(f"• {record_type}: {name} → {content}")
        
        # Format record summary based on nameserver provider - simplified
        if provider_type == "cloudflare":
            if record_counts:
                # Clean summary without "Records:" prefix
                counts_text = ", ".join([f"{count} {rtype}" for rtype, count in record_counts.items()])
                records_summary = counts_text
                if preview_records:
                    records_summary += "\n\n" + "\n".join(preview_records)
                    if len(dns_records) > 3:
                        records_summary += f"\n... {len(dns_records) - 3} more records"
            else:
                records_summary = "No records found"
        else:
            records_summary = f"Records managed by {provider_name}"
        
        message = f"""DNS Dashboard: {domain_name}

Status: Active
Provider: {provider_status}

Nameservers:
{nameserver_display}

{records_summary}"""
        
        # Build keyboard with conditional DNS record management options
        keyboard = []
        
        # Only show Add Record and List All buttons if using Cloudflare nameservers
        if provider_type == "cloudflare":
            keyboard.append([
                InlineKeyboardButton("➕ Add Record", callback_data=f"dns:{domain_name}:add"),
                InlineKeyboardButton("📝 List All", callback_data=f"dns:{domain_name}:list")
            ])
            keyboard.append([
                InlineKeyboardButton("🛡️ Security Settings", callback_data=f"dns:{domain_name}:security")
            ])
        
        # Always show nameserver management
        keyboard.append([InlineKeyboardButton("📡 Manage Nameservers", callback_data=f"dns:{domain_name}:nameservers")])
        
        # Add conditional nameserver options based on current provider
        if provider_type != "cloudflare":
            keyboard.append([InlineKeyboardButton("🔄 Switch to Cloudflare NS", callback_data=f"dns:{domain_name}:ns_to_cloudflare")])
        
        keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data="my_domains")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing DNS dashboard for {domain_name}: {e}")
        error_message = f"❌ DNS Dashboard Error\n\nFailed to load dashboard for {domain_name}.\n\nError: {str(e)[:100]}..."
        await safe_edit_message(query, error_message)

async def show_dns_add_type_picker(query, domain):
    """Show record type picker for adding new DNS records"""
    message = f"""
➕ Add DNS Record: {domain}

Select the type of DNS record you want to add:
"""
    
    keyboard = [
        [InlineKeyboardButton("🅰️ A Record", callback_data=f"dns:{domain}:add:A"),
         InlineKeyboardButton("🔗 CNAME", callback_data=f"dns:{domain}:add:CNAME")],
        [InlineKeyboardButton("📝 TXT Record", callback_data=f"dns:{domain}:add:TXT"),
         InlineKeyboardButton("📧 MX Record", callback_data=f"dns:{domain}:add:MX")],
        [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain}:view")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def start_dns_add_wizard(query, context, domain, record_type):
    """Start the DNS record addition wizard"""
    user = query.from_user
    
    # Initialize wizard state in context.user_data
    wizard_state = {
        'domain': domain,
        'action': 'add',
        'type': record_type,
        'step': 1,
        'data': {}
    }
    
    # Store wizard state for this user
    context.user_data['dns_wizard'] = wizard_state
    
    if record_type == "A":
        await continue_a_record_wizard(query, context, wizard_state)
    elif record_type == "CNAME":
        await continue_cname_record_wizard(query, context, wizard_state)
    elif record_type == "TXT":
        await continue_txt_record_wizard(query, context, wizard_state)
    elif record_type == "MX":
        await continue_mx_record_wizard(query, context, wizard_state)
    else:
        await safe_edit_message(query, f"🚧 {record_type} Wizard\n\nComing soon!")

async def continue_dns_add_wizard(query, domain, record_type, step):
    """Continue the DNS addition wizard at specified step"""
    user = query.from_user
    flow_id = f"{user.id}_{domain}_{record_type}"
    
    # Initialize default values to prevent LSP "possibly unbound" warnings
    message = f"🚧 {record_type} Record Wizard\n\nComing soon!"
    keyboard = [[InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain}:add")]]
    
    if record_type == "A":
        if step == 1:
            message = f"""
🅰️ Add A Record (1/4): {domain}

Enter the name/host for this A record.

Current: Root domain (@)
"""
            keyboard = [
                [InlineKeyboardButton("Use Root (@)", callback_data=f"dns_wizard:{domain}:A:name:@")],
                [InlineKeyboardButton("Use www", callback_data=f"dns_wizard:{domain}:A:name:www")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain}:add")]
            ]
        elif step == 2:
            message = f"""
🅰️ Add A Record (2/4): {domain}

Enter the IPv4 address this record should point to.

Please type the IP address:
"""
            keyboard = [
                [InlineKeyboardButton("Use 8.8.8.8", callback_data=f"dns_wizard:{domain}:A:ip:8.8.8.8")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain}:add:A")]
            ]
    # Add more record types here...
    else:
        message = f"🚧 {record_type} Record Wizard\n\nComing soon! Please use A or CNAME records for now."
        keyboard = [[InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain}:add")]]
    
    # Ensure variables are always defined (remove problematic locals() checks)
    # Variables are already defined in all code paths above
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def show_dns_record_list(query, domain, page=1):
    """Show paginated list of DNS records"""
    user = query.from_user
    
    # Immediate response for better UX
    await safe_edit_message(query, "🔄 Loading DNS Records...\n\nFetching your records...")
    
    try:
        user_record = await get_or_create_user(user.id)
        
        # Check domain ownership
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get DNS records
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
        
        cloudflare = CloudflareService()
        all_records = await cloudflare.list_dns_records(cf_zone['cf_zone_id'])
        
        # Paginate records (8 per page)
        per_page = 8
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        records = all_records[start_idx:end_idx]
        total_pages = (len(all_records) + per_page - 1) // per_page
        
        if not all_records:
            message = f"""
📝 DNS Records: {domain}

No DNS records found.

Get started by adding your first record!
"""
            keyboard = [
                [InlineKeyboardButton("➕ Add Record", callback_data=f"dns:{domain}:add")],
                [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain}:view")]
            ]
        else:
            message = f"""
📝 DNS Records: {domain} (Page {page}/{total_pages})

Total Records: {len(all_records)}

"""
            keyboard = []
            
            for record in records:
                record_type = record.get('type', 'Unknown')
                name = record.get('name', 'Unknown')
                content = record.get('content', 'Unknown')[:30]  # Truncate long content
                if len(record.get('content', '')) > 30:
                    content += "..."
                proxied = "🟠" if record.get('proxied') else "⚪"
                
                message += f"• {record_type} {name} → {content} {proxied}\n"
                
                # Add record button with record ID
                record_id = record.get('id', '')
                keyboard.append([InlineKeyboardButton(f"⚙️ {record_type}: {name}", callback_data=f"dns:{domain}:record:{record_id}")])
            
            # Navigation buttons
            nav_buttons = []
            if page > 1:
                nav_buttons.append(InlineKeyboardButton("◀️ Previous", callback_data=f"dns:{domain}:list:{page-1}"))
            if page < total_pages:
                nav_buttons.append(InlineKeyboardButton("Next ▶️", callback_data=f"dns:{domain}:list:{page+1}"))
            
            if nav_buttons:
                keyboard.append(nav_buttons)
            
            keyboard.extend([
                [InlineKeyboardButton("➕ Add Record", callback_data=f"dns:{domain}:add")],
                [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain}:view")]
            ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing DNS record list: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load DNS records.")

async def show_dns_record_detail(query, domain, record_id):
    """Show details for a specific DNS record with edit/delete options"""
    user = query.from_user
    
    # Immediate response for better UX with unique identifier  
    await safe_edit_message(query, f"🔄 DNS Record Details - {domain}\n\nLoading specific record information (ID: {record_id[:8]}...)...")
    
    try:
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
        
        # Get the specific DNS record
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        record = await cloudflare.get_dns_record(zone_id, record_id)
        
        if not record:
            await safe_edit_message(query, "❌ Record Not Found\n\nThe DNS record could not be found.")
            return
        
        # Format record details
        record_type = record.get('type', 'Unknown')
        name = record.get('name', 'Unknown')
        content = record.get('content', 'Unknown')
        ttl = record.get('ttl', 'Auto')
        proxied = record.get('proxied', False)
        priority = record.get('priority', None)
        
        # Display TTL nicely
        if ttl == 1:
            ttl_display = "Auto"
        elif ttl < 3600:
            ttl_display = f"{ttl} seconds"
        elif ttl < 86400:
            ttl_display = f"{ttl // 3600} hours"
        else:
            ttl_display = f"{ttl // 86400} days"
        
        proxy_display = "🟠 Proxied" if proxied else "⚪ Direct"
        
        message = f"""
🔍 DNS Record Details

Domain: {domain}
Type: {record_type}
Name: {name}
Content: {content}
TTL: {ttl_display}
Proxy: {proxy_display}
"""
        
        # Add priority for MX records
        if record_type == 'MX' and priority:
            message += f"Priority: {priority}\n"
        
        message += f"""
Record ID: {record_id}

<b>Actions:</b>
"""
        
        keyboard = [
            [InlineKeyboardButton("✏️ Edit Record", callback_data=f"dns:{domain}:edit:{record_id}"),
             InlineKeyboardButton("🗑️ Delete Record", callback_data=f"dns:{domain}:delete:{record_id}")],
            [InlineKeyboardButton("📝 Records", callback_data=f"dns:{domain}:list")],
            [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain}:view")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing DNS record detail for {domain}/{record_id}: {e}")
        error_message = f"❌ <b>DNS Record Error</b>\n\nFailed to load record <code>{escape_html(record_id[:8])}...</code> for <code>{escape_html(domain)}</code>.\n\nError: {escape_html(str(e)[:100])}..."
        await safe_edit_message(query, error_message)

async def start_dns_edit_wizard(query, context, domain, record_id):
    """Start DNS record editing wizard with pre-filled values"""
    user = query.from_user
    
    try:
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone and record
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
        
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        record = await cloudflare.get_dns_record(zone_id, record_id)
        
        if not record:
            await safe_edit_message(query, "❌ Record Not Found\n\nThe DNS record could not be found.")
            return
        
        # Initialize edit wizard state with current values
        record_type = record.get('type', '').upper()
        current_name = record.get('name', '')
        current_content = record.get('content', '')
        current_ttl = record.get('ttl', 300)  # Keep as integer for proper type comparison
        current_proxied = 'true' if record.get('proxied', False) else 'false'
        current_priority = record.get('priority', 10) if record_type == 'MX' else None
        
        # Store edit wizard state
        context.user_data['dns_wizard'] = {
            'domain': domain,
            'action': 'edit',
            'type': record_type,
            'record_id': record_id,
            'step': 1,
            'data': {
                'name': current_name,
                'content': current_content,
                'ttl': current_ttl,
                'proxied': current_proxied,
                'priority': current_priority
            },
            'original_data': {
                'name': current_name,
                'content': current_content,
                'ttl': current_ttl,
                'proxied': current_proxied,
                'priority': current_priority
            }
        }
        
        # Add timestamp to prevent caching issues
        context.user_data['dns_wizard']['timestamp'] = int(time.time())
        
        # Start edit wizard for the specific record type
        if record_type == "A":
            await continue_a_record_edit_wizard(query, context, context.user_data['dns_wizard'])
        elif record_type == "CNAME":
            await continue_cname_record_edit_wizard(query, context.user_data['dns_wizard'])
        elif record_type == "TXT":
            await continue_txt_record_edit_wizard(query, context.user_data['dns_wizard'])
        elif record_type == "MX":
            await continue_mx_record_edit_wizard(query, context.user_data['dns_wizard'])
        else:
            await safe_edit_message(query, f"✏️ <b>Edit {escape_html(record_type)} Record</b>\n\nEditing {escape_html(record_type)} records is not yet supported. You can delete and recreate the record instead.")
            
    except Exception as e:
        logger.error(f"Error starting DNS edit wizard: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not start edit wizard.")

async def confirm_dns_delete(query, context, domain, record_id):
    """Confirm DNS record deletion with safety checks"""
    user = query.from_user
    
    try:
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone and record details
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
        
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        record = await cloudflare.get_dns_record(zone_id, record_id)
        
        if not record:
            await safe_edit_message(query, "❌ Record Not Found\n\nThe DNS record could not be found.")
            return
        
        # Format record details for confirmation
        record_type = record.get('type', 'Unknown')
        name = record.get('name', 'Unknown')
        content = record.get('content', 'Unknown')
        
        message = f"""
🗑️ <b>Confirm Record Deletion</b>\n\n⚠️ <b>WARNING: This action cannot be undone!</b>

Domain: {domain}
Type: {record_type}
Name: {name}
Content: {content}

Are you sure you want to permanently delete this DNS record?

🔴 <b>This will immediately remove the record from your DNS zone.</b>
"""
        
        # Store domain context for delete callback to avoid Telegram's 64-byte limit
        context.user_data['delete_context'] = {'domain': domain, 'record_id': record_id}
        
        # Use shorter callback data to avoid Telegram's 64-byte limit
        keyboard = [
            [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:record:{record_id}")],
            [InlineKeyboardButton("🗑️ YES, DELETE RECORD", callback_data=f"del:{record_id}")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error confirming DNS record deletion: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load record for deletion.")

async def execute_dns_delete(query, context, domain, record_id):
    """Execute DNS record deletion"""
    user = query.from_user
    
    try:
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
        
        # Show deleting message
        await safe_edit_message(query, "🗑️ <b>Deleting DNS Record...</b>\n\nPlease wait...")
        
        # Get record info before deletion for confirmation message
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        record = await cloudflare.get_dns_record(zone_id, record_id)
        
        if not record:
            await safe_edit_message(query, "❌ Record Not Found\n\nThe DNS record could not be found.")
            return
        
        record_type = record.get('type', 'Unknown')
        name = record.get('name', 'Unknown')
        
        # Delete the DNS record
        success = await cloudflare.delete_dns_record(zone_id, record_id)
        
        if success:
            # Success message
            message = f"""
✅ <b>DNS Record Deleted Successfully</b>

Domain: {domain}
Type: {record_type}
Name: {name}

✅ <b>DNS Record Deleted</b>

Record permanently removed from DNS zone.
"""
            
            keyboard = [
                [InlineKeyboardButton("📝 View Remaining Records", callback_data=f"dns:{domain}:list")],
                [InlineKeyboardButton("➕ Add New Record", callback_data=f"dns:{domain}:add")],
                [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain}:view")]
            ]
        else:
            # Error message
            message = f"""
❌ <b>DNS Record Deletion Failed</b>

Domain: {domain}
<b>Record:</b> {record_type} {name}

Could not delete the DNS record. This may be due to:
• Network connectivity issues
• Cloudflare API limitations
• Record protection settings

<b>Try Again:</b>
"""
            
            keyboard = [
                [InlineKeyboardButton("🔄 Try Again", callback_data=f"dns:{domain}:delete:{record_id}")],
                [InlineKeyboardButton("⬅️ Back to Record", callback_data=f"dns:{domain}:record:{record_id}")],
                [InlineKeyboardButton("🌐 Dashboard", callback_data=f"dns:{domain}:view")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error executing DNS record deletion: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not delete DNS record. Please try again.")

async def handle_dns_wizard_callback(query, context, callback_data):
    """Handle DNS wizard step callbacks: dns_wizard:{domain}:{type}:{field}:{value}"""
    user = query.from_user
    
    try:
        # Parse: dns_wizard:{domain}:{type}:{field}:{value}
        parts = callback_data.split(':', 4)
        if len(parts) < 5:
            await safe_edit_message(query, create_error_message("Invalid wizard step"))
            return
        
        domain = parts[1]
        record_type = parts[2]
        field = parts[3]
        value = parts[4]
        
        # Get or initialize wizard state from context
        wizard_state = context.user_data.get('dns_wizard', {
            'domain': domain,
            'action': 'add',
            'type': record_type,
            'step': 1,
            'data': {}
        })
        
        # Update wizard data with new field value
        if field == "create" and value == "confirm":
            # Final step - create the DNS record
            await create_dns_record_from_wizard(query, context, wizard_state)
            return
        elif value == "back":
            # Handle back navigation by removing the last field
            # A Record back navigation
            if field == "name" and record_type == "A":
                # Going back from A name step - clear wizard completely
                wizard_state['data'] = {}
            elif field == "ip" and 'name' in wizard_state['data']:
                del wizard_state['data']['name']
            elif field == "ttl" and 'ip' in wizard_state['data']:
                del wizard_state['data']['ip']
            elif field == "proxied" and 'ttl' in wizard_state['data']:
                del wizard_state['data']['ttl']
            # TXT Record back navigation
            elif field == "name" and record_type == "TXT":
                # Going back from TXT name step - clear wizard completely
                wizard_state['data'] = {}
            elif field == "content" and 'name' in wizard_state['data']:
                del wizard_state['data']['name']
            elif field == "ttl" and 'content' in wizard_state['data']:
                del wizard_state['data']['content']
            # CNAME Record back navigation  
            elif field == "name" and record_type == "CNAME":
                # Going back from CNAME name step - clear wizard completely
                wizard_state['data'] = {}
            elif field == "target" and 'name' in wizard_state['data']:
                del wizard_state['data']['name']
            elif field == "ttl" and 'target' in wizard_state['data']:
                del wizard_state['data']['target']
            # MX Record back navigation
            elif field == "name" and record_type == "MX":
                # Going back from MX name step - clear wizard completely  
                wizard_state['data'] = {}
            elif field == "server" and 'name' in wizard_state['data']:
                del wizard_state['data']['name']
            elif field == "priority" and 'server' in wizard_state['data']:
                del wizard_state['data']['server']
            elif field == "ttl" and 'priority' in wizard_state['data']:
                del wizard_state['data']['priority']
        else:
            # Store the field value
            wizard_state['data'][field] = value
        
        # Store bot message ID for later editing
        if hasattr(query, 'message') and query.message:
            wizard_state['bot_message_id'] = query.message.message_id
        
        # Update context with modified state
        context.user_data['dns_wizard'] = wizard_state
        
        # Continue to next step based on record type
        if record_type == "A":
            await continue_a_record_wizard(query, context, wizard_state)
        elif record_type == "CNAME":
            await continue_cname_record_wizard(query, context, wizard_state)
        elif record_type == "TXT":
            await continue_txt_record_wizard(query, context, wizard_state)
        elif record_type == "MX":
            await continue_mx_record_wizard(query, context, wizard_state)
        else:
            await safe_edit_message(query, create_error_message("Unknown record type"))
            
    except Exception as e:
        logger.error(f"Error in DNS wizard callback: {e}")
        await safe_edit_message(query, "❌ <b>Wizard error</b>\n\nPlease try again.")

async def continue_a_record_wizard(query, context, wizard_state):
    """Continue A record wizard based on current data"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    if 'name' not in data:
        # Step 1: Dynamic Name Selection for A Record
        # Get Cloudflare zone to check existing records
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
            
        # Get available names for A records
        available_names = await get_available_names_for_record_type(domain, 'A', cf_zone['cf_zone_id'])
        
        if not available_names:
            await safe_edit_message(query, 
                f"❌ <b>No Available Names</b>\n\n"
                f"All common names have CNAME records.\n\n"
                f"Delete CNAME records or use different subdomain."
            )
            return
            
        message = f"🅰️ <b>A Record - {domain}</b>\n\n<b>Choose available name:</b>"
        
        # Create dynamic buttons
        keyboard = []
        row = []
        for name_info in available_names[:6]:  # Limit to first 6 options
            button_text = f"{name_info['display']}"
            row.append(InlineKeyboardButton(button_text, callback_data=f"dns_wizard:{domain}:A:name:{name_info['name']}"))
            if len(row) == 2:  # 2 buttons per row
                keyboard.append(row)
                row = []
        if row:  # Add remaining buttons
            keyboard.append(row)
            
        keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain}:add")])
    elif 'ip' not in data:
        # Step 2: IP Address
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"""
🅰️ Add A Record (2/4): {domain}

Name: {name_display}

Enter the IPv4 address this record should point to.
"""
        keyboard = [
            [InlineKeyboardButton("Use 8.8.8.8", callback_data=f"dns_wizard:{domain}:A:ip:8.8.8.8")],
            [InlineKeyboardButton("Use 1.1.1.1", callback_data=f"dns_wizard:{domain}:A:ip:1.1.1.1")],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:A:name:back")]
        ]
    elif 'ttl' not in data:
        # Step 3: TTL
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"""
🅰️ Add A Record (3/4): {domain}

Name: {name_display}
IP: {data['ip']}

Select TTL (Time To Live):
"""
        keyboard = [
            [InlineKeyboardButton("Auto (Recommended)", callback_data=f"dns_wizard:{domain}:A:ttl:1")],
            [InlineKeyboardButton("5 minutes", callback_data=f"dns_wizard:{domain}:A:ttl:300")],
            [InlineKeyboardButton("1 hour", callback_data=f"dns_wizard:{domain}:A:ttl:3600"),
             InlineKeyboardButton("1 day", callback_data=f"dns_wizard:{domain}:A:ttl:86400")],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:A:ip:back")]
        ]
    elif 'proxied' not in data:
        # Step 4: Proxy Setting with IP Validation
        name_display = data['name'] if data['name'] != '@' else domain
        ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
        ip_address = data['ip']
        
        # Check if IP can be proxied
        can_proxy = is_ip_proxyable(ip_address)
        
        if can_proxy:
            # Public IP - show both options
            message = f"""
🅰️ Add A Record (4/4): {domain}

Name: {name_display}
IP: {data['ip']}
TTL: {ttl_display}

Select Proxy setting:

🟠 Proxied - Traffic goes through Cloudflare (faster, protected)
⚪ Direct - Traffic goes directly to your server
"""
            keyboard = [
                [InlineKeyboardButton("🟠 Proxied (Recommended)", callback_data=f"dns_wizard:{domain}:A:proxied:true")],
                [InlineKeyboardButton("⚪ Direct", callback_data=f"dns_wizard:{domain}:A:proxied:false")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:A:ttl:back")]
            ]
        else:
            # Private/Reserved IP - only show direct option with explanation
            message = f"""
🅰️ Add A Record (4/4): {domain}

Name: {name_display}
IP: {data['ip']}
TTL: {ttl_display}

🚫 Proxy mode not available for this IP

Private IP addresses cannot use proxy mode because they're not reachable from the internet.

Available option:
⚪ Direct - Traffic goes directly to your server
"""
            keyboard = [
                [InlineKeyboardButton("⚪ Direct (Only Option)", callback_data=f"dns_wizard:{domain}:A:proxied:false")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:A:ttl:back")]
            ]
    else:
        # Step 5: Confirmation
        await show_a_record_confirmation(query, wizard_state)
        return
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def create_dns_record_from_wizard(query, context, wizard_state):
    """Create DNS record from wizard state with proper validation"""
    user = query.from_user
    domain = wizard_state['domain']
    record_type = wizard_state['type']
    data = wizard_state['data']
    
    try:
        # Special validation for CNAME records
        if record_type == "CNAME":
            record_name = data['name'] if data['name'] != '@' else domain
            cf_zone = await get_cloudflare_zone(domain)
            if cf_zone:
                cloudflare = CloudflareService()
                zone_id = cf_zone['cf_zone_id']
                
                # Check for existing records at the same name
                existing_records = await cloudflare.list_dns_records(zone_id)
                if existing_records:
                    conflicting_records = [r for r in existing_records if r.get('name') == record_name and r.get('type') != 'CNAME']
                    
                    if conflicting_records:
                        conflict_types = [str(r.get('type', 'Unknown')) for r in conflicting_records if r.get('type')]
                        await safe_edit_message(query, 
                            f"❌ CNAME Conflict\n\n"
                            f"Cannot create CNAME for {data['name']} due to existing {', '.join(conflict_types)} records.\n\n"
                            f"Use different subdomain or delete conflicting records."
                        )
                        return
        # Validate required data
        if record_type == "A":
            if not all(k in data for k in ['name', 'ip', 'ttl', 'proxied']):
                await safe_edit_message(query, "❌ Incomplete Data\n\nPlease complete all wizard steps.")
                return
        elif record_type == "TXT":
            if not all(k in data for k in ['name', 'content', 'ttl']):
                await safe_edit_message(query, "❌ Incomplete Data\n\nPlease complete all wizard steps.")
                return
        elif record_type == "CNAME":
            if not all(k in data for k in ['name', 'target', 'ttl']):
                await safe_edit_message(query, "❌ Incomplete Data\n\nPlease complete all wizard steps.")
                return
        elif record_type == "MX":
            if not all(k in data for k in ['name', 'server', 'priority', 'ttl']):
                await safe_edit_message(query, "❌ Incomplete Data\n\nPlease complete all wizard steps.")
                return
        
        # Get user record and verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
        
        # Show creating message
        await safe_edit_message(query, "🔄 Creating DNS Record...\n\nPlease wait...")
        
        # Create DNS record using CloudflareService
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        
        # Prepare record data based on type
        record_name = data['name'] if data['name'] != '@' else domain
        record_proxied = False  # Default for non-A records
        record_priority = None  # Initialize for MX records
        
        if record_type == "A":
            record_content = data['ip']
            record_proxied = data['proxied'] == 'true'
            # For proxied A records, force TTL to Auto (1) as recommended by Cloudflare
            if record_proxied:
                record_ttl = 1  # Auto TTL for proxied records
            else:
                record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1
        elif record_type == "TXT":
            record_content = data['content']
            # For non-A records, use the selected TTL
            record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        elif record_type == "CNAME":
            record_content = data['target']
            # For non-A records, use the selected TTL
            record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        elif record_type == "MX":
            # MX records need special handling for priority
            record_content = data['server']
            record_priority = int(data['priority'])
            # For non-A records, use the selected TTL
            record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        else:
            # Fallback for unknown record types
            record_content = data.get('content', '')
            record_priority = None  # Initialize for LSP
            # For non-A records, use the selected TTL
            record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        
        # Create the record (proxy parameter only for A records, priority for MX records)
        if record_type == "A":
            result = await cloudflare.create_dns_record(
                zone_id=zone_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl,
                proxied=record_proxied
            )
        elif record_type == "MX":
            result = await cloudflare.create_dns_record(
                zone_id=zone_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl,
                priority=record_priority
            )
        else:
            result = await cloudflare.create_dns_record(
                zone_id=zone_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl
            )
        
        if result and result.get('success'):
            # Success - clear wizard state and show success message
            if 'dns_wizard' in context.user_data:
                del context.user_data['dns_wizard']
            
            record_info = result.get('result', {})
            name_display = record_info.get('name', record_name)
            content_display = record_info.get('content', record_content)
            
            if record_type == "A":
                proxy_display = "🟠 Proxied" if record_proxied else "⚪ Direct"
                message = f"""
✅ {record_type} Record Created ({proxy_display})
{name_display} → {content_display}
"""
            elif record_type == "TXT":
                content_preview = content_display[:80] + "..." if len(content_display) > 80 else content_display
                message = f"""
✅ {record_type} Record Created
{name_display}: {content_preview}
"""
            elif record_type == "CNAME":
                message = f"""
✅ {record_type} Record Created
{name_display} → {content_display}
"""
            elif record_type == "MX":
                message = f"""
✅ {record_type} Record Created
{name_display} → {content_display} (Priority: {data['priority']})
"""
            else:
                # Default message for other record types
                message = f"""
✅ {record_type} Record Created
{name_display}: {content_display}
"""
            
            keyboard = [
                [InlineKeyboardButton("🌐 View DNS Dashboard", callback_data=f"dns:{domain}:view")],
                [InlineKeyboardButton("➕ Add Another Record", callback_data=f"dns:{domain}:add")],
                [InlineKeyboardButton("⬅️ Back to Domains", callback_data="my_domains")]
            ]
        else:
            # Failed - show error with details
            error_msg = "Unknown error occurred"
            if result and result.get('errors'):
                errors = result.get('errors', [])
                if errors:
                    error_msg = errors[0].get('message', error_msg)
            
            message = f"""
❌ DNS Record Creation Failed

Error: {error_msg}

Please check your settings and try again.
"""
            
            keyboard = [
                [InlineKeyboardButton("🔄 Try Again", callback_data=f"dns:{domain}:add:{record_type}")],
                [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain}:view")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error creating DNS record: {e}")
        # Clear wizard state on error
        if 'dns_wizard' in context.user_data:
            del context.user_data['dns_wizard']
        
        message = f"""
❌ DNS Record Creation Error

An unexpected error occurred while creating the DNS record.

Please try again or contact {BrandConfig().support_contact} if the problem persists.
"""
        
        keyboard = [
            [InlineKeyboardButton("🔄 Try Again", callback_data=f"dns:{domain}:add")],
            [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain}:view")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)

async def show_a_record_confirmation(query, wizard_state):
    """Show A record confirmation before creation"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    name_display = data['name'] if data['name'] != '@' else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    proxy_display = "🟠 Proxied" if data['proxied'] == "true" else "⚪ Direct"
    
    message = f"""
✅ Confirm A Record Creation

Domain: {domain}
Name: {name_display}
Points to: {data['ip']}
TTL: {ttl_display}
Proxy: {proxy_display}

This will create:
{name_display} → {data['ip']}

Ready to create this DNS record?
"""
    
    keyboard = [
        [InlineKeyboardButton("✅ Create Record", callback_data=f"dns_wizard:{domain}:A:create:confirm")],
        [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:A:proxied:back"),
         InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:view")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def show_txt_record_confirmation(query, wizard_state):
    """Show TXT record confirmation before creation"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    name_display = data['name'] if data['name'] != '@' else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    content_display, parse_mode = escape_content_for_display(data['content'], mode="full")
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
✅ Create TXT Record - Final Confirmation

Domain: {domain}
Type: TXT
Name: {name_summary}
Content: {content_display}
TTL: {ttl_display}

Ready to create this DNS record?
"""
    
    keyboard = [
        [InlineKeyboardButton("✅ Create Record", callback_data=f"dns_wizard:{domain}:TXT:create:confirm")],
        [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:TXT:ttl:back"),
         InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:view")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def show_cname_record_confirmation(query, wizard_state):
    """Show CNAME record confirmation before creation"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    name_display = data['name'] if data['name'] != '@' else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    target_display, parse_mode = escape_content_for_display(data['target'], mode="full")
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
✅ Create CNAME Record - Final Confirmation

Domain: {domain}
Type: CNAME
Name: {name_summary}
Target: {target_display}
TTL: {ttl_display}

Ready to create this DNS record?
"""
    
    keyboard = [
        [InlineKeyboardButton("✅ Create Record", callback_data=f"dns_wizard:{domain}:CNAME:create:confirm")],
        [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:CNAME:ttl:back"),
         InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:view")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def show_mx_record_confirmation(query, wizard_state):
    """Show MX record confirmation before creation"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    name_display = data['name'] if data['name'] != '@' else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    server_display, parse_mode = escape_content_for_display(data['server'], mode="full")
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
✅ Create MX Record - Final Confirmation

Domain: {domain}
Type: MX
Name: {name_summary}
Mail Server: {server_display}
Priority: {data['priority']}
TTL: {ttl_display}

Ready to create this DNS record?
"""
    
    keyboard = [
        [InlineKeyboardButton("✅ Create Record", callback_data=f"dns_wizard:{domain}:MX:create:confirm")],
        [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:MX:ttl:back"),
         InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:view")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def continue_cname_record_wizard(query, context, wizard_state):
    """Continue CNAME record wizard based on current data"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    if 'name' not in data:
        # Step 1: Dynamic Name Selection
        # Get Cloudflare zone to check existing records
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
            
        # Get available names for CNAME
        available_names = await get_available_names_for_record_type(domain, 'CNAME', cf_zone['cf_zone_id'])
        
        if not available_names:
            await safe_edit_message(query, 
                f"❌ <b>No Available Names</b>\n\n"
                f"All common subdomains have conflicting records.\n\n"
                f"Delete existing records or use custom subdomain."
            )
            return
            
        message = f"🔗 CNAME Record - {domain}\n\nChoose available subdomain:"
        
        # Create dynamic buttons (max 3 per row)
        keyboard = []
        row = []
        for name_info in available_names[:6]:  # Limit to first 6 options
            button_text = f"{name_info['display']}"
            row.append(InlineKeyboardButton(button_text, callback_data=f"dns_wizard:{domain}:CNAME:name:{name_info['name']}"))
            if len(row) == 2:  # 2 buttons per row
                keyboard.append(row)
                row = []
        if row:  # Add remaining buttons
            keyboard.append(row)
            
        keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain}:add")])
    elif 'target' not in data:
        # Step 2: Target Domain
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"""
🔗 Add CNAME Record (2/3): {domain}

Name: {escape_content_for_display(name_display, mode="summary")[0]}

Enter the target domain this CNAME should point to.

Enter full domain name with extension.
"""
        keyboard = [
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:CNAME:name:back")]
        ]
    elif 'ttl' not in data:
        # Step 3: TTL
        name_display = data['name'] if data['name'] != '@' else domain
        target_preview = escape_content_for_display(data['target'], mode="summary")
        message = f"""
🔗 Add CNAME Record (3/3): {domain}

Name: {escape_content_for_display(name_display, mode="summary")[0]}
Target: {target_preview[0] if isinstance(target_preview, tuple) else target_preview}

Select TTL (Time To Live):
"""
        keyboard = [
            [InlineKeyboardButton("Auto (Recommended)", callback_data=f"dns_wizard:{domain}:CNAME:ttl:1")],
            [InlineKeyboardButton("5 minutes", callback_data=f"dns_wizard:{domain}:CNAME:ttl:300")],
            [InlineKeyboardButton("1 hour", callback_data=f"dns_wizard:{domain}:CNAME:ttl:3600"),
             InlineKeyboardButton("1 day", callback_data=f"dns_wizard:{domain}:CNAME:ttl:86400")],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:CNAME:target:back")]
        ]
    else:
        # Step 4: Confirmation
        await show_cname_record_confirmation(query, wizard_state)
        return
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def continue_txt_record_wizard(query, context, wizard_state):
    """Continue TXT record wizard based on current data"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    if 'name' not in data:
        # Step 1: Dynamic Name Selection for TXT Record
        # Get Cloudflare zone to check existing records
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
            
        # Get available names for TXT records
        available_names = await get_available_names_for_record_type(domain, 'TXT', cf_zone['cf_zone_id'])
        
        if not available_names:
            await safe_edit_message(query, 
                f"❌ <b>No Available Names</b>\n\n"
                f"All common names have CNAME records.\n\n"
                f"Delete CNAME records or use different subdomain."
            )
            return
            
        message = f"📝 TXT Record - {domain}\n\nChoose available name:"
        
        # Create dynamic buttons
        keyboard = []
        row = []
        for name_info in available_names[:6]:  # Limit to first 6 options
            button_text = f"{name_info['display']}"
            row.append(InlineKeyboardButton(button_text, callback_data=f"dns_wizard:{domain}:TXT:name:{name_info['name']}"))
            if len(row) == 2:  # 2 buttons per row
                keyboard.append(row)
                row = []
        if row:  # Add remaining buttons
            keyboard.append(row)
            
        keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain}:add")])
    elif 'content' not in data:
        # Step 2: TXT Content
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"📝 TXT Value\n\nExample: v=spf1 include:_spf.google.com ~all"
        keyboard = [
            [InlineKeyboardButton("SPF Record", callback_data=await compress_callback(f"dns_wizard:{domain}:TXT:content:v=spf1 include:_spf.google.com ~all", context))],
            [InlineKeyboardButton("Google Verification", callback_data=await compress_callback(f"dns_wizard:{domain}:TXT:content:google-site-verification=YOUR_CODE_HERE", context))],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:TXT:name:back")]
        ]
    elif 'ttl' not in data:
        # Step 3: TTL
        name_display = data['name'] if data['name'] != '@' else domain
        content_preview = escape_content_for_display(data['content'], mode="full")  # Use full mode for safe HTML
        name_safe = escape_content_for_display(name_display, mode="full")
        message = f"📝 TTL Selection\n\n{name_safe[0]} → {content_preview[0]}"
        keyboard = [
            [InlineKeyboardButton("Auto (Recommended)", callback_data=f"dns_wizard:{domain}:TXT:ttl:1")],
            [InlineKeyboardButton("5 minutes", callback_data=f"dns_wizard:{domain}:TXT:ttl:300")],
            [InlineKeyboardButton("1 hour", callback_data=f"dns_wizard:{domain}:TXT:ttl:3600"),
             InlineKeyboardButton("1 day", callback_data=f"dns_wizard:{domain}:TXT:ttl:86400")],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:TXT:content:back")]
        ]
    else:
        # Step 4: Confirmation
        await show_txt_record_confirmation(query, wizard_state)
        return
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Use HTML parse mode for TTL step to safely display user content
    parse_mode = ParseMode.HTML
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode=parse_mode)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def continue_mx_record_wizard(query, context, wizard_state):
    """Continue MX record wizard based on current data"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    
    if 'name' not in data:
        # Step 1: Dynamic Name Selection for MX Record
        # Get Cloudflare zone to check existing records
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
            
        # Get available names for MX records
        available_names = await get_available_names_for_record_type(domain, 'MX', cf_zone['cf_zone_id'])
        
        if not available_names:
            await safe_edit_message(query, 
                f"❌ <b>No Available Names</b>\n\n"
                f"All common names have CNAME records.\n\n"
                f"Delete CNAME records or use different subdomain."
            )
            return
            
        message = f"📧 MX Record - {domain}\n\nChoose available name:"
        
        # Create dynamic buttons
        keyboard = []
        row = []
        for name_info in available_names[:6]:  # Limit to first 6 options
            button_text = f"{name_info['display']}"
            row.append(InlineKeyboardButton(button_text, callback_data=f"dns_wizard:{domain}:MX:name:{name_info['name']}"))
            if len(row) == 2:  # 2 buttons per row
                keyboard.append(row)
                row = []
        if row:  # Add remaining buttons
            keyboard.append(row)
            
        keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain}:add")])
    elif 'server' not in data:
        # Step 2: Mail Server
        name_display = data['name'] if data['name'] != '@' else domain
        message = f"""
📧 Add MX Record (2/4): {domain}

Name: {escape_content_for_display(name_display, mode="summary")[0]}

Enter the mail server this MX record should point to.

Enter full hostname of your mail server.
"""
        keyboard = [
            [InlineKeyboardButton(f"Use mail.{domain}", callback_data=f"dns_wizard:{domain}:MX:server:mail.{domain}")],
            [InlineKeyboardButton("Use Google Workspace", callback_data=f"dns_wizard:{domain}:MX:server:aspmx.l.google.com")],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:MX:name:back")]
        ]
    elif 'priority' not in data:
        # Step 3: Priority
        name_display = data['name'] if data['name'] != '@' else domain
        server_preview = escape_content_for_display(data['server'], mode="summary")
        message = f"""
📧 Add MX Record (3/4): {domain}

Name: {escape_content_for_display(name_display, mode="summary")[0]}
Server: {server_preview[0] if isinstance(server_preview, tuple) else server_preview}

Select priority for this MX record:

Lower numbers = higher priority
• 10 = Primary mail server
• 20 = Secondary mail server  
• 30 = Backup mail server
"""
        keyboard = [
            [InlineKeyboardButton("10 (Primary)", callback_data=f"dns_wizard:{domain}:MX:priority:10")],
            [InlineKeyboardButton("20 (Secondary)", callback_data=f"dns_wizard:{domain}:MX:priority:20"),
             InlineKeyboardButton("30 (Backup)", callback_data=f"dns_wizard:{domain}:MX:priority:30")],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:MX:server:back")]
        ]
    elif 'ttl' not in data:
        # Step 4: TTL
        name_display = data['name'] if data['name'] != '@' else domain
        server_preview = escape_content_for_display(data['server'], mode="summary")
        message = f"""
📧 Add MX Record (4/4): {domain}

Name: {escape_content_for_display(name_display, mode="summary")[0]}
Server: {server_preview[0] if isinstance(server_preview, tuple) else server_preview}
Priority: {data['priority']}

Select TTL (Time To Live):
"""
        keyboard = [
            [InlineKeyboardButton("Auto (Recommended)", callback_data=f"dns_wizard:{domain}:MX:ttl:1")],
            [InlineKeyboardButton("5 minutes", callback_data=f"dns_wizard:{domain}:MX:ttl:300")],
            [InlineKeyboardButton("1 hour", callback_data=f"dns_wizard:{domain}:MX:ttl:3600"),
             InlineKeyboardButton("1 day", callback_data=f"dns_wizard:{domain}:MX:ttl:86400")],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:MX:priority:back")]
        ]
    else:
        # Step 5: Confirmation
        await show_mx_record_confirmation(query, wizard_state)
        return
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle all text messages (unified handler for domain search, registration, etc.)"""
    user = update.effective_user
    effective_message = update.effective_message
    
    if not effective_message or not effective_message.text:
        return
        
    text = effective_message.text.strip()
    
    # Check for hosting domain input context
    user_data = context.user_data or {}
    hosting_flow = user_data.get('hosting_flow')
    if hosting_flow in ['awaiting_new_domain', 'awaiting_existing_domain']:
        await handle_hosting_domain_input(update, context, text)
        return
    
    # Check for unified hosting flow context
    unified_flow = user_data.get('unified_flow')
    if unified_flow in ['awaiting_new_domain', 'awaiting_existing_domain']:
        await handle_unified_text_input(update, context, text)
        return
    
    # Check for bundle domain search context
    bundle_context = user_data.get('bundle_domain_search')
    if bundle_context:
        plan_id = bundle_context.get('plan_id')
        if plan_id:
            # Clear the bundle context
            user_data.pop('bundle_domain_search', None)
            await process_bundle_domain_search(update, context, text.lower().strip(), str(plan_id))
            return
    
    # Check for edit input context (IP address changes and TXT content changes)
    edit_input = user_data.get('edit_input')
    if edit_input and edit_input['type'] == 'ip':
        await handle_ip_input(update, context, text, edit_input)
        return
    elif edit_input and edit_input['type'] == 'content':
        await handle_content_input(update, context, text, edit_input)
        return
    elif edit_input and edit_input['type'] == 'cname_target':
        await handle_cname_target_input(update, context, text, edit_input)
        return
    elif edit_input and edit_input['type'] == 'mx_server':
        await handle_mx_server_input(update, context, text, edit_input)
        return
    
    # Check for nameserver input context  
    nameserver_input = user_data.get('expecting_nameserver_input')
    if nameserver_input:
        await handle_nameserver_input(update, context, text, nameserver_input)
        return
    
    # Check if user is in DNS wizard context expecting input
    dns_wizard = user_data.get('dns_wizard')
    if dns_wizard and dns_wizard.get('action') == 'add':
        wizard_data = dns_wizard.get('data', {})
        record_type = dns_wizard.get('type')
        
        if record_type == 'A' and 'name' in wizard_data and 'ip' not in wizard_data:
            # A record expecting IP input
            await handle_dns_wizard_ip_input(update, context, text, dns_wizard)
            return
        elif record_type == 'TXT' and 'name' in wizard_data and 'content' not in wizard_data:
            # TXT record expecting content input
            await handle_dns_wizard_txt_input(update, context, text, dns_wizard)
            return
        elif record_type == 'CNAME' and 'name' in wizard_data and 'target' not in wizard_data:
            # CNAME record expecting target input
            await handle_dns_wizard_cname_input(update, context, text, dns_wizard)
            return
        elif record_type == 'MX' and 'name' in wizard_data and 'server' not in wizard_data:
            # MX record expecting server input
            await handle_dns_wizard_mx_input(update, context, text, dns_wizard)
            return
    
    # Basic domain search functionality - only if not in wizard context
    if '.' in text and len(text) > 3:
        domain_name = text.lower().strip()
        
        # Only proceed if it's a valid domain name  
        if not is_valid_domain(domain_name):
            # For inline domain detection, show helpful error message
            error_msg = get_domain_validation_error(domain_name)
            if effective_message:
                await effective_message.reply_text(
                    create_warning_message(
                        "Domain Format Issue", 
                        f"{domain_name} - {error_msg}\n\nNeed help? Try typing: /search example.com"
                    ),
                    parse_mode='HTML'
                )
            return
            
        if effective_message:
            searching_msg = await effective_message.reply_text(
                f"🔄 <b>Searching {domain_name}</b>\n\n"
                "• Checking availability\n"
                "• Getting pricing\n" 
                "• Analyzing status...",
                parse_mode=ParseMode.HTML
            )
        else:
            return
        
        # Perform actual domain search
        try:
            availability = await openprovider.check_domain_availability(domain_name)
            
            if availability is None:
                # API error or no response - provide helpful fallback
                message = f"""
⚠️ Search Unavailable: {domain_name}

Service temporarily down. Try again in a few minutes.
"""
                keyboard = [
                    [InlineKeyboardButton("🔄 Try Again", callback_data="search_domains")],
                    [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
                ]
            elif availability.get('available'):
                # Domain is available - extract dynamic pricing
                price_info = availability.get('price_info', {})
                create_price = price_info.get('create_price', 0)
                currency = price_info.get('currency', 'EUR')
                is_premium = availability.get('premium', False)
                
                # Format pricing display using robust money formatting (price is already in USD after markup)
                if create_price > 0:
                    price_display = f"{format_money(create_price, currency, include_currency=True)}/year"
                else:
                    price_display = "Contact for pricing"
                
                message = f"""
✅ {domain_name} Available

{'Premium' if is_premium else 'Standard'} domain
{price_display}
"""
                keyboard = [
                    [InlineKeyboardButton(f"🛒 Register {domain_name}", callback_data=f"register_{domain_name}")],
                    [InlineKeyboardButton("🔍 Search Another", callback_data="search_domains")],
                    [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
                ]
            else:
                # Domain is not available
                message = f"""
❌ {domain_name} Unavailable

Already registered. Try .net, .org, or .io
"""
                keyboard = [
                    [InlineKeyboardButton("🔍 Search Another", callback_data="search_domains")],
                    [InlineKeyboardButton("⬅️ Back", callback_data="main_menu")]
                ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await searching_msg.edit_text(message, reply_markup=reply_markup)
            
        except Exception as e:
            logger.error(f"Error searching domain {domain_name}: {e}")
            await searching_msg.edit_text("❌ Error searching domain. Please try again.")
        
        return
    
    # Enhanced response for unrecognized text - help users get oriented
    message = """🤖 I didn't understand that message

• Use /start for the main menu
• Type a domain name to search (e.g., example.com)  
• Use the buttons below for quick actions"""
    
    keyboard = [
        [InlineKeyboardButton("🏠 Main Menu", callback_data="main_menu")],
        [InlineKeyboardButton("🔍 Search Domains", callback_data="search_domains")],
        [InlineKeyboardButton("💰 Hosting Plans", callback_data="unified_hosting_plans")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    if effective_message:
        await effective_message.reply_text(message, reply_markup=reply_markup)

# DNS Record Edit Wizard Functions  
async def continue_a_record_edit_wizard(query, context, wizard_state):
    """Continue A record edit wizard with auto-apply functionality"""
    user = query.from_user
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Initialize or get AutoApplySession
    session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'A')
    
    # Set original state from current wizard data if not already set
    if not session.original_state:
        await session.set_original_state(data)
    
    # Update session with current draft state
    session.draft_state = data.copy()
    
    # Check for validation errors and changes
    validation = session.validate_current_state()
    changes_summary = session.get_changes_summary()
    
    # Build display elements
    name_display = data['name'] if data['name'] != domain else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    proxy_display = "🟠 Proxied" if data['proxied'] == "true" else "⚪ Direct"
    
    # Status indicator based on validation and changes
    if validation['errors']:
        status_icon = "❌"
        status_text = "Validation Error"
    elif validation['has_changes']:
        if session.is_applying:
            status_icon = "🔄"
            status_text = "Applying..."
        else:
            status_icon = "⚡"
            status_text = "Auto-Apply Ready"
    else:
        status_icon = "✅"
        status_text = "Current State"
    
    # Build message with real-time status
    message = f"""
{status_icon} Edit A Record: {domain} • {status_text}

Current Configuration:
Name: {name_display} (read-only)
IP Address: {data['content']}
TTL: {ttl_display}
Proxy Status: {proxy_display}
"""
    
    # Add changes summary if there are changes
    if changes_summary:
        changes_text = "\n".join(f"• {change}" for change in changes_summary)
        message += f"\n⚡ Changes:\n{changes_text}\n"
    
    # Add validation errors if any
    if validation['errors']:
        error_text = "\n".join(f"• {error}" for error in validation['errors'].values())
        message += f"\n❌ Issues:\n{error_text}\n"
    
    message += "\nClick to modify fields:"
    
    # Build keyboard without Save Changes button
    keyboard = [
        [InlineKeyboardButton("📝 Change IP Address", callback_data=await compress_callback(f"dns_edit:{domain}:A:ip:{record_id}", context))],
        [InlineKeyboardButton("⏰ Change TTL", callback_data=await compress_callback(f"dns_edit:{domain}:A:ttl:{record_id}", context))],
        [InlineKeyboardButton("🔄 Toggle Proxy", callback_data=await compress_callback(f"dns_edit:{domain}:A:proxy:{record_id}", context))]
    ]
    
    # Add action buttons based on state
    action_row = []
    if validation['has_changes']:
        if validation['errors']:
            action_row.append(InlineKeyboardButton("🔄 Revert Changes", callback_data=await compress_callback(f"dns_edit:{domain}:A:revert:{record_id}", context)))
        elif session.is_applying:
            action_row.append(InlineKeyboardButton("⏸️ Applying...", callback_data="noop"))
    
    action_row.append(InlineKeyboardButton("❌ Cancel", callback_data=await compress_callback(f"dns:{domain}:record:{record_id}", context)))
    keyboard.append(action_row)
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Use safe_edit_message for centralized deduplication
    await safe_edit_message(query, message, reply_markup=reply_markup)
    
    # Trigger auto-apply if conditions are met
    if await session.should_auto_apply():
        asyncio.create_task(auto_apply_with_feedback(query, context, session))

async def continue_cname_record_edit_wizard(query, wizard_state):
    """Continue CNAME record edit wizard with auto-apply functionality"""
    user = query.from_user
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    original_data = wizard_state['original_data']
    
    # Initialize or get AutoApplySession
    session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'CNAME')
    
    # Set original state from wizard data if not already set
    if not session.original_state:
        await session.set_original_state(original_data)
    
    # Update session with current draft state
    session.draft_state = data.copy()
    
    # Check for validation errors and changes
    validation = session.validate_current_state()
    changes_summary = session.get_changes_summary()
    
    # Build display elements
    name_display = data['name'] if data['name'] != '@' else domain
    target_display, _ = escape_content_for_display(data['content'], mode="full")
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    
    # Status indicator based on validation and changes
    if validation['errors']:
        status_icon = "❌"
        status_text = "Validation Error"
    elif validation['has_changes']:
        if session.is_applying:
            status_icon = "🔄"
            status_text = "Applying..."
        else:
            status_icon = "⚡"
            status_text = "Auto-Apply Ready"
    else:
        status_icon = "✅"
        status_text = "Current State"
    
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
{status_icon} Edit CNAME Record: {domain} • {status_text}

Name: {name_summary}
Target: {target_display}
TTL: {ttl_display}
"""
    
    # Add changes summary if there are changes
    if changes_summary:
        changes_text = "\n".join(f"• {change}" for change in changes_summary)
        message += f"\n\n⚡ Changes:\n{changes_text}"
    
    # Add validation errors if any
    if validation['errors']:
        error_text = "\n".join(f"• {error}" for error in validation['errors'].values())
        message += f"\n\n❌ Issues:\n{error_text}"
    
    message += "\n\nClick to modify fields:"
    
    # Build keyboard without Save Changes button
    keyboard = [
        [InlineKeyboardButton("📝 Edit Target", callback_data=f"dns_edit:{domain}:CNAME:content:{record_id}")],
        [InlineKeyboardButton("⏱️ Edit TTL", callback_data=f"dns_edit:{domain}:CNAME:ttl:{record_id}")]
    ]
    
    # Add action buttons based on state
    action_row = []
    if validation['has_changes']:
        if validation['errors']:
            action_row.append(InlineKeyboardButton("🔄 Revert Changes", callback_data=f"dns_edit:{domain}:CNAME:revert:{record_id}"))
        elif session.is_applying:
            action_row.append(InlineKeyboardButton("⏸️ Applying...", callback_data="noop"))
    
    action_row.append(InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:record:{record_id}"))
    keyboard.append(action_row)
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        # Trigger auto-apply if conditions are met
        if await session.should_auto_apply():
            asyncio.create_task(auto_apply_with_feedback(query, None, session))
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def continue_txt_record_edit_wizard(query, wizard_state):
    """Continue TXT record edit wizard with auto-apply functionality"""
    user = query.from_user
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    original_data = wizard_state['original_data']
    
    # Initialize or get AutoApplySession
    session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'TXT')
    
    # Set original state from wizard data if not already set
    if not session.original_state:
        await session.set_original_state(original_data)
    
    # Update session with current draft state
    session.draft_state = data.copy()
    
    # Check for validation errors and changes
    validation = session.validate_current_state()
    changes_summary = session.get_changes_summary()
    
    # Build display elements
    name_display = data['name'] if data['name'] != '@' else domain
    content_display, _ = escape_content_for_display(data['content'], mode="full")
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    
    # Status indicator based on validation and changes
    if validation['errors']:
        status_icon = "❌"
        status_text = "Validation Error"
    elif validation['has_changes']:
        if session.is_applying:
            status_icon = "🔄"
            status_text = "Applying..."
        else:
            status_icon = "⚡"
            status_text = "Auto-Apply Ready"
    else:
        status_icon = "✅"
        status_text = "Current State"
    
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
{status_icon} Edit TXT Record: {domain} • {status_text}

Name: {name_summary}
Content: {content_display}
TTL: {ttl_display}
"""
    
    # Add changes summary if there are changes
    if changes_summary:
        changes_text = "\n".join(f"• {change}" for change in changes_summary)
        message += f"\n\n⚡ Changes:\n{changes_text}"
    
    # Add validation errors if any
    if validation['errors']:
        error_text = "\n".join(f"• {error}" for error in validation['errors'].values())
        message += f"\n\n❌ Issues:\n{error_text}"
    
    message += "\n\nClick to modify fields:"
    
    # Build keyboard without Save Changes button
    keyboard = [
        [InlineKeyboardButton("📝 Edit Content", callback_data=f"dns_edit:{domain}:TXT:content:{record_id}")],
        [InlineKeyboardButton("⏱️ Edit TTL", callback_data=f"dns_edit:{domain}:TXT:ttl:{record_id}")]
    ]
    
    # Add action buttons based on state
    action_row = []
    if validation['has_changes']:
        if validation['errors']:
            action_row.append(InlineKeyboardButton("🔄 Revert Changes", callback_data=f"dns_edit:{domain}:TXT:revert:{record_id}"))
        elif session.is_applying:
            action_row.append(InlineKeyboardButton("⏸️ Applying...", callback_data="noop"))
    
    action_row.append(InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:record:{record_id}"))
    keyboard.append(action_row)
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        # Trigger auto-apply if conditions are met
        if await session.should_auto_apply():
            asyncio.create_task(auto_apply_with_feedback(query, None, session))
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def continue_mx_record_edit_wizard(query, wizard_state):
    """Continue MX record edit wizard with auto-apply functionality"""
    user = query.from_user
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    original_data = wizard_state['original_data']
    
    # Initialize or get AutoApplySession
    session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'MX')
    
    # Set original state from wizard data if not already set
    if not session.original_state:
        await session.set_original_state(original_data)
    
    # Update session with current draft state
    session.draft_state = data.copy()
    
    # Check for validation errors and changes
    validation = session.validate_current_state()
    changes_summary = session.get_changes_summary()
    
    # Build display elements
    name_display = data['name'] if data['name'] != '@' else domain
    server_display, _ = escape_content_for_display(data['content'], mode="full")
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    priority = data.get('priority', '10')
    
    # Status indicator based on validation and changes
    if validation['errors']:
        status_icon = "❌"
        status_text = "Validation Error"
    elif validation['has_changes']:
        if session.is_applying:
            status_icon = "🔄"
            status_text = "Applying..."
        else:
            status_icon = "⚡"
            status_text = "Auto-Apply Ready"
    else:
        status_icon = "✅"
        status_text = "Current State"
    
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
{status_icon} Edit MX Record: {domain} • {status_text}

Name: {name_summary}
Mail Server: {server_display}
Priority: {priority}
TTL: {ttl_display}
"""
    
    # Add changes summary if there are changes
    if changes_summary:
        changes_text = "\n".join(f"• {change}" for change in changes_summary)
        message += f"\n\n⚡ Changes:\n{changes_text}"
    
    # Add validation errors if any
    if validation['errors']:
        error_text = "\n".join(f"• {error}" for error in validation['errors'].values())
        message += f"\n\n❌ Issues:\n{error_text}"
    
    message += "\n\nClick to modify fields:"
    
    # Build keyboard without Save Changes button
    keyboard = [
        [InlineKeyboardButton("📝 Edit Server", callback_data=f"dns_edit:{domain}:MX:content:{record_id}")],
        [InlineKeyboardButton("🔢 Edit Priority", callback_data=f"dns_edit:{domain}:MX:priority:{record_id}")],
        [InlineKeyboardButton("⏱️ Edit TTL", callback_data=f"dns_edit:{domain}:MX:ttl:{record_id}")]
    ]
    
    # Add action buttons based on state
    action_row = []
    if validation['has_changes']:
        if validation['errors']:
            action_row.append(InlineKeyboardButton("🔄 Revert Changes", callback_data=f"dns_edit:{domain}:MX:revert:{record_id}"))
        elif session.is_applying:
            action_row.append(InlineKeyboardButton("⏸️ Applying...", callback_data="noop"))
    
    action_row.append(InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:record:{record_id}"))
    keyboard.append(action_row)
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup, parse_mode='HTML')
        
        # Trigger auto-apply if conditions are met
        if await session.should_auto_apply():
            asyncio.create_task(auto_apply_with_feedback(query, None, session))
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def handle_delete_callback(query, context, callback_data):
    """Handle shortened delete callback: del:{record_id}"""
    try:
        # Extract record_id from callback data
        parts = callback_data.split(':')
        if len(parts) != 2:
            await safe_edit_message(query, "❌ Invalid Delete Action\n\nPlease try again.")
            return
        
        record_id = parts[1]
        
        # Get domain from stored context
        delete_context = context.user_data.get('delete_context')
        if not delete_context or delete_context.get('record_id') != record_id:
            await safe_edit_message(query, "❌ Session Expired\n\nPlease try the delete action again.")
            return
        
        domain = delete_context['domain']
        
        # Clean up context and execute deletion
        if 'delete_context' in context.user_data:
            del context.user_data['delete_context']
        
        await execute_dns_delete(query, context, domain, record_id)
        
    except Exception as e:
        logger.error(f"Error handling delete callback {callback_data}: {e}")
        await safe_edit_message(query, "❌ Delete Error\n\nCould not process deletion. Please try again.")

async def prompt_for_content_change(query, context, domain, record_id):
    """Prompt user to enter new TXT content"""
    message = f"""
📝 Change TXT Content

Domain: {domain}

Please type the new content for this TXT record.

Type your new TXT content:
"""
    
    # Store context for text input handling
    context.user_data['edit_input'] = {
        'type': 'content',
        'domain': domain,
        'record_id': record_id
    }
    
    keyboard = [
        [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def prompt_for_ip_change(query, context, domain, record_id):
    """Prompt user to enter a new IP address"""
    message = f"""
📝 Change IP Address

Domain: {domain}

Please type the new IP address for this A record.

Example: 192.168.1.1 or 8.8.8.8

Type your new IP address:
"""
    
    # Store context for text input handling
    context.user_data['edit_input'] = {
        'type': 'ip',
        'domain': domain,
        'record_id': record_id
    }
    
    keyboard = [
        [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def prompt_for_cname_target_change(query, context, domain, record_id):
    """Prompt user to enter new CNAME target"""
    message = f"""
🔗 Change CNAME Target

Domain: {domain}

Please type the new target domain for this CNAME record.

Enter full domain name with extension.

Type your new CNAME target:
"""
    
    # Store context for text input handling
    context.user_data['edit_input'] = {
        'type': 'cname_target',
        'domain': domain,
        'record_id': record_id
    }
    
    keyboard = [
        [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def prompt_for_mx_server_change(query, context, domain, record_id):
    """Prompt user to enter new MX server"""
    message = f"""
📧 Change MX Server

Domain: {domain}

Please type the new mail server for this MX record.

Type your new MX server:
"""
    
    # Store context for text input handling
    context.user_data['edit_input'] = {
        'type': 'mx_server',
        'domain': domain,
        'record_id': record_id
    }
    
    keyboard = [
        [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def prompt_for_mx_priority_change(query, context, domain, record_id):
    """Prompt user to select new MX priority"""
    message = f"""
🔢 Change MX Priority

Domain: {domain}

Select the new priority for this MX record:

Lower numbers = higher priority
• 10 = Primary mail server
• 20 = Secondary mail server  
• 30 = Backup mail server
• 50 = Low priority backup

Choose your MX priority:
"""
    
    keyboard = [
        [InlineKeyboardButton("10 (Primary)", callback_data=f"edit_mx_priority:{record_id}:10"),
         InlineKeyboardButton("20 (Secondary)", callback_data=f"edit_mx_priority:{record_id}:20")],
        [InlineKeyboardButton("30 (Backup)", callback_data=f"edit_mx_priority:{record_id}:30"),
         InlineKeyboardButton("50 (Low Priority)", callback_data=f"edit_mx_priority:{record_id}:50")],
        [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            raise e

async def prompt_for_ttl_change(query, context, domain, record_id):
    """Show TTL selection buttons"""
    message = f"""
⏰ Change TTL (Time To Live)

Domain: {domain}

Select the new TTL for this DNS record:
"""
    
    keyboard = [
        [InlineKeyboardButton("🚀 Auto (Recommended)", callback_data=f"edit_ttl:{record_id}:1")],
        [InlineKeyboardButton("⚡ 1 minute", callback_data=f"edit_ttl:{record_id}:60")],
        [InlineKeyboardButton("🕐 5 minutes", callback_data=f"edit_ttl:{record_id}:300")],
        [InlineKeyboardButton("🕐 30 minutes", callback_data=f"edit_ttl:{record_id}:1800")],
        [InlineKeyboardButton("🕐 1 hour", callback_data=f"edit_ttl:{record_id}:3600")],
        [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:edit:{record_id}")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Prevent "Message is not modified" errors by checking current content
    try:
        await safe_edit_message(query, message, reply_markup=reply_markup)
    except Exception as e:
        if "Message is not modified" in str(e):
            # Message content is identical, just answer the callback
            logger.info(f"Prevented duplicate message update for user {query.from_user.id}")
        else:
            # Re-raise other errors
            raise e

async def toggle_proxy_setting(query, context, domain, record_id):
    """Toggle proxy setting for the DNS record with auto-apply"""
    try:
        user = query.from_user
        wizard_state = context.user_data.get('dns_wizard')
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, "❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get AutoApplySession
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'A')
        
        # Get current proxy setting and IP address
        current_proxied = wizard_state['data'].get('proxied', 'false')
        new_proxied = 'false' if current_proxied == 'true' else 'true'
        ip_address = wizard_state['data'].get('content', '')
        
        # If trying to enable proxy, validate IP first
        if new_proxied == 'true' and ip_address:
            if not is_ip_proxyable(ip_address):
                # Show error message with detailed explanation
                error_message = get_proxy_restriction_message(ip_address)
                
                keyboard = [
                    [InlineKeyboardButton("⬅️ Back to Edit", callback_data=await compress_callback(f"dns:{domain}:edit:{record_id}", context))]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await safe_edit_message(query, error_message, reply_markup=reply_markup)
                return
        
        # Update proxy setting using session
        session.update_field('proxied', new_proxied)
        
        # If enabling proxy, set TTL to Auto (1) as recommended by Cloudflare
        if new_proxied == 'true':
            session.update_field('ttl', '1')  # Auto TTL for proxied records (string for update_field)
            wizard_state['data']['ttl'] = 1  # Store as integer in wizard state
        
        # Update wizard state
        wizard_state['data']['proxied'] = new_proxied
        context.user_data['dns_wizard'] = wizard_state
        
        # Show updated edit interface with auto-apply
        await continue_a_record_edit_wizard(query, context, wizard_state)
        
    except Exception as e:
        logger.error(f"Error toggling proxy setting: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not toggle proxy setting.")

async def handle_dns_edit_callback(query, context, callback_data):
    """Handle DNS edit callback routing with auto-apply support"""
    try:
        # Parse callback: dns_edit:{domain}:{type}:{action}:{record_id}
        parts = callback_data.split(':')
        if len(parts) < 5:
            await safe_edit_message(query, "❌ Invalid Edit Action\n\nPlease try again.")
            return
        
        domain = parts[1]
        record_type = parts[2]
        action = parts[3]
        record_id = parts[4]
        
        # Handle different edit actions
        if action == "save":
            # Legacy save - redirect to record view since auto-apply handles saves now
            await safe_edit_message(query, "✅ Auto-Apply Active\n\nChanges are automatically applied when valid.")
            await asyncio.sleep(1.5)
            # Redirect to record view
            await show_dns_record_detail(query, domain, record_id)
        elif action == "revert":
            await handle_revert_changes(query, context, domain, record_type, record_id)
        elif action == "ip":
            await prompt_for_ip_change(query, context, domain, record_id)
        elif action == "content":
            # Handle content editing based on record type
            wizard_state = context.user_data.get('dns_wizard')
            if wizard_state and wizard_state.get('type') == 'CNAME':
                await prompt_for_cname_target_change(query, context, domain, record_id)
            elif wizard_state and wizard_state.get('type') == 'MX':
                await prompt_for_mx_server_change(query, context, domain, record_id)
            else:
                await prompt_for_content_change(query, context, domain, record_id)
        elif action == "priority":
            await prompt_for_mx_priority_change(query, context, domain, record_id)
        elif action == "ttl":
            await prompt_for_ttl_change(query, context, domain, record_id)
        elif action == "proxy":
            await toggle_proxy_setting(query, context, domain, record_id)
        else:
            await safe_edit_message(query, "❌ Unknown Edit Action\n\nPlease try again.")
            
    except Exception as e:
        logger.error(f"Error handling DNS edit callback {callback_data}: {e}")
        await safe_edit_message(query, "❌ Edit Error\n\nCould not process edit action.")

async def handle_revert_changes(query, context, domain, record_type, record_id):
    """Handle reverting changes back to original state"""
    try:
        user = query.from_user
        wizard_state = context.user_data.get('dns_wizard')
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, "❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get AutoApplySession and revert
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, record_type)
        session.revert_to_original()
        
        # Update wizard state to match reverted state
        wizard_state['data'] = session.draft_state.copy()
        context.user_data['dns_wizard'] = wizard_state
        
        # Show success message and return to editing
        await safe_edit_message(query, "🔄 Changes Reverted\n\nRecord restored to original state.")
        await asyncio.sleep(1.0)
        
        # Return to appropriate editing interface
        if record_type == 'A':
            await continue_a_record_edit_wizard(query, context, wizard_state)
        # Add other record types as they are implemented
        else:
            await show_dns_record_detail(query, domain, record_id)
            
    except Exception as e:
        logger.error(f"Error reverting changes for {record_type} record {record_id}: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not revert changes.")

async def handle_ttl_selection(query, context, callback_data):
    """Handle TTL selection with auto-apply: edit_ttl:{record_id}:{ttl_value}"""
    try:
        parts = callback_data.split(':')
        if len(parts) != 3:
            await safe_edit_message(query, "❌ Invalid TTL Selection\n\nPlease try again.")
            return
        
        record_id = parts[1]
        ttl_value = parts[2]
        user = query.from_user
        
        # Update wizard state with new TTL
        wizard_state = context.user_data.get('dns_wizard')
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, "❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get domain and record type for auto-apply session
        domain = wizard_state['domain']
        record_type = wizard_state.get('type', 'A').upper()
        
        # Get AutoApplySession and update TTL
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, record_type)
        validation = session.update_field('ttl', ttl_value)
        
        # Update wizard data (convert to integer to match validation expectations)
        wizard_state['data']['ttl'] = int(ttl_value)
        context.user_data['dns_wizard'] = wizard_state
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ TTL Update Failed\n\n{validation['errors'].get('ttl', 'Invalid TTL value')}"
            await safe_edit_message(query, error_message)
            return
        
        # Show updated edit interface with auto-apply (A records only for now)
        await continue_a_record_edit_wizard(query, context, wizard_state)
        
    except Exception as e:
        logger.error(f"Error handling TTL selection {callback_data}: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not update TTL.")

async def handle_mx_priority_selection(query, context, callback_data):
    """Handle MX priority selection: edit_mx_priority:{record_id}:{priority}"""
    try:
        parts = callback_data.split(':')
        if len(parts) != 3:
            await safe_edit_message(query, create_error_message("Invalid Priority Selection", "Please try again."))
            return
        
        record_id = parts[1]
        priority_value = parts[2]
        
        # Validate priority value
        try:
            priority = int(priority_value)
            if priority < 0 or priority > 65535:
                await safe_edit_message(query, create_error_message("Invalid Priority", "Priority must be between 0 and 65535."))
                return
        except ValueError:
            await safe_edit_message(query, create_error_message("Invalid Priority Format", "Priority must be a number."))
            return
        
        # Update wizard state with new priority
        wizard_state = context.user_data.get('dns_wizard')
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, "❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Update priority in wizard data
        wizard_state['data']['priority'] = priority_value
        context.user_data['dns_wizard'] = wizard_state
        
        # Show success message and return to edit interface
        await safe_edit_message(query, f"✅ Priority Updated\n\nNew priority: {priority}\n\nReturning to edit menu...")
        
        # Brief pause then show edit interface
        import asyncio
        await asyncio.sleep(1)
        await continue_mx_record_edit_wizard(query, wizard_state)
        
    except Exception as e:
        logger.error(f"Error handling MX priority selection {callback_data}: {e}")
        await safe_edit_message(query, "❌ Priority Update Error\n\nCould not update priority. Please try again.")

async def handle_content_input(update, context, text, edit_input):
    """Handle TXT content input during record editing with auto-apply"""
    try:
        # Validate TXT content
        content = text.strip()
        
        if not content:
            await update.message.reply_text(
                "❌ Empty Content\n\nPlease enter some content for the TXT record.\n\nTry again:"
            )
            return
        
        if len(content) > 4096:  # Cloudflare limit
            await update.message.reply_text(
                "❌ Content Too Long\n\nTXT content cannot exceed 4096 characters.\n\nTry again:"
            )
            return
        
        # Update wizard state and session
        wizard_state = context.user_data.get('dns_wizard')
        record_id = edit_input['record_id']
        domain = edit_input['domain']
        user = update.effective_user
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await update.message.reply_text("❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get AutoApplySession and update content
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'TXT')
        validation = session.update_field('content', content)
        
        # Update wizard data
        wizard_state['data']['content'] = content
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear edit input context
        if 'edit_input' in context.user_data:
            del context.user_data['edit_input']
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ Content Update Failed\n\n{validation['errors'].get('content', 'Invalid content')}\n\nPlease enter different content:"
            await update.message.reply_text(error_message)
            return
        
        # Show success message
        await update.message.reply_text(
            f"✅ Content Updated\n\nNew content: {content[:50]}{'...' if len(content) > 50 else ''}\n\n⚡ Auto-applying change..."
        )
        
        # Brief pause then show updated interface with auto-apply
        await asyncio.sleep(0.5)
        
        # Create a query adapter for the auto-apply edit wizard
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=update.message.message_id,
            user_id=user.id
        )
        
        await continue_txt_record_edit_wizard_as_message(update, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
            
    except Exception as e:
        logger.error(f"Error handling content input: {e}")
        await update.message.reply_text(
            "❌ Input Error\n\nPlease try again."
        )

async def continue_txt_record_edit_wizard_as_message(update, context, wizard_state):
    """Show TXT record edit wizard as a new message"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Build edit interface
    name_display = data['name'] if data['name'] != '@' else domain
    content_display, parse_mode = escape_content_for_display(data['content'], mode="full")
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    name_summary, _ = escape_content_for_display(name_display, mode="summary")
    
    message = f"""
📝 Edit TXT Record: {domain}

Name: {name_summary} (read-only)
Content: {content_display}
TTL: {ttl_display}

Click to modify any field below:
"""
    
    keyboard = [
        [InlineKeyboardButton("📝 Change Content", callback_data=f"dns_edit:{domain}:TXT:content:{record_id}")],
        [InlineKeyboardButton("⏰ Change TTL", callback_data=f"dns_edit:{domain}:TXT:ttl:{record_id}")],
        [InlineKeyboardButton("✅ Save Changes", callback_data=f"dns_edit:{domain}:TXT:save:{record_id}")],
        [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain}:record:{record_id}")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        message,
        reply_markup=reply_markup,
        parse_mode='HTML'
    )

async def handle_dns_wizard_txt_input(update, context, txt_content, wizard_state):
    """Handle TXT content input during DNS wizard"""
    try:
        # Validate TXT content (basic validation - not empty and reasonable length)
        txt_content = txt_content.strip()
        
        if not txt_content:
            await update.message.reply_text(
                "❌ Empty TXT Content\n\nPlease enter some content for your TXT record.\n\nTry again:"
            )
            return
        
        if len(txt_content) > 4096:  # Cloudflare limit for TXT records
            await update.message.reply_text(
                "❌ TXT Content Too Long\n\nTXT records cannot exceed 4096 characters.\n\nPlease enter shorter content:"
            )
            return
        
        # Update wizard state with TXT content
        wizard_state['data']['content'] = txt_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Get the bot's last message ID from wizard state (not user's input message)
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            # Fallback: send new message instead of editing
            await update.message.reply_text(
                "❌ <b>Wizard Error</b>\n\nPlease restart the DNS wizard."
            )
            return
            
        # Create adapter for continue_txt_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step
        await continue_txt_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
            
    except Exception as e:
        logger.error(f"Error handling TXT content input: {e}")
        await update.message.reply_text(
            "❌ Input Error\n\nPlease try entering your TXT content again:"
        )

async def handle_cname_target_input(update, context, target_content, edit_input):
    """Handle CNAME target input during record editing with auto-apply"""
    try:
        # Validate CNAME target
        target_content = target_content.strip()
        
        if not target_content:
            await update.message.reply_text(
                "❌ <b>Empty CNAME Target</b>\n\nPlease enter a target domain for your CNAME record.\n\nTry again:"
            )
            return
        
        # Update wizard state and session
        wizard_state = context.user_data.get('dns_wizard')
        record_id = edit_input['record_id']
        domain = edit_input['domain']
        user = update.effective_user
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await update.message.reply_text("❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get AutoApplySession and update target
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'CNAME')
        validation = session.update_field('content', target_content)
        
        # Update wizard data
        wizard_state['data']['content'] = target_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear edit input context
        if 'edit_input' in context.user_data:
            del context.user_data['edit_input']
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ Target Update Failed\n\n{validation['errors'].get('content', 'Invalid target domain')}\n\nPlease enter a different target:"
            await update.message.reply_text(error_message)
            return
        
        # Show success message
        await update.message.reply_text(
            f"✅ CNAME Target Updated\n\nNew target: {target_content}\n\n⚡ Auto-applying change..."
        )
        
        # Brief pause then show updated interface with auto-apply
        await asyncio.sleep(0.5)
        
        # Create a query adapter for the auto-apply edit wizard
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=update.message.message_id,
            user_id=user.id
        )
        
        await continue_cname_record_edit_wizard_as_message(update, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
        
    except Exception as e:
        logger.error(f"Error handling CNAME target input: {e}")
        await update.message.reply_text("❌ Error\n\nCould not process CNAME target.")

async def handle_mx_server_input(update, context, server_content, edit_input):
    """Handle MX server input during record editing with auto-apply"""
    try:
        # Validate MX server
        server_content = server_content.strip()
        
        if not server_content:
            await update.message.reply_text(
                "❌ <b>Empty Mail Server</b>\n\nPlease enter a mail server for your MX record.\n\nTry again:"
            )
            return
        
        # Update wizard state and session
        wizard_state = context.user_data.get('dns_wizard')
        record_id = edit_input['record_id']
        domain = edit_input['domain']
        user = update.effective_user
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await update.message.reply_text("❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get AutoApplySession and update server
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'MX')
        validation = session.update_field('content', server_content)
        
        # Update wizard data
        wizard_state['data']['content'] = server_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear edit input context
        if 'edit_input' in context.user_data:
            del context.user_data['edit_input']
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ <b>Server Update Failed</b>\n\n{validation['errors'].get('content', 'Invalid mail server')}\n\nPlease enter a different server:"
            await update.message.reply_text(error_message)
            return
        
        # Show success message
        await update.message.reply_text(
            f"✅ <b>MX Server Updated</b>\n\nNew server: <code>{server_content}</code>\n\n⚡ Auto-applying change..."
        )
        
        # Brief pause then show updated interface with auto-apply
        await asyncio.sleep(0.5)
        
        # Create a query adapter for the auto-apply edit wizard
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=update.message.message_id,
            user_id=user.id
        )
        
        await continue_mx_record_edit_wizard_as_message(update, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
        
    except Exception as e:
        logger.error(f"Error handling MX server input: {e}")
        await update.message.reply_text("❌ Error\n\nCould not process MX server.")

async def continue_cname_record_edit_wizard_as_message(update, context, wizard_state):
    """Show CNAME record edit wizard as a new message"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Show edit interface with editable fields
    name_display = data['name'] if data['name'] != domain else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    target_display, _ = escape_content_for_display(data['content'], mode="summary")
    
    message = f"""
✏️ <b>Edit CNAME Record: {domain}</b>

<b>Current Configuration:</b>
Name: <code>{name_display}</code> (read-only)
<b>Target:</b> <code>{target_display}</code>
TTL: {ttl_display}

<b>Click to modify any field below:</b>
"""
    
    keyboard = [
        [InlineKeyboardButton("📝 Change Target", callback_data=await compress_callback(f"dns_edit:{domain}:CNAME:content:{record_id}", context))],
        [InlineKeyboardButton("⏰ Change TTL", callback_data=await compress_callback(f"dns_edit:{domain}:CNAME:ttl:{record_id}", context))],
        [InlineKeyboardButton("✅ Save Changes", callback_data=await compress_callback(f"dns_edit:{domain}:CNAME:save:{record_id}", context))],
        [InlineKeyboardButton("❌ Cancel", callback_data=await compress_callback(f"dns:{domain}:record:{record_id}", context))]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, reply_markup=reply_markup)

async def continue_mx_record_edit_wizard_as_message(update, context, wizard_state):
    """Show MX record edit wizard as a new message"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Show edit interface with editable fields
    name_display = data['name'] if data['name'] != domain else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    server_display, _ = escape_content_for_display(data['content'], mode="summary")
    priority = data.get('priority', '10')
    
    message = f"""
✏️ <b>Edit MX Record: {domain}</b>

<b>Current Configuration:</b>
Name: <code>{name_display}</code> (read-only)
<b>Mail Server:</b> <code>{server_display}</code>
Priority: {priority}
TTL: {ttl_display}

<b>Click to modify any field below:</b>
"""
    
    keyboard = [
        [InlineKeyboardButton("📝 Change Server", callback_data=await compress_callback(f"dns_edit:{domain}:MX:content:{record_id}", context))],
        [InlineKeyboardButton("🔢 Change Priority", callback_data=await compress_callback(f"dns_edit:{domain}:MX:priority:{record_id}", context))],
        [InlineKeyboardButton("⏰ Change TTL", callback_data=await compress_callback(f"dns_edit:{domain}:MX:ttl:{record_id}", context))],
        [InlineKeyboardButton("✅ Save Changes", callback_data=await compress_callback(f"dns_edit:{domain}:MX:save:{record_id}", context))],
        [InlineKeyboardButton("❌ Cancel", callback_data=await compress_callback(f"dns:{domain}:record:{record_id}", context))]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, reply_markup=reply_markup)

async def handle_dns_wizard_cname_input(update, context, target_content, wizard_state):
    """Handle CNAME target input during DNS wizard"""
    try:
        # Validate CNAME target (basic validation - not empty and reasonable format)
        target_content = target_content.strip()
        
        if not target_content:
            await update.message.reply_text(
                "❌ <b>Empty CNAME Target</b>\n\nPlease enter a target domain for your CNAME record.\n\nTry again:"
            )
            return
        
        # Basic domain format validation (must contain a dot and be reasonable length)
        if '.' not in target_content or len(target_content) < 3:
            await update.message.reply_text(
                "❌ Invalid Domain Format\n\nPlease enter a valid domain name (e.g., example.com).\n\nTry again:"
            )
            return
        
        if len(target_content) > 253:  # RFC limit for domain names
            await update.message.reply_text(
                "❌ <b>Domain Name Too Long</b>\n\nDomain names cannot exceed 253 characters.\n\nPlease enter a shorter domain:"
            )
            return
        
        # Update wizard state with CNAME target
        wizard_state['data']['target'] = target_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Get the bot's last message ID from wizard state (not user's input message)
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            # Fallback: send new message instead of editing
            await update.message.reply_text(
                "❌ <b>Wizard Error</b>\n\nPlease restart the DNS wizard."
            )
            return
            
        # Create adapter for continue_cname_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step
        await continue_cname_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
            
    except Exception as e:
        logger.error(f"Error handling CNAME target input: {e}")
        await update.message.reply_text(
            "❌ <b>Input Error</b>\n\nPlease try entering your CNAME target again:"
        )

async def handle_dns_wizard_mx_input(update, context, server_content, wizard_state):
    """Handle MX server input during DNS wizard"""
    try:
        # Validate MX server (basic validation - not empty and reasonable format)
        server_content = server_content.strip()
        
        if not server_content:
            await update.message.reply_text(
                "❌ <b>Empty Mail Server</b>\n\nPlease enter a mail server for your MX record.\n\nTry again:"
            )
            return
        
        # Basic mail server format validation (must contain a dot and be reasonable length)
        if '.' not in server_content or len(server_content) < 3:
            await update.message.reply_text(
                "❌ <b>Invalid Server Format</b>\n\nPlease enter a valid mail server (e.g., mail.example.com).\n\nTry again:"
            )
            return
        
        if len(server_content) > 253:  # RFC limit for domain names
            await update.message.reply_text(
                "❌ <b>Server Name Too Long</b>\n\nServer names cannot exceed 253 characters.\n\nPlease enter a shorter server name:"
            )
            return
        
        # Update wizard state with MX server
        wizard_state['data']['server'] = server_content
        context.user_data['dns_wizard'] = wizard_state
        
        # Get the bot's last message ID from wizard state (not user's input message)
        bot_message_id = wizard_state.get('bot_message_id')
        if not bot_message_id:
            # Fallback: send new message instead of editing
            await update.message.reply_text(
                "❌ <b>Wizard Error</b>\n\nPlease restart the DNS wizard."
            )
            return
            
        # Create adapter for continue_mx_record_wizard with bot's message ID
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=bot_message_id,
            user_id=update.effective_user.id
        )
        
        # Continue to next step
        await continue_mx_record_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
            
    except Exception as e:
        logger.error(f"Error handling MX server input: {e}")
        await update.message.reply_text(
            "❌ Input Error\n\nPlease try entering your mail server again:"
        )

async def handle_dns_wizard_ip_input(update, context, ip_address, wizard_state):
    """Handle IP address input during DNS wizard"""
    try:
        # Validate IP address format
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        if not re.match(ip_pattern, ip_address.strip()):
            await update.message.reply_text(
                "❌ <b>Invalid IP Address</b>\n\nPlease enter a valid IPv4 address (e.g., 192.168.1.1)\n\nTry again:"
            )
            return
        
        # Update wizard state with IP address
        wizard_state['data']['ip'] = ip_address.strip()
        wizard_state['data']['content'] = ip_address.strip()  # For record creation
        context.user_data['dns_wizard'] = wizard_state
        
        # Continue to next step of wizard
        # Send confirmation and continue wizard
        name_display = wizard_state['data'].get('name', '@')
        
        await update.message.reply_text(
            f"✅ <b>IP Address Set</b>\n\nName: <code>{name_display}</code>\nIP: <code>{ip_address.strip()}</code>\n\nContinuing to next step..."
        )
        
        # Brief pause then send next wizard step as new message
        import asyncio
        await asyncio.sleep(1)
        
        # Show next step of wizard based on current state
        await show_next_wizard_step(update.message, context, wizard_state)
        
    except Exception as e:
        logger.error(f"Error handling DNS wizard IP input: {e}")
        await update.message.reply_text("❌ Error\n\nCould not process IP address.")

async def handle_ip_input(update, context, ip_address, edit_input):
    """Handle IP address input for editing with auto-apply"""
    try:
        # Validate IP address format
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        
        if not re.match(ip_pattern, ip_address.strip()):
            await update.message.reply_text(
                "❌ <b>Invalid IP Address</b>\n\nPlease enter a valid IPv4 address (e.g., 192.168.1.1)\n\nTry again:"
            )
            return
        
        # Update wizard state and session
        wizard_state = context.user_data.get('dns_wizard')
        record_id = edit_input['record_id']
        domain = edit_input['domain']
        user = update.effective_user
        
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await update.message.reply_text("❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Get AutoApplySession and update IP
        session = dns_auto_apply_manager.get_session(user.id, domain, record_id, 'A')
        validation = session.update_field('content', ip_address.strip())
        
        # Update wizard data
        wizard_state['data']['content'] = ip_address.strip()
        context.user_data['dns_wizard'] = wizard_state
        
        # Clear edit input context
        if 'edit_input' in context.user_data:
            del context.user_data['edit_input']
        
        # Show immediate feedback based on validation
        if validation['errors']:
            error_message = f"❌ IP Update Failed\n\n{validation['errors'].get('content', 'Invalid IP address')}\n\nPlease enter a different IP address:"
            await update.message.reply_text(error_message)
            return
        
        # Show success message
        await update.message.reply_text(
            f"✅ IP Updated\n\nNew IP: {ip_address.strip()}\n\n⚡ Auto-applying change..."
        )
        
        # Brief pause then show updated interface with auto-apply
        await asyncio.sleep(0.5)
        
        # Create a query adapter for the auto-apply edit wizard
        query_adapter = WizardQueryAdapter(
            bot=context.bot,
            chat_id=update.message.chat.id,
            message_id=update.message.message_id,
            user_id=user.id
        )
        
        await continue_a_record_edit_wizard(query_adapter, context, wizard_state)
        
        # Delete the input message for cleaner interface
        try:
            await update.message.delete()
        except Exception:
            pass  # Ignore if we can't delete
        
    except Exception as e:
        logger.error(f"Error handling IP input: {e}")
        await update.message.reply_text("❌ Error\n\nCould not process IP address.")

async def continue_a_record_edit_wizard_as_message(update, context, wizard_state):
    """Show A record edit wizard as a new message"""
    domain = wizard_state['domain']
    data = wizard_state['data']
    record_id = wizard_state['record_id']
    
    # Show edit interface with editable fields
    name_display = data['name'] if data['name'] != domain else domain
    ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
    proxy_display = "🟠 Proxied" if data['proxied'] == "true" else "⚪ Direct"
    
    message = f"""
✏️ Edit A Record: {domain}

Current Configuration:
Name: {name_display} (read-only)
IP Address: {data['content']}
TTL: {ttl_display}
Proxy Status: {proxy_display}

<b>Click to modify any field below:</b>
"""
    
    keyboard = [
        [InlineKeyboardButton("📝 Change IP Address", callback_data=await compress_callback(f"dns_edit:{domain}:A:ip:{record_id}", context))],
        [InlineKeyboardButton("⏰ Change TTL", callback_data=await compress_callback(f"dns_edit:{domain}:A:ttl:{record_id}", context))],
        [InlineKeyboardButton("🔄 Toggle Proxy", callback_data=await compress_callback(f"dns_edit:{domain}:A:proxy:{record_id}", context))],
        [InlineKeyboardButton("✅ Save Changes", callback_data=await compress_callback(f"dns_edit:{domain}:A:save:{record_id}", context))],
        [InlineKeyboardButton("❌ Cancel", callback_data=await compress_callback(f"dns:{domain}:record:{record_id}", context))]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(message, reply_markup=reply_markup)

async def save_dns_record_changes(query, context, domain, record_type, record_id):
    """Save DNS record changes from edit wizard"""
    user = query.from_user
    
    try:
        # Get wizard state
        wizard_state = context.user_data.get('dns_wizard')
        if not wizard_state or wizard_state.get('record_id') != record_id:
            await safe_edit_message(query, "❌ <b>Session Expired</b>\n\nPlease try the edit action again.")
            return
        
        # Verify domain ownership
        user_record = await get_or_create_user(user.id)
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone
        cf_zone = await get_cloudflare_zone(domain)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain}")
            return
        
        # Show updating message
        await safe_edit_message(query, "🔄 Updating DNS Record...\n\nPlease wait...")
        
        # Update DNS record using CloudflareService
        cloudflare = CloudflareService()
        zone_id = cf_zone['cf_zone_id']
        data = wizard_state['data']
        
        # Prepare record data based on record type
        record_name = data['name']
        record_content = data['content']
        record_ttl = int(data['ttl']) if data['ttl'] != '1' else 1  # 1 = Auto
        
        if record_type == "A":
            record_proxied = data['proxied'] == 'true'
            
            # Update A record
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=record_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl,
                proxied=record_proxied
            )
            
            if result and result.get('success') and result.get('result', {}).get('id'):
                # Success message for A record
                name_display = record_name if record_name != domain else domain
                ttl_display = "Auto" if record_ttl == 1 else f"{record_ttl}s"
                proxy_display = "🟠 Proxied" if record_proxied else "⚪ Direct"
                
                message = f"""
✅ DNS Record Updated

Domain: {domain}
Type: A ({proxy_display})
Name: {name_display}
IP: {record_content}
TTL: {ttl_display}

Record updated and active.
"""
            else:
                message = f"""
❌ DNS Record Update Failed

Domain: {domain}
Record: {record_type} {data.get('name', 'Unknown')}

Could not update the DNS record. Please try again.
"""
                
        elif record_type == "CNAME":
            # Update CNAME record
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=record_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl
            )
            
            if result and result.get('success') and result.get('result', {}).get('id'):
                # Success message for CNAME record
                name_display = record_name if record_name != domain else domain
                ttl_display = "Auto" if record_ttl == 1 else f"{record_ttl}s"
                target_display, _ = escape_content_for_display(record_content, mode="summary")
                
                message = f"""
✅ DNS Record Updated

Domain: {domain}
Type: CNAME
Name: {name_display}
Target: {target_display}
TTL: {ttl_display}

Record updated and active.
"""
            else:
                message = f"""
❌ DNS Record Update Failed

Domain: {domain}
Record: {record_type} {data.get('name', 'Unknown')}

Could not update the CNAME record. Please verify the target domain is valid.
"""
                
        elif record_type == "MX":
            # MX records need priority parameter
            record_priority = int(data.get('priority', 10))
            
            # Update MX record
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=record_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl,
                priority=record_priority
            )
            
            if result and result.get('success') and result.get('result', {}).get('id'):
                # Success message for MX record
                name_display = record_name if record_name != domain else domain
                ttl_display = "Auto" if record_ttl == 1 else f"{record_ttl}s"
                server_display, _ = escape_content_for_display(record_content, mode="summary")
                
                message = f"""
✅ DNS Record Updated

Domain: {domain}
Type: MX
Name: {name_display}
Mail Server: {server_display}
Priority: {record_priority}
TTL: {ttl_display}

Record updated and active.
"""
            else:
                message = f"""
❌ DNS Record Update Failed

Domain: {domain}
Record: {record_type} {data.get('name', 'Unknown')}

Could not update the MX record. Please verify the mail server is valid.
"""
                
        elif record_type == "TXT":
            # Update TXT record
            result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=record_id,
                record_type=record_type,
                name=record_name,
                content=record_content,
                ttl=record_ttl
            )
            
            if result and result.get('success') and result.get('result', {}).get('id'):
                # Success message for TXT record
                name_display = record_name if record_name != domain else domain
                ttl_display = "Auto" if record_ttl == 1 else f"{record_ttl}s"
                content_preview = record_content[:50] + "..." if len(record_content) > 50 else record_content
                
                message = f"""
✅ DNS Record Updated

Domain: {domain}
Type: TXT
Name: {name_display}
Content: {content_preview}
TTL: {ttl_display}

Record updated and active.
"""
            else:
                message = f"""
❌ DNS Record Update Failed

Domain: {domain}
Record: {record_type} {data.get('name', 'Unknown')}

Could not update the TXT record. Please try again.
"""
        else:
            # Unsupported record type for editing
            message = f"""
🚧 Edit Not Supported

Editing {record_type} records is not yet supported. You can:
• Delete and recreate the record
• Use the Cloudflare dashboard for advanced editing
"""
            
        # Clear wizard state if update was successful  
        result = locals().get('result')
        if result and result.get('success') and result.get('result', {}).get('id'):
            if 'dns_wizard' in context.user_data:
                del context.user_data['dns_wizard']
            
            keyboard = [
                [InlineKeyboardButton("📝 View Record Details", callback_data=f"dns:{domain}:record:{record_id}")],
                [InlineKeyboardButton("📋 Records", callback_data=f"dns:{domain}:list")],
                [InlineKeyboardButton("➕ Add New Record", callback_data=f"dns:{domain}:add")],
                [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain}:view")]
            ]
        else:
            # Failed update or unsupported type
            keyboard = [
                [InlineKeyboardButton("🔄 Try Again", callback_data=f"dns:{domain}:edit:{record_id}")],
                [InlineKeyboardButton("📝 View Record Details", callback_data=f"dns:{domain}:record:{record_id}")],
                [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain}:view")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error saving DNS record changes: {e}")
        await safe_edit_message(query, "❌ Update Error\n\nCould not save changes. Please try again.")

async def show_next_wizard_step(message, context, wizard_state):
    """Show next wizard step as new message instead of editing existing one"""
    try:
        domain = wizard_state['domain']
        record_type = wizard_state['type']
        data = wizard_state['data']
        
        if record_type == 'A':
            if 'name' not in data:
                # Step 1: Name/Host
                message_text = f"""
🅰️ Add A Record (1/4): {domain}

Enter the name/host for this A record.
"""
                keyboard = [
                    [InlineKeyboardButton("Use Root (@)", callback_data=f"dns_wizard:{domain}:A:name:@")],
                    [InlineKeyboardButton("Use www", callback_data=f"dns_wizard:{domain}:A:name:www")],
                    [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain}:add")]
                ]
            elif 'ip' not in data:
                # This shouldn't happen as we just set the IP, but safety check
                message_text = f"✅ IP Address Set\n\nReturning to wizard menu..."
                keyboard = [[InlineKeyboardButton("⬅️ Back to DNS", callback_data=f"dns:{domain}:view")]]
            elif 'ttl' not in data:
                # Step 3: TTL
                name_display = data['name'] if data['name'] != '@' else domain
                message_text = f"""
🅰️ Add A Record (3/4): {domain}

Name: {name_display}
IP: {data['ip']}

Select TTL (Time To Live):
"""
                keyboard = [
                    [InlineKeyboardButton("Auto (Recommended)", callback_data=f"dns_wizard:{domain}:A:ttl:1")],
                    [InlineKeyboardButton("5 minutes", callback_data=f"dns_wizard:{domain}:A:ttl:300")],
                    [InlineKeyboardButton("1 hour", callback_data=f"dns_wizard:{domain}:A:ttl:3600"),
                     InlineKeyboardButton("1 day", callback_data=f"dns_wizard:{domain}:A:ttl:86400")],
                    [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:A:ip:back")]
                ]
            elif 'proxied' not in data:
                # Step 4: Proxy Setting
                name_display = data['name'] if data['name'] != '@' else domain
                ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
                message_text = f"""
🅰️ Add A Record (4/4): {domain}

Name: {name_display}
IP: {data['ip']}
TTL: {ttl_display}

Enable Cloudflare Proxy?

🔒 Proxied (Recommended): Hide your server IP, get DDoS protection & caching
🌐 DNS Only: Direct connection to your server
"""
                keyboard = [
                    [InlineKeyboardButton("🔒 Enable Proxy (Recommended)", callback_data=f"dns_wizard:{domain}:A:proxied:true")],
                    [InlineKeyboardButton("🌐 DNS Only", callback_data=f"dns_wizard:{domain}:A:proxied:false")],
                    [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:A:ttl:back")]
                ]
            else:
                # All data collected, show final confirmation
                name_display = data['name'] if data['name'] != '@' else domain
                ttl_display = "Auto" if data['ttl'] == 1 else f"{data['ttl']}s"
                proxy_display = "🔒 Proxied" if data['proxied'] == 'true' else "🌐 DNS Only"
                
                message_text = f"""
✅ Create A Record - Final Confirmation

Domain: {domain}
Name: {name_display}
IP Address: {data['ip']}
TTL: {ttl_display}
Proxy: {proxy_display}

Confirm to create this DNS record?
"""
                keyboard = [
                    [InlineKeyboardButton("✅ Create Record", callback_data=f"dns_wizard:{domain}:A:create:confirm")],
                    [InlineKeyboardButton("⬅️ Back", callback_data=f"dns_wizard:{domain}:A:proxied:back")]
                ]
        else:
            # Fallback for other record types
            message_text = f"✅ Data Updated\n\nReturning to wizard..."
            keyboard = [[InlineKeyboardButton("⬅️ Back to DNS", callback_data=f"dns:{domain}:view")]]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await message.reply_text(message_text, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing next wizard step: {e}")
        await message.reply_text("❌ Error\n\nCould not continue wizard.")

# =============================================================================
# NAMESERVER MANAGEMENT FUNCTIONS
# =============================================================================

async def show_nameserver_management(query, domain_name, context):
    """Show nameserver management interface"""
    user = query.from_user
    
    try:
        user_record = await get_or_create_user(user.id)
        
        # Check if user owns this domain
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain_name for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # Get Cloudflare zone info and nameservers
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, f"❌ DNS Unavailable\n\nNo zone for {domain_name}")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        zone_info = await cloudflare.get_zone_info(zone_id)
        nameservers = zone_info.get('name_servers', []) if zone_info else []
        
        # Detect provider and format display
        provider_type, provider_name = detect_nameserver_provider(nameservers)
        nameserver_display = format_nameserver_display(nameservers, max_display=4)
        
        # Provider status and recommendations
        if provider_type == "cloudflare":
            status_icon = "🟢"
            recommendation = "✅ Optimal Configuration\nYour domain is using Cloudflare's nameservers for best performance and security."
        else:
            status_icon = "🔶"
            recommendation = "Consider switching to Cloudflare nameservers for better performance and DNS management."
        
        message = f"""
📡 NS: {domain_name}

{status_icon} {provider_name}
{nameserver_display}

Type new nameservers:
"""
        
        keyboard = []
        
        # Add appropriate management options
        if provider_type != "cloudflare":
            keyboard.append([InlineKeyboardButton("🔄 Switch to Cloudflare NS", callback_data=f"dns:{domain_name}:ns_to_cloudflare")])
        
        keyboard.extend([
            [InlineKeyboardButton("📋 Records", callback_data=f"dns:{domain_name}:list")],
            [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data=f"dns:{domain_name}:view")]
        ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context for direct nameserver input
        context.user_data['expecting_nameserver_input'] = {
            'domain': domain_name,
            'chat_id': query.message.chat.id if query.message else None,
            'message_id': query.message.message_id if query.message else None
        }
        
    except Exception as e:
        logger.error(f"Error showing nameserver management: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load nameserver information.")

async def confirm_switch_to_cloudflare_ns(query, domain_name):
    """Confirm switching to Cloudflare nameservers"""
    try:
        # Get current nameserver info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, "❌ Error\n\nDomain zone not found.")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        zone_info = await cloudflare.get_zone_info(zone_id)
        cf_nameservers = zone_info.get('name_servers', []) if zone_info else []
        
        if not cf_nameservers:
            await safe_edit_message(query, "❌ Error\n\nCould not retrieve Cloudflare nameservers.")
            return
        
        cf_ns_display = format_nameserver_display(cf_nameservers, max_display=4)
        
        message = f"""
🔄 Switch to Cloudflare Nameservers

Domain: {domain_name}

New Cloudflare Nameservers:
{cf_ns_display}

Status: Requires registrar update for activation

Enhanced security, CDN, and integrated DNS management.

Confirm this action?
"""
        
        keyboard = [
            [InlineKeyboardButton("✅ Confirm Switch", callback_data=f"dns:{domain_name}:ns_to_cloudflare:confirm")],
            [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain_name}:nameservers")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing Cloudflare NS confirmation: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not prepare nameserver switch.")

async def execute_switch_to_cloudflare_ns(query, context, domain_name):
    """Execute switch to Cloudflare nameservers via OpenProvider API"""
    try:
        user = query.from_user
        
        # Show processing message
        await safe_edit_message(query, "🔄 Switching to Cloudflare Nameservers\n\nRetrieving Cloudflare nameservers and updating domain configuration...")
        
        # Get Cloudflare nameservers
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, "❌ Error\n\nDomain zone not found.")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        zone_info = await cloudflare.get_zone_info(zone_id)
        cf_nameservers = zone_info.get('name_servers', []) if zone_info else []
        
        if not cf_nameservers:
            await safe_edit_message(query, "❌ Error\n\nCould not retrieve Cloudflare nameservers.")
            return
        
        cf_ns_display = format_nameserver_display(cf_nameservers, max_display=4)
        
        # Try to update nameservers via OpenProvider API
        logger.info(f"Attempting to switch {domain_name} to Cloudflare nameservers via OpenProvider API")
        
        # CRITICAL FIX: Get domain ID from database first
        domain_id = await get_domain_provider_id(domain_name)
        domain_id = str(domain_id) if domain_id else None
        
        if not domain_id:
            logger.error(f"❌ No provider domain ID found for {domain_name} in database")
            await safe_edit_message(query, f"❌ Error\n\nDomain registration data not found. Please contact {BrandConfig().support_contact}.")
            return
        
        logger.info(f"Using domain ID {domain_id} for Cloudflare nameserver switch")
        openprovider = OpenProviderService()
        update_result = await openprovider.update_nameservers(domain_name, cf_nameservers, domain_id)
        
        # Check success conditions
        if update_result and (update_result.get('success') or update_result.get('code') == 0):
            # Success case - nameservers updated via API
            # CRITICAL: Update database with new Cloudflare nameservers for sync
            db_updated = await update_domain_nameservers(domain_name, cf_nameservers)
            if db_updated:
                logger.info(f"✅ Database updated with Cloudflare nameservers for {domain_name}")
            else:
                logger.warning(f"⚠️ Failed to update database nameservers for {domain_name}")
            
            # Compact nameserver display for mobile
            ns_count = len(cf_nameservers)
            ns_summary = f"{ns_count} Cloudflare NS" if ns_count > 1 else "Cloudflare NS"
            
            message = f"""
✅ Cloudflare Nameservers Updated
Domain: {domain_name}
Status: ✅ API Updated
Nameservers: {ns_summary}
Propagation: 24-48 hours
"""
            
            keyboard = [
                [InlineKeyboardButton("📋 Manage DNS Records", callback_data=f"dns:{domain_name}:list")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.info(f"Successfully switched {domain_name} to Cloudflare nameservers via OpenProvider API")
            
        elif update_result and not update_result.get('success'):
            # API call failed - show error with fallback instructions
            error_msg = update_result.get('message', 'Unknown error')
            error_code = update_result.get('error_code', 0)
            
            message = f"""
⚠️ API Update Failed - Manual Action Required

Domain: {domain_name}
Error: {error_msg}

Cloudflare Nameservers (for manual update):
{cf_ns_display}

Manual Steps Required:
1. Log in to your OpenProvider account
2. Find domain management for {domain_name}
3. Update nameserver settings with the Cloudflare nameservers above
4. Save changes - DNS propagation takes 24-48 hours

⚠️ Note: 
The automated update failed (Error {error_code}). Please update manually at your registrar.

Once updated, all DNS management for this domain will be handled through Cloudflare and this bot.
"""
            
            keyboard = [
                [InlineKeyboardButton("🔄 Retry API Update", callback_data=f"dns:{domain_name}:ns_to_cloudflare:confirm")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.warning(f"OpenProvider API update failed for {domain_name} Cloudflare switch: {error_msg} (Error {error_code})")
            
        else:
            # API unavailable - show fallback instructions
            message = f"""
⚠️ Manual Update Required

Domain: {domain_name}

Cloudflare Nameservers (for manual update):
{cf_ns_display}

Manual Steps:
1. Log in to your domain registrar (OpenProvider)
2. Find domain management for {domain_name}
3. Update nameserver settings with the Cloudflare nameservers above
4. Save changes - DNS propagation takes 24-48 hours

Benefits after update:
• Enhanced DDoS protection and CDN
• Full DNS management through this bot
• Better security and performance

⚠️ Note: 
OpenProvider API is currently unavailable. Please update manually.

Once updated, all DNS management for this domain will be handled through Cloudflare and this bot.
"""
            
            keyboard = [
                [InlineKeyboardButton("🔄 Retry API Update", callback_data=f"dns:{domain_name}:ns_to_cloudflare:confirm")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.warning(f"OpenProvider API unavailable for Cloudflare nameserver switch of {domain_name}")
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error executing Cloudflare NS switch for {domain_name}: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not process nameserver switch. Please try again.")

async def handle_nameserver_input(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str, nameserver_input_context):
    """Handle nameserver input from user - simplified single input interface"""
    try:
        user = update.effective_user
        effective_message = update.effective_message
        domain_name = nameserver_input_context['domain']
        
        # Parse nameservers from various input formats
        nameservers = parse_nameserver_input(text)
        
        if not nameservers:
            if effective_message:
                await effective_message.reply_text(
                    "❌ No Valid Nameservers Found\n\n"
                    "Please enter nameservers in one of these formats:\n"
                    "• Line-separated (one per line)\n"
                    "• Comma-separated: ns1.example.com, ns2.example.com\n"
                    "• Space-separated: ns1.example.com ns2.example.com\n\n"
                    "Each nameserver must be a valid FQDN (e.g., ns1.example.com)"
                )
            return
        
        # Validate nameservers
        valid_nameservers = []
        invalid_nameservers = []
        
        for ns in nameservers:
            ns_clean = ns.strip().lower()
            if ns_clean and is_valid_nameserver(ns_clean):
                valid_nameservers.append(ns_clean)
            elif ns_clean:  # Only add to invalid if not empty
                invalid_nameservers.append(ns)
        
        # Check for validation errors
        if len(valid_nameservers) < 2:
            if effective_message:
                await effective_message.reply_text(
                    f"❌ Not Enough Valid Nameservers\n\n"
                    f"At least 2 valid nameservers required. Found {len(valid_nameservers)} valid nameserver(s).\n\n"
                    "Please enter 2-5 valid nameserver addresses."
                )
            return
        
        if len(valid_nameservers) > 5:
            if effective_message:
                await effective_message.reply_text(
                    f"❌ Too Many Nameservers\n\n"
                    f"Maximum 5 nameservers allowed. You provided {len(valid_nameservers)} nameservers.\n\n"
                    "Please reduce to 2-5 nameservers for optimal DNS performance."
                )
            return
        
        if invalid_nameservers:
            invalid_list = "\n".join([f"• {ns}" for ns in invalid_nameservers])
            if effective_message:
                await effective_message.reply_text(
                    f"❌ Invalid Nameservers Found\n\n"
                    f"The following nameservers are invalid:\n{invalid_list}\n\n"
                    "Please use valid FQDN format (e.g., ns1.example.com)."
                )
            return
        
        # If all validations pass, proceed with update
        if not user or not effective_message:
            logger.error("Missing user or message in nameserver input handler")
            return
            
        # Clean up context
        if context.user_data and 'expecting_nameserver_input' in context.user_data:
            del context.user_data['expecting_nameserver_input']
        
        # Execute the nameserver update directly for text input
        await execute_nameserver_update_text(effective_message, context, domain_name, valid_nameservers, user)
        
    except Exception as e:
        logger.error(f"Error handling nameserver input: {e}")
        if update.effective_message:
            await update.effective_message.reply_text(
                "❌ Error Processing Nameservers\n\n"
                "Could not process your nameserver input. Please try again."
            )

def parse_nameserver_input(text: str) -> list:
    """Parse nameserver input from various formats"""
    if not text:
        return []
    
    # Try different separation methods
    nameservers = []
    
    # First try newline separation (most common for multi-line input)
    if '\n' in text:
        nameservers = [ns.strip() for ns in text.split('\n') if ns.strip()]
    # Then try comma separation
    elif ',' in text:
        nameservers = [ns.strip() for ns in text.split(',') if ns.strip()]
    # Finally try space separation
    elif ' ' in text:
        nameservers = [ns.strip() for ns in text.split() if ns.strip()]
    # Single nameserver
    else:
        nameservers = [text.strip()] if text.strip() else []
    
    # Remove duplicates while preserving order
    seen = set()
    unique_nameservers = []
    for ns in nameservers:
        ns_lower = ns.lower()
        if ns_lower not in seen:
            seen.add(ns_lower)
            unique_nameservers.append(ns)
    
    return unique_nameservers

async def show_custom_nameserver_form(query, context, domain_name):
    """Show simplified form for entering all custom nameservers at once"""
    try:
        message = f"""
⚙️ <b>Set Custom Nameservers: {domain_name}</b>

<b>Enter all nameservers (2-5 required):</b>

You can enter nameservers in any of these formats:

Line-separated (recommended):
<code>ns1.example.com
ns2.example.com
ns3.example.com</code>

<b>Comma-separated:</b>
<code>ns1.example.com, ns2.example.com, ns3.example.com</code>

<b>Space-separated:</b>
<code>ns1.example.com ns2.example.com ns3.example.com</code>

<b>Requirements:</b>
• 2-5 nameservers required
• Valid FQDN format (e.g., ns1.example.com)
• Each nameserver must end with a domain

Update nameservers at your registrar after entering.

<b>Type your nameservers below:</b>
"""
        
        keyboard = [
            [InlineKeyboardButton("❌ Cancel", callback_data=f"dns:{domain_name}:nameservers")],
            [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:nameservers")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context for text input
        context.user_data['expecting_nameserver_input'] = {
            'domain': domain_name,
            'chat_id': query.message.chat.id if query.message else None,
            'message_id': query.message.message_id if query.message else None
        }
        
    except Exception as e:
        logger.error(f"Error showing custom nameserver form: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load nameserver form.")

async def execute_nameserver_update_text(message, context, domain_name, nameservers, user):
    """Execute nameserver update for text input with direct message sending"""
    try:
        # Show processing message
        processing_msg = await message.reply_text(
            "🔄 Processing Nameserver Update\n\nValidating nameservers and updating domain configuration..."
        )
        
        # Get the domain ID from database for OpenProvider API
        provider_domain_id = await get_domain_provider_id(domain_name)
        
        # Try to update nameservers via OpenProvider API
        openprovider = OpenProviderService()
        api_success = await openprovider.update_nameservers(domain_name, nameservers, provider_domain_id)
        
        if api_success and api_success.get('success'):
            # Store updated nameservers in database
            db_update_success = await update_domain_nameservers(domain_name, nameservers)
            if db_update_success:
                logger.info(f"✅ Stored updated nameservers in database for {domain_name}")
            else:
                logger.warning(f"⚠️ Failed to store nameservers in database for {domain_name}")
            
            ns_list = "\n".join([f"• {ns}" for ns in nameservers])
            success_message = f"""
✅ Nameservers Updated

Domain: {domain_name}
Nameservers: {len(nameservers)} configured
{ns_list}

Changes propagate globally within 24-48 hours.
"""
            
            # Check if nameservers are Cloudflare - only show DNS management if they are
            provider_type, _ = detect_nameserver_provider(nameservers)
            
            if provider_type == "cloudflare":
                keyboard = [
                    [InlineKeyboardButton("⚙️ Manage DNS", callback_data=f"dns:{domain_name}:main")],
                    [InlineKeyboardButton("🌐 My Domains", callback_data="my_domains")]
                ]
            else:
                # Custom nameservers - no DNS management available, show Cloudflare switch
                keyboard = [
                    [InlineKeyboardButton("🔄 Switch to Cloudflare NS", callback_data=f"dns:{domain_name}:ns_to_cloudflare")],
                    [InlineKeyboardButton("🌐 My Domains", callback_data="my_domains")]
                ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=processing_msg.message_id,
                text=success_message,
                reply_markup=reply_markup
            )
            
            logger.info(f"Nameservers updated successfully for {domain_name}")
            
        else:
            # API failed - show manual instructions
            ns_list = "\n".join([f"• {ns}" for ns in nameservers])
            manual_message = f"""
⚠️ Manual Update Required

Domain: {domain_name}
Status: API unavailable
{ns_list}

Steps: OpenProvider → Domain Settings → Update Nameservers

Return here after updating (24-48h propagation).
"""
            
            keyboard = [
                [InlineKeyboardButton("🔄 Retry API Update", callback_data=f"retry_ns_update:{domain_name}:{user.id}")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await context.bot.edit_message_text(
                chat_id=message.chat.id,
                message_id=processing_msg.message_id,
                text=manual_message,
                reply_markup=reply_markup
            )
            
            logger.warning(f"OpenProvider API unavailable for nameserver update of {domain_name}")
            
    except Exception as e:
        logger.error(f"Error executing nameserver update for {domain_name}: {e}")
        try:
            await message.reply_text(
                "❌ Error\n\nCould not process nameserver update. Please try again."
            )
        except Exception as reply_error:
            logger.error(f"Error sending error message: {reply_error}")

async def handle_retry_nameserver_update(query, context, callback_data):
    """Handle retry nameserver update callback: retry_ns_update:{domain_name}:{user_id}"""
    try:
        parts = callback_data.split(":")
        if len(parts) < 3:
            await safe_edit_message(query, "❌ Error\n\nInvalid retry request.")
            return
        
        domain_name = parts[1]
        expected_user_id = int(parts[2])
        user = query.from_user
        
        # Verify user ID matches for security
        if user.id != expected_user_id:
            await safe_edit_message(query, "❌ Access Denied\n\nUnauthorized retry attempt.")
            return
        
        # Show the custom nameserver form for retry
        await show_custom_nameserver_form(query, context, domain_name)
        
    except Exception as e:
        logger.error(f"Error handling retry nameserver update: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not process retry request.")

async def execute_nameserver_update(query, context, domain_name, ns_data_token):
    """Execute custom nameserver update via OpenProvider API"""
    try:
        user = query.from_user
        
        # Show processing message
        await safe_edit_message(query, "🔄 Processing Nameserver Update\n\nValidating nameservers and updating domain configuration...")
        
        # Retrieve nameserver data from token
        ns_data = await retrieve_callback_token(user.id, ns_data_token)
        if not ns_data or ns_data.startswith("error:"):
            await safe_edit_message(query, "❌ Error\n\nNameserver data expired. Please try again.")
            return
        
        # Parse nameservers
        nameservers = ns_data.split("|")
        
        # Validate nameservers with enhanced checks
        valid_nameservers = []
        invalid_nameservers = []
        
        for ns in nameservers:
            ns = ns.strip().lower()  # Normalize to lowercase
            if ns and is_valid_nameserver(ns):
                valid_nameservers.append(ns)
            else:
                invalid_nameservers.append(ns)
        
        # Enforce 2-5 nameserver limit
        if len(valid_nameservers) < 2:
            await safe_edit_message(query, 
                "❌ Invalid Configuration\n\n" +
                f"At least 2 valid nameservers required. Found {len(valid_nameservers)} valid nameservers.")
            return
        
        if len(valid_nameservers) > 5:
            await safe_edit_message(query, 
                "❌ Too Many Nameservers\n\n" +
                f"Maximum 5 nameservers allowed. You provided {len(valid_nameservers)} nameservers.\n\n" +
                "Please reduce to 2-5 nameservers for optimal DNS performance.")
            return
        
        if invalid_nameservers:
            invalid_list = "\n".join([f"• {ns}" for ns in invalid_nameservers])
            await safe_edit_message(query, 
                f"❌ Invalid Nameservers\n\nThe following nameservers are invalid:\n{invalid_list}\n\nPlease use valid FQDN format.")
            return
        
        # Get the domain ID from database for OpenProvider API
        provider_domain_id = await get_domain_provider_id(domain_name)
        
        # Try to update nameservers via OpenProvider API
        logger.info(f"Attempting to update nameservers for {domain_name} (ID: {provider_domain_id}) via OpenProvider API")
        openprovider = OpenProviderService()
        update_result = await openprovider.update_nameservers(domain_name, valid_nameservers, provider_domain_id)
        
        if update_result and update_result.get('success'):
            # Success case - nameservers updated via API
            # Store updated nameservers in database
            db_update_success = await update_domain_nameservers(domain_name, valid_nameservers)
            if db_update_success:
                logger.info(f"✅ Stored updated nameservers in database for {domain_name}")
            else:
                logger.warning(f"⚠️ Failed to store nameservers in database for {domain_name}")
            
            ns_display = format_nameserver_display(valid_nameservers, max_display=4)
            provider_type, provider_name = detect_nameserver_provider(valid_nameservers)
            
            message = f"""
✅ Nameservers Updated Successfully

Domain: {domain_name}
Provider: {provider_name}

Updated Nameservers:
{ns_display}

Status: ✅ Updated via OpenProvider API
Propagation: Changes will propagate over the next 24-48 hours

Next Steps:
• DNS changes are now live at your registrar
• No additional action required
• DNS management available through this bot for Cloudflare nameservers

DNS changes propagate within 48 hours.
"""
            
            keyboard = [
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.info(f"Successfully updated nameservers for {domain_name} via OpenProvider API: {valid_nameservers}")
            
        elif update_result and not update_result.get('success'):
            # API call failed - show error with fallback instructions
            error_msg = update_result.get('message', 'Unknown error')
            error_code = update_result.get('error_code', 0)
            
            ns_display = format_nameserver_display(valid_nameservers, max_display=4)
            
            message = f"""
⚠️ API Update Failed - Manual Action Required

Domain: {domain_name}
Error: {error_msg}

Your Nameservers (for manual update):
{ns_display}

Manual Steps Required:
1. Log in to your OpenProvider account
2. Find domain management for {domain_name}
3. Update nameserver settings with the nameservers above
4. Save changes - DNS propagation takes 24-48 hours

⚠️ Note: 
The automated update failed (Error {error_code}). Please update manually at your registrar.
"""
            
            keyboard = [
                [InlineKeyboardButton("🔄 Retry API Update", callback_data=f"dns:{domain_name}:ns_update:{ns_data_token}")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.warning(f"OpenProvider API update failed for {domain_name}: {error_msg} (Error {error_code})")
            
        else:
            # API unavailable - show fallback instructions
            ns_display = format_nameserver_display(valid_nameservers, max_display=4)
            provider_type, provider_name = detect_nameserver_provider(valid_nameservers)
            
            message = f"""
⚠️ Manual Update Required

Domain: {domain_name}
Provider: {provider_name}

Your Nameservers (for manual update):
{ns_display}

Manual Steps:
1. Log in to your domain registrar (OpenProvider)
2. Find domain management for {domain_name}
3. Update nameserver settings with the nameservers above
4. Save changes - DNS propagation takes 24-48 hours

⚠️ Note: 
OpenProvider API is currently unavailable. Please update manually.
"""
            
            keyboard = [
                [InlineKeyboardButton("🔄 Retry API Update", callback_data=f"dns:{domain_name}:ns_update:{ns_data_token}")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:nameservers")]
            ]
            
            logger.warning(f"OpenProvider API unavailable for nameserver update of {domain_name}")
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Clean up context
        if 'expecting_nameserver_input' in context.user_data:
            del context.user_data['expecting_nameserver_input']
        
    except Exception as e:
        logger.error(f"Error executing nameserver update for {domain_name}: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not process nameserver update. Please try again.")

# =============================================================================
# CLOUDFLARE SECURITY SETTINGS FUNCTIONS
# =============================================================================

async def show_security_settings(query, domain_name):
    """Show Cloudflare security settings interface with JavaScript Challenge toggle"""
    user = query.from_user
    
    try:
        user_record = await get_or_create_user(user.id)
        
        # Check if user owns this domain
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain_name for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        # FIXED LOGIC: Check Cloudflare zone existence FIRST before nameserver validation
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            # No Cloudflare zone found - check if domain uses Cloudflare nameservers
            nameservers = await get_domain_nameservers(domain_name)
            
            # If no nameservers stored, try to fetch from Cloudflare API as fallback
            if not nameservers:
                logger.info(f"No stored nameservers for {domain_name}, attempting Cloudflare API fallback")
                cloudflare = CloudflareService()
                zone_info = await cloudflare.get_zone_by_name(domain_name)
                
                if zone_info and zone_info.get('name_servers'):
                    # Found zone via API - persist nameservers and update database
                    api_nameservers = zone_info.get('name_servers', [])
                    logger.info(f"✅ Fetched nameservers from Cloudflare API for {domain_name}: {api_nameservers}")
                    
                    # Persist nameservers to database
                    await update_domain_nameservers(domain_name, api_nameservers)
                    nameservers = api_nameservers
                    
                    # Also save zone info if missing in database
                    if zone_info.get('id'):
                        await save_cloudflare_zone(
                            domain_name=domain_name,
                            cf_zone_id=zone_info['id'],
                            nameservers=api_nameservers,
                            status=zone_info.get('status', 'active')
                        )
                        # Reload zone from database now that it's saved
                        cf_zone = await get_cloudflare_zone(domain_name)
                        logger.info(f"✅ Saved Cloudflare zone info for {domain_name}")
            
            # If still no Cloudflare zone after API fallback, check nameserver provider
            if not cf_zone:
                provider_type, _ = detect_nameserver_provider(nameservers)
                
                if provider_type != "cloudflare":
                    await safe_edit_message(query, 
                        f"🛡️ Security Settings Unavailable\n\n"
                        f"Security features require Cloudflare nameservers.\n\n"
                        f"Switch to Cloudflare first to access security settings."
                    )
                    return
                else:
                    # Domain uses Cloudflare nameservers but zone not found in database
                    await safe_edit_message(query, 
                        f"❌ Security Settings Unavailable\n\n"
                        f"Cloudflare zone configuration not found for {domain_name}.\n\n"
                        f"Please ensure the domain is properly added to Cloudflare."
                    )
                    return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        # Get current security settings
        await safe_edit_message(query, "🔄 Loading Security Settings...\n\nFetching Cloudflare configuration...")
        
        settings = await cloudflare.get_zone_settings(zone_id)
        if not settings:
            await safe_edit_message(query, "❌ Error\n\nCould not load security settings.")
            return
        
        # Get JavaScript Challenge status from WAF Custom Rules
        js_challenge_status = await cloudflare.get_javascript_challenge_status(zone_id)
        js_challenge = js_challenge_status.get('enabled', False)
        force_https = settings.get('always_use_https', False)
        
        # Get auto-proxy preference for this domain
        auto_proxy_enabled = await get_domain_auto_proxy_enabled(domain_name)
        
        # Format JavaScript Challenge status
        if js_challenge:
            rule_count = js_challenge_status.get('rule_count', 0)
            js_status = "✅ On"
            js_description = f"Visible JavaScript Challenge active ({rule_count} rule{'s' if rule_count != 1 else ''})"
        else:
            js_status = "❌ Off"
            js_description = "No JavaScript Challenge protection enabled"
        
        https_status = "✅ On" if force_https else "❌ Off"
        auto_proxy_status = "✅ On" if auto_proxy_enabled else "❌ Off"
        
        message = f"""
🛡️ Security Settings: {domain_name}

🔐 Visible JavaScript Challenge: {js_status}
_{js_description}_

🔒 Force HTTPS: {https_status}

🔧 Auto-Enable Proxy: {auto_proxy_status}
_Automatically enable Cloudflare proxy when using features that require it_

Adjust security settings for your domain:
"""
        
        keyboard = [
            [InlineKeyboardButton("🔐 JavaScript Challenge Toggle", callback_data=f"dns:{domain_name}:security:js_challenge:toggle")],
            [InlineKeyboardButton("🔒 Toggle Force HTTPS", callback_data=f"dns:{domain_name}:security:force_https:toggle")],
            [InlineKeyboardButton("🔧 Toggle Auto-Enable Proxy", callback_data=f"dns:{domain_name}:security:auto_proxy:toggle")],
            [InlineKeyboardButton("⬅️ Back to DNS", callback_data=f"dns:{domain_name}:view")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing security settings: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not load security settings.")

async def toggle_javascript_challenge(query, domain_name, action):
    """Handle JavaScript Challenge toggle"""
    try:
        # Get Cloudflare zone info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, "❌ Error\n\nCloudflare zone not found.")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        if action == "toggle":
            # Show JavaScript Challenge options
            message = f"""
🔐 Visible JavaScript Challenge: {domain_name}

Choose protection level:

Enable: Show 5-second "Checking your browser" page to all visitors
Disable: Allow all traffic without visible challenge

_Visible JavaScript Challenge displays an interstitial page to verify browsers and block automated attacks._
"""
            
            keyboard = [
                [InlineKeyboardButton("✅ Enable", callback_data=f"dns:{domain_name}:security:js_challenge:on"),
                 InlineKeyboardButton("❌ Disable", callback_data=f"dns:{domain_name}:security:js_challenge:off")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
        else:
            # Apply Visible JavaScript Challenge setting
            enabled = action == "on"
            
            try:
                if enabled:
                    # Auto-enable proxy for web records before enabling JavaScript Challenge
                    proxy_result = await ensure_proxy_for_feature(
                        zone_id=zone_id,
                        domain_name=domain_name,
                        feature_name="Visible JavaScript Challenge",
                        query=query
                    )
                    
                    if not proxy_result.get('success'):
                        # Check if user confirmation is needed for proxy enablement
                        if proxy_result.get('needs_confirmation'):
                            # Show confirmation dialog for proxy enablement
                            confirmation_message = proxy_result.get('message', 'Proxy enablement required')
                            
                            message = f"""
🔧 Proxy Confirmation Required

{confirmation_message}

Visible JavaScript Challenge requires Cloudflare proxy to function properly. 

Would you like to enable proxy for these records now?
"""
                            
                            keyboard = [
                                [InlineKeyboardButton("✅ Yes, Enable Proxy", callback_data=f"dns:{domain_name}:security:js_challenge:confirm_proxy:on"),
                                 InlineKeyboardButton("❌ No, Cancel", callback_data=f"dns:{domain_name}:security")],
                            ]
                            
                            reply_markup = InlineKeyboardMarkup(keyboard)
                            await safe_edit_message(query, message, reply_markup=reply_markup)
                            return
                        else:
                            # Proxy enablement failed, show error and return
                            error_message = proxy_result.get('message', 'Failed to enable proxy for JavaScript Challenge')
                            await safe_edit_message(query, f"❌ JavaScript Challenge Setup Failed\n\n{error_message}")
                            return
                    
                    # Enable visible JavaScript challenge for all traffic
                    result = await cloudflare.enable_javascript_challenge(zone_id, "Visible JavaScript Challenge - Bot Protection")
                    
                    # If JavaScript Challenge fails, rollback proxy changes
                    if not result.get('success') and proxy_result.get('rollback_needed'):
                        logger.warning("JavaScript Challenge failed, rolling back proxy changes")
                        rollback_success = await rollback_proxy_changes(zone_id, proxy_result.get('modified_records', []))
                        if rollback_success:
                            logger.info("Successfully rolled back proxy changes")
                        else:
                            logger.warning("Proxy rollback partially failed")
                else:
                    # Disable JavaScript challenge by removing all JS challenge rules
                    # Note: We don't disable proxy when turning features off - that's user choice
                    success = await cloudflare.disable_javascript_challenge(zone_id)
                    result = {'success': success}
                    
            except asyncio.CancelledError:
                await safe_edit_message(query, "⏱️ Request Timeout\n\nThe JavaScript Challenge update was cancelled. Please try again.")
                return
            
            if result.get('success'):
                status = "Enabled" if enabled else "Disabled"
                if enabled:
                    description = "All visitors will see a 5-second 'Checking your browser' page before accessing your site."
                else:
                    description = "Visitors can access your site directly without any JavaScript challenge."
                
                message = f"""
✅ Visible JavaScript Challenge Updated

Domain: {domain_name}
Status: {status}

_{description}_

Changes take effect within a few minutes.
"""
            else:
                # Handle detailed error messages
                errors = result.get('errors', [{'message': 'Unknown error occurred'}])
                error_messages = []
                
                # Ensure errors is a list
                if not isinstance(errors, list):
                    errors = [{'message': 'Unknown error occurred'}]
                    
                for error in errors:
                    error_msg = error.get('user_message') or error.get('message', 'Unknown error')
                    error_messages.append(error_msg)
                
                error_text = "\n\n".join(error_messages)
                
                message = f"""
❌ Visible JavaScript Challenge Update Failed

{error_text}

Please try again later.
"""
            
            keyboard = [
                [InlineKeyboardButton("⬅️ Back to Security", callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
    except Exception as e:
        logger.error(f"Error toggling JavaScript Challenge setting: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not update JavaScript Challenge setting.")

async def toggle_force_https_setting(query, domain_name, action):
    """Toggle Force HTTPS setting"""
    try:
        # Get Cloudflare zone info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, "❌ Error\n\nCloudflare zone not found.")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        if action == "toggle":
            # Show Force HTTPS options
            message = f"""
🔒 Force HTTPS: {domain_name}

Choose HTTPS redirect behavior:

On: Automatically redirect HTTP to HTTPS
Off: Allow both HTTP and HTTPS
"""
            
            keyboard = [
                [InlineKeyboardButton("✅ Enable Force HTTPS", callback_data=f"dns:{domain_name}:security:force_https:on"),
                 InlineKeyboardButton("❌ Disable Force HTTPS", callback_data=f"dns:{domain_name}:security:force_https:off")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
        else:
            # Apply Force HTTPS setting
            enabled = action == "on"
            
            if enabled:
                # Auto-enable proxy for web records before enabling Force HTTPS
                proxy_result = await ensure_proxy_for_feature(
                    zone_id=zone_id,
                    domain_name=domain_name,
                    feature_name="Force HTTPS",
                    query=query
                )
                
                if not proxy_result.get('success'):
                    # Check if user confirmation is needed for proxy enablement
                    if proxy_result.get('needs_confirmation'):
                        # Show confirmation dialog for proxy enablement
                        confirmation_message = proxy_result.get('message', 'Proxy enablement required')
                        
                        message = f"""
🔧 Proxy Confirmation Required

{confirmation_message}

Force HTTPS requires Cloudflare proxy to function properly. 

Would you like to enable proxy for these records now?
"""
                        
                        keyboard = [
                            [InlineKeyboardButton("✅ Yes, Enable Proxy", callback_data=f"dns:{domain_name}:security:force_https:confirm_proxy:on"),
                             InlineKeyboardButton("❌ No, Cancel", callback_data=f"dns:{domain_name}:security")],
                        ]
                        
                        reply_markup = InlineKeyboardMarkup(keyboard)
                        await safe_edit_message(query, message, reply_markup=reply_markup)
                        return
                    else:
                        # Proxy enablement failed, show error and return
                        error_message = proxy_result.get('message', 'Failed to enable proxy for Force HTTPS')
                        await safe_edit_message(query, f"❌ Force HTTPS Setup Failed\n\n{error_message}")
                        return
                
                # Enable Force HTTPS
                result = await cloudflare.update_force_https(zone_id, enabled)
                
                # If Force HTTPS fails, rollback proxy changes
                if not result.get('success') and proxy_result.get('rollback_needed'):
                    logger.warning("Force HTTPS failed, rolling back proxy changes")
                    rollback_success = await rollback_proxy_changes(zone_id, proxy_result.get('modified_records', []))
                    if rollback_success:
                        logger.info("Successfully rolled back proxy changes")
                    else:
                        logger.warning("Proxy rollback partially failed")
            else:
                # Disable Force HTTPS
                # Note: We don't disable proxy when turning features off - that's user choice
                result = await cloudflare.update_force_https(zone_id, enabled)
            
            if result.get('success'):
                status = "Enabled" if enabled else "Disabled"
                message = f"""
✅ Force HTTPS Updated

Domain: {domain_name}
Status: {status}

{'All HTTP traffic will now redirect to HTTPS.' if enabled else 'HTTP and HTTPS are both allowed.'}
"""
            else:
                # Handle detailed error messages including SSL validation
                errors = result.get('errors', [{'message': 'Unknown error occurred'}])
                error_messages = []
                
                for error in errors:
                    error_code = error.get('code', '')
                    
                    if error_code == 'ssl_required':
                        error_msg = (
                            "🔒 SSL Certificate Required\n\n"
                            "Force HTTPS requires an active SSL certificate. "
                            "Please ensure your domain has a valid SSL certificate configured before enabling this feature."
                        )
                    else:
                        error_msg = error.get('user_message') or error.get('message', 'Unknown error')
                    
                    error_messages.append(error_msg)
                
                error_text = "\n\n".join(error_messages)
                
                message = f"""
❌ Force HTTPS Update Failed

{error_text}

Please try again later.
"""
            
            keyboard = [
                [InlineKeyboardButton("⬅️ Back to Security", callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
    except Exception as e:
        logger.error(f"Error toggling Force HTTPS setting: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not update Force HTTPS setting.")

async def toggle_auto_proxy_setting(query, domain_name, action):
    """Toggle Auto-Enable Proxy setting for user preference control"""
    try:
        user = query.from_user
        user_record = await get_or_create_user(user.id)
        
        # Check if user owns this domain
        user_domains = await get_user_domains(user_record['id'])
        domain_found = any(d['domain_name'] == domain_name for d in user_domains)
        
        if not domain_found:
            await safe_edit_message(query, "❌ Access Denied\n\nDomain not found in your account.")
            return
        
        if action == "toggle":
            # Show Auto-Proxy preference options
            current_setting = await get_domain_auto_proxy_enabled(domain_name)
            current_status = "✅ Enabled" if current_setting else "❌ Disabled"
            
            message = f"""
🔧 Auto-Enable Proxy: {domain_name}

Current Setting: {current_status}

Choose your preference:

Enable: Automatically enable Cloudflare proxy when using security features
Disable: Ask for confirmation before enabling proxy

_Auto-proxy automatically enables Cloudflare proxy for DNS records when features like JavaScript Challenge or Force HTTPS require it for proper functionality._
"""
            
            keyboard = [
                [InlineKeyboardButton("✅ Enable Auto-Proxy", callback_data=f"dns:{domain_name}:security:auto_proxy:on"),
                 InlineKeyboardButton("❌ Disable Auto-Proxy", callback_data=f"dns:{domain_name}:security:auto_proxy:off")],
                [InlineKeyboardButton("⬅️ Back", callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
        else:
            # Apply Auto-Proxy preference setting
            enabled = action == "on"
            
            # Update the database setting
            success = await set_domain_auto_proxy_enabled(domain_name, enabled)
            
            if success:
                status = "Enabled" if enabled else "Disabled"
                status_icon = "✅" if enabled else "❌"
                
                if enabled:
                    description = "Security features will automatically enable proxy when needed"
                else:
                    description = "You will be prompted before proxy changes are made"
                
                message = f"""
{status_icon} Auto-Proxy Setting Updated

Domain: {domain_name}
Auto-Enable Proxy: {status}

{description}

Your preference has been saved and will apply to future security feature configurations.
"""
            else:
                message = f"""
❌ Auto-Proxy Update Failed

Could not update the auto-proxy setting for {domain_name}.

Please try again later.
"""
            
            keyboard = [
                [InlineKeyboardButton("⬅️ Back to Security", callback_data=f"dns:{domain_name}:security")]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            await safe_edit_message(query, message, reply_markup=reply_markup)
            
    except Exception as e:
        logger.error(f"Error toggling auto-proxy setting: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not update auto-proxy setting.")

async def force_enable_proxy_and_feature(query, domain_name, feature_type):
    """Force enable proxy and then enable security feature when user confirms despite auto-proxy being disabled"""
    try:
        # Get Cloudflare zone info
        cf_zone = await get_cloudflare_zone(domain_name)
        if not cf_zone:
            await safe_edit_message(query, "❌ Error\n\nCloudflare zone not found.")
            return
        
        zone_id = cf_zone['cf_zone_id']
        cloudflare = CloudflareService()
        
        # Show progress message
        await safe_edit_message(query, "🔄 Enabling Proxy...\n\nForce enabling proxy for security feature...")
        
        # Force enable proxy by temporarily overriding auto_proxy_enabled check
        web_records = await cloudflare.get_web_records_for_proxy(zone_id, domain_name)
        
        if not web_records:
            await safe_edit_message(query, "❌ Error\n\nNo web records found to proxy.")
            return
        
        # Categorize records and enable proxy for needed records
        proxy_needed = []
        for record in web_records:
            is_proxied = record.get('proxied', False)
            is_eligible = record.get('proxy_eligible', False)
            
            if is_eligible and not is_proxied:
                proxy_needed.append(record)
        
        if not proxy_needed:
            await safe_edit_message(query, "✅ Proxy Already Enabled\n\nAll required records are already proxied.")
            # Continue to feature enablement
        else:
            # Enable proxy for required records
            modified_records = []
            failed_records = []
            
            for record in proxy_needed:
                record_id = record.get('id')
                record_name = record.get('name', 'unknown')
                
                if not record_id:
                    continue
                
                result = await cloudflare.update_record_proxied(zone_id, record_id, True)
                
                if result.get('success'):
                    modified_records.append({
                        'id': record_id,
                        'name': record_name,
                        'type': record.get('type'),
                        'content': record.get('content')
                    })
                    logger.info(f"✅ Force enabled proxy for {record_name}")
                else:
                    errors = result.get('errors', [])
                    error_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
                    failed_records.append({'name': record_name, 'error': error_msg})
                    logger.error(f"❌ Failed to force enable proxy for {record_name}: {error_msg}")
            
            if failed_records:
                error_list = "\n".join([f"• {r['name']}: {r['error']}" for r in failed_records])
                await safe_edit_message(query, f"❌ Proxy Enablement Failed\n\nSome records could not be proxied:\n\n{error_list}")
                return
        
        # Now enable the requested security feature
        await safe_edit_message(query, f"🔄 Enabling Security Feature...\n\nProxy enabled, now configuring {feature_type.replace('_', ' ').title()}...")
        
        if feature_type == "js_challenge":
            result = await cloudflare.enable_javascript_challenge(zone_id, "Visible JavaScript Challenge - Bot Protection")
            feature_name = "Visible JavaScript Challenge"
        elif feature_type == "force_https":
            result = await cloudflare.update_force_https(zone_id, True)
            feature_name = "Force HTTPS"
        else:
            await safe_edit_message(query, "❌ Error\n\nUnknown security feature type.")
            return
        
        # Show final result
        if result.get('success'):
            message = f"""
✅ {feature_name} Enabled Successfully

Domain: {domain_name}
Proxy: ✅ Enabled for required records
{feature_name}: ✅ Active

Your security feature is now active and working properly.
"""
        else:
            message = f"""
❌ {feature_name} Setup Failed

Proxy was enabled successfully, but the security feature could not be activated.

Please try enabling {feature_name} again from the security settings.
"""
        
        keyboard = [
            [InlineKeyboardButton("⬅️ Back to Security", callback_data=f"dns:{domain_name}:security")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error in force_enable_proxy_and_feature: {e}")
        await safe_edit_message(query, "❌ Error\n\nCould not enable proxy and security feature.")

async def ensure_proxy_for_feature(zone_id: str, domain_name: str, feature_name: str, query=None) -> Dict:
    """
    Automatically enable Cloudflare proxy for web records when required by security features.
    Respects user preference for auto-proxy behavior.
    
    Args:
        zone_id: Cloudflare zone ID
        domain_name: Domain name
        feature_name: Name of feature requiring proxy (for user messaging)
        query: Telegram query for user notifications (optional)
        
    Returns:
        Dict with success status, modified records, and rollback info
    """
    try:
        cloudflare = CloudflareService()
        logger.info(f"🔄 Auto-proxy check for {feature_name} on {domain_name}")
        
        # Check user's auto-proxy preference for this domain
        auto_proxy_enabled = await get_domain_auto_proxy_enabled(domain_name)
        logger.info(f"Auto-proxy preference for {domain_name}: {auto_proxy_enabled}")
        
        # Get web records that should be proxied for web features
        web_records = await cloudflare.get_web_records_for_proxy(zone_id, domain_name)
        
        if not web_records:
            logger.info(f"No web records found for {domain_name}")
            return {
                'success': True,
                'modified_records': [],
                'message': f"No standard web records found to proxy for {feature_name}.",
                'rollback_needed': False
            }
        
        # Categorize records by eligibility and current proxy status
        proxy_needed = []  # Records that need proxy enabled
        already_proxied = []  # Records already proxied
        ineligible = []  # Records that cannot be proxied
        
        for record in web_records:
            is_proxied = record.get('proxied', False)
            is_eligible = record.get('proxy_eligible', False)
            
            if is_eligible and not is_proxied:
                proxy_needed.append(record)
            elif is_eligible and is_proxied:
                already_proxied.append(record)
            else:
                ineligible.append(record)
        
        # If no records need proxy changes, we're good
        if not proxy_needed:
            if already_proxied:
                record_names = [r.get('name', 'unknown') for r in already_proxied]
                message = f"✅ Proxy already enabled for: {', '.join(record_names)}"
            else:
                message = f"No eligible records found for {feature_name}"
            
            return {
                'success': True,
                'modified_records': [],
                'message': message,
                'rollback_needed': False
            }
        
        # Check user preference for auto-proxy - if disabled, require confirmation
        if not auto_proxy_enabled:
            record_names = [r.get('name', 'unknown') for r in proxy_needed]
            record_count = len(proxy_needed)
            
            logger.info(f"Auto-proxy disabled for {domain_name}, requiring user confirmation for {record_count} records")
            
            # Return special status requiring user confirmation
            return {
                'success': False,
                'needs_confirmation': True,
                'pending_records': proxy_needed,
                'message': f"{feature_name} requires proxy to be enabled for {record_count} DNS record{'s' if record_count != 1 else ''} ({', '.join(record_names)}). Enable proxy?",
                'rollback_needed': False
            }
        
        # Auto-proxy is enabled, proceed with automatic proxy enablement
        logger.info(f"Auto-proxy enabled for {domain_name}, proceeding with automatic proxy enablement")
        
        # Enable proxy for eligible records
        modified_records = []
        failed_records = []
        
        logger.info(f"🔧 Enabling proxy for {len(proxy_needed)} records")
        
        for record in proxy_needed:
            record_id = record.get('id')
            record_name = record.get('name', 'unknown')
            
            if not record_id:
                logger.warning(f"No record ID for {record_name}, skipping")
                continue
            
            result = await cloudflare.update_record_proxied(zone_id, record_id, True)
            
            if result.get('success'):
                modified_records.append({
                    'id': record_id,
                    'name': record_name,
                    'type': record.get('type'),
                    'content': record.get('content')
                })
                logger.info(f"✅ Proxy enabled for {record_name}")
            else:
                errors = result.get('errors', [])
                error_msg = errors[0].get('message', 'Unknown error') if errors else 'Unknown error'
                failed_records.append({'name': record_name, 'error': error_msg})
                logger.error(f"❌ Failed to enable proxy for {record_name}: {error_msg}")
        
        # Prepare user-friendly message
        success_count = len(modified_records)
        total_needed = len(proxy_needed)
        
        if success_count == total_needed and success_count > 0:
            # Complete success
            record_names = [r['name'] for r in modified_records]
            formatted_names = []
            for name in record_names:
                if name == domain_name:
                    formatted_names.append(f"{name} (root)")
                else:
                    formatted_names.append(f"{name}")
            
            message = f"🔧 Auto-Enabled Cloudflare Proxy\n\n"
            message += f"Enabled proxy for: {', '.join(formatted_names)}\n"
            message += f"_Required for {feature_name} to function properly._"
            
            # Notify user if query is provided
            if query:
                notification = f"""
🔧 Cloudflare Proxy Auto-Enabled

Enabled proxy for: {', '.join(formatted_names)}

_This is required for {feature_name} to work properly. Your feature will be enabled next._
"""
                await safe_edit_message(query, notification)
                # Brief pause for user to read
                await asyncio.sleep(1)
            
            return {
                'success': True,
                'modified_records': modified_records,
                'message': message,
                'rollback_needed': True
            }
        
        elif success_count > 0:
            # Partial success
            success_names = [r['name'] for r in modified_records]
            failed_names = [r['name'] for r in failed_records]
            
            message = f"⚠️ Partial Proxy Success\n\n"
            message += f"✅ Enabled: {', '.join(success_names)}\n"
            message += f"❌ Failed: {', '.join(failed_names)}\n\n"
            message += f"_Proceeding with {feature_name} for successfully proxied records._"
            
            return {
                'success': True,  # Partial success still allows feature to work
                'modified_records': modified_records,
                'message': message,
                'rollback_needed': True
            }
        
        else:
            # Complete failure
            error_details = []
            for failed in failed_records:
                error_details.append(f"• {failed['name']}: {failed['error']}")
            
            message = f"❌ Proxy Enablement Failed\n\n"
            message += f"Could not enable proxy for any records:\n"
            message += "\n".join(error_details[:3])  # Limit to 3 errors for readability
            if len(error_details) > 3:
                message += f"\n... and {len(error_details) - 3} more"
            
            return {
                'success': False,
                'modified_records': [],
                'message': message,
                'rollback_needed': False
            }
        
    except Exception as e:
        logger.error(f"❌ Error in auto-proxy for {feature_name}: {e}")
        return {
            'success': False,
            'modified_records': [],
            'message': f"Error enabling proxy for {feature_name}: {str(e)}",
            'rollback_needed': False
        }

async def rollback_proxy_changes(zone_id: str, modified_records: List[Dict]) -> bool:
    """
    Rollback proxy changes if feature enablement fails.
    
    Args:
        zone_id: Cloudflare zone ID
        modified_records: List of records that were modified during auto-proxy
        
    Returns:
        True if rollback successful, False otherwise
    """
    try:
        if not modified_records:
            return True
        
        cloudflare = CloudflareService()
        rollback_success = True
        
        logger.info(f"🔄 Rolling back proxy changes for {len(modified_records)} records")
        
        for record in modified_records:
            record_id = record.get('id')
            record_name = record.get('name', 'unknown')
            
            if not record_id:
                continue
            
            result = await cloudflare.update_record_proxied(zone_id, record_id, False)
            
            if result.get('success'):
                logger.info(f"↩️ Proxy disabled for {record_name} (rollback)")
            else:
                logger.error(f"❌ Failed to rollback proxy for {record_name}")
                rollback_success = False
        
        if rollback_success:
            logger.info("✅ Proxy rollback completed successfully")
        else:
            logger.warning("⚠️ Proxy rollback partially failed")
        
        return rollback_success
        
    except Exception as e:
        logger.error(f"❌ Error during proxy rollback: {e}")
        return False

def format_proxy_notification(domain_name: str, feature_name: str, modified_records: List[Dict]) -> str:
    """Format user notification for automatic proxy enablement"""
    if not modified_records:
        return f"No proxy changes needed for {feature_name}."
    
    record_names = []
    for record in modified_records:
        name = record.get('name', 'unknown')
        if name == domain_name:
            record_names.append(f"{name} (root)")
        else:
            record_names.append(f"{name}")
    
    notification = f"🔧 Proxy Auto-Enabled\n\n"
    notification += f"Records: {', '.join(record_names)}\n"
    notification += f"Feature: {feature_name}\n\n"
    notification += "_Cloudflare proxy is now active for these records to enable the requested feature._"
    
    return notification

# HOSTING PAYMENT INTEGRATION - PRIORITY 1
async def show_hosting_payment_options_with_intent(query, intent_id: int, price: float, plan_name: str, domain_name: str):
    """Show payment options for hosting provision intent"""
    user = query.from_user
    
    try:
        user_record = await get_or_create_user(user.id)
        wallet_balance = await get_user_wallet_balance(user.id)
        has_sufficient_balance = wallet_balance >= float(price)
        domain_display = f"Domain: {domain_name}" if domain_name != 'pending-domain' else "Domain: To be configured"
        
        message = f"""💰 Payment Required - Hosting Provision
        
{domain_display}
Plan: {plan_name}
Price: ${price}/month
Your Wallet Balance: {format_money(wallet_balance, 'USD', include_currency=True)}

Choose your payment method:"""
        
        keyboard = []
        if has_sufficient_balance:
            keyboard.append([InlineKeyboardButton(f"💳 Pay with Wallet - ${price}", callback_data=f"pay_hosting_intent_wallet_{intent_id}")])
        
        keyboard.extend([
            [InlineKeyboardButton("💰 Pay with Bitcoin", callback_data=f"pay_hosting_intent_crypto_{intent_id}_bitcoin")],
            [InlineKeyboardButton("💎 Pay with Ethereum", callback_data=f"pay_hosting_intent_crypto_{intent_id}_ethereum")],
            [InlineKeyboardButton("🔶 Pay with USDT", callback_data=f"pay_hosting_intent_crypto_{intent_id}_usdt")],
            [InlineKeyboardButton("⬅️ Back to Plans", callback_data="hosting_plans")]
        ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Update intent status to payment_pending
        await update_hosting_intent_status(intent_id, 'payment_pending')
        
    except Exception as e:
        logger.error(f"Error showing hosting payment options with intent {intent_id}: {e}")
        await safe_edit_message(query, "❌ Error showing payment options. Please try again.")

async def show_hosting_payment_options(query, subscription_id: int, price: float, plan_name: str, domain_name: str):
    """Show payment options for hosting subscription (legacy - for existing subscriptions)"""
    user = query.from_user
    
    try:
        user_record = await get_or_create_user(user.id)
        wallet_balance = await get_user_wallet_balance(user.id)
        has_sufficient_balance = wallet_balance >= float(price)
        domain_display = f"Domain: {domain_name}" if domain_name != 'pending-domain' else "Domain: To be configured"
        
        message = f"""💰 Payment Required - Hosting

{domain_display}
Plan: {plan_name}
Price: ${price}/month
Your Wallet Balance: {format_money(wallet_balance, 'USD', include_currency=True)}

Choose your payment method:"""
        
        keyboard = []
        if has_sufficient_balance:
            keyboard.append([InlineKeyboardButton("💳 Pay with Wallet Balance", callback_data=f"pay_hosting_wallet_{subscription_id}_{price}")])
        else:
            keyboard.append([InlineKeyboardButton("💳 Insufficient Balance (Add Funds)", callback_data="wallet_deposit")])
        
        keyboard.extend([
            [InlineKeyboardButton("₿ Bitcoin (BTC)", callback_data=f"pay_hosting_btc_{subscription_id}_{price}")],
            [InlineKeyboardButton("🚀 Litecoin (LTC)", callback_data=f"pay_hosting_ltc_{subscription_id}_{price}")],
            [InlineKeyboardButton("⬅️ Back to Plans", callback_data="hosting_plans")]
        ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing hosting payment options: {e}")
        await safe_edit_message(query, "❌ Error loading payment options. Please try again.")

async def process_hosting_crypto_payment(query, crypto_type: str, subscription_id: str, price: str):
    """Generate crypto payment for hosting subscription (based on domain crypto payment)"""
    user = query.from_user
    
    try:
        amount = float(price)
        
        # Get subscription details
        subscription = await execute_query(
            "SELECT * FROM hosting_subscriptions WHERE id = %s",
            (int(subscription_id),)
        )
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting subscription not found.")
            return
        
        subscription = subscription[0]
        
        await safe_edit_message(query, f"Generating {crypto_type.upper()} payment address...")
        
        # Get user record for database ID
        from database import get_or_create_user
        user_record = await get_or_create_user(telegram_id=user.id)
        
        # Generate payment with configured provider (DynoPay/BlockBee)
        order_id = f"hosting_{subscription_id}_{user.id}_{int(time.time())}"
        
        from services.payment_provider import PaymentProviderFactory
        provider = PaymentProviderFactory.get_primary_provider()
        payment_result = await provider.create_payment_address(
            currency=crypto_type.lower(),
            order_id=order_id,
            value=amount,
            user_id=user_record['id']
        )
        
        if not payment_result:
            await safe_edit_message(query, "❌ Payment Error\n\nCould not generate payment address. Please try again.")
            return
        
        # Save hosting payment order to database (extend payment_orders table)
        user_record = await get_or_create_user(user.id)
        await execute_update(
            "INSERT INTO payment_orders (user_id, order_type, domain_name, amount, currency, status, payment_address, payment_id, subscription_id, order_subtype) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (user_record['id'], 'hosting', subscription['domain_name'], amount, 'USD', 'pending_payment', payment_result['address'], order_id, int(subscription_id), 'hosting_monthly')
        )
        
        # Show payment instructions
        payment_message = f"""
💰 Hosting Payment Instructions

Domain: {subscription['domain_name']}
Plan: {subscription.get('plan_name', 'Hosting Plan')}
Amount: ${amount}/month (≈ {payment_result.get('crypto_amount', 'TBD')} {crypto_type.upper()})

Send exactly this amount to:
<code>{payment_result['address']}</code>

⏰ Payment expires in 15 minutes
💡 Tap the address above to copy it

Once payment is received, your hosting account will be automatically created!
"""
        
        keyboard = [
            [InlineKeyboardButton("❌ Cancel Order", callback_data="hosting_plans")],
            [InlineKeyboardButton("⬅️ Back to Hosting", callback_data="my_hosting")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, payment_message, reply_markup=reply_markup)
        
        logger.info(f"Hosting crypto payment generated: {crypto_type.upper()} for subscription {subscription_id}")
        
    except Exception as e:
        logger.error(f"Error generating hosting crypto payment: {e}")
        await safe_edit_message(query, "❌ Error generating payment. Please try again.")

async def process_hosting_wallet_payment(query, subscription_id: str, price: str):
    """Process wallet payment for hosting subscription - UPDATED TO USE ORCHESTRATOR PATTERN"""
    user = query.from_user
    
    try:
        amount = float(price)
        subscription = await execute_query("SELECT * FROM hosting_subscriptions WHERE id = %s", (int(subscription_id),))
        
        if not subscription:
            await safe_edit_message(query, "❌ Hosting subscription not found.")
            return
        
        subscription = subscription[0]
        
        # Get user record for orchestrator
        user_record = await get_or_create_user(query.from_user.id)
        user_id = user_record['id']
        
        await safe_edit_message(query, f"💳 Processing wallet payment for hosting...")
        
        # Debit wallet balance first (before routing to orchestrator)
        debit_success = await debit_wallet_balance(
            user_id, 
            amount, 
            f"Hosting subscription payment - {subscription['domain_name']}"
        )
        
        if not debit_success:
            await safe_edit_message(query, "❌ Insufficient wallet balance or payment error.")
            return
        
        logger.info(f"✅ Hosting subscription wallet payment successful: User {user.id} paid ${amount:.2f} for subscription {subscription_id}")
        
        # Create payment details for wallet payments (matching registration fix pattern)
        wallet_payment_details = {
            'amount_usd': amount,
            'currency': 'USD',
            'payment_method': 'wallet'
        }
        
        # Update subscription status to paid
        await execute_update(
            "UPDATE hosting_subscriptions SET status = 'paid', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
            (int(subscription_id),)
        )
        
        # Create hosting account using the improved pattern 
        await create_hosting_account_after_payment(int(subscription_id), subscription, wallet_payment_details)
        
        # Success message with proper payment details
        message = f"""✅ Payment Successful!

Domain: {subscription['domain_name']}
Plan: {subscription.get('plan_name', 'Hosting Plan')}
Amount: ${amount:.2f}/month
Payment: Wallet Balance

🚀 Your hosting account is being created...
You'll receive the account details shortly!"""
        
        keyboard = [
            [InlineKeyboardButton("🏠 My Hosting", callback_data="my_hosting")],
            [InlineKeyboardButton("💰 Wallet", callback_data="wallet_main")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await safe_edit_message(query, message, reply_markup=reply_markup)
        logger.info(f"✅ Hosting wallet payment successful: User {user.id}, Subscription {subscription_id}, Amount ${amount}")
        
    except Exception as e:
        logger.error(f"Error in hosting wallet payment: {e}")
        await safe_edit_message(query, "❌ Payment error. Please try again.")

async def create_hosting_account_after_payment(subscription_id: int, subscription: Dict, payment_details: Optional[Dict] = None):
    """Create cPanel hosting account after successful payment"""
    try:
        logger.info(f"🚀 Creating hosting account for subscription {subscription_id}")
        user = await execute_query("SELECT email FROM users WHERE id = %s", (subscription['user_id'],))
        user_email = user[0]['email'] if user and user[0]['email'] else 'noemail@example.com'
        
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if p.get('id') == subscription['hosting_plan_id']), None)
        
        if not plan:
            logger.error(f"❌ Plan not found for subscription {subscription_id}")
            return
        
        account_details = await cpanel.create_hosting_account(
            domain=subscription['domain_name'],
            plan=plan.get('name', 'default'),
            email=user_email
        )
        
        if account_details:
            await execute_update(
                "UPDATE hosting_subscriptions SET cpanel_username = %s, cpanel_password = %s, server_ip = %s, status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (account_details['username'], account_details['password'], account_details['server_ip'], subscription_id)
            )
            
            await create_cpanel_account(
                subscription_id=subscription_id,
                username=account_details['username'],
                domain=subscription['domain_name'],
                server_name=account_details.get('server_name', 'server1'),
                ip_address=account_details['server_ip']
            )
            
            await send_hosting_account_notification(subscription['user_id'], account_details, subscription)
            logger.info(f"✅ Hosting account created successfully for subscription {subscription_id}")
            
        else:
            logger.error(f"❌ Failed to create hosting account for subscription {subscription_id}")
            
    except Exception as e:
        logger.error(f"Error creating hosting account after payment: {e}")

async def send_hosting_account_notification(user_id: int, account_details: Dict, subscription: Dict):
    """Send hosting account details to user via Telegram"""
    try:
        user = await execute_query("SELECT telegram_id FROM users WHERE id = %s", (user_id,))
        if not user:
            logger.error(f"User not found for hosting notification: {user_id}")
            return
        
        telegram_id = user[0]['telegram_id']
        
        message = f"""🎉 Hosting Account Ready!

✅ Your hosting account has been successfully created:

🌐 Domain: {subscription['domain_name']}
👤 Username: {account_details['username']}
🔑 Password: {account_details['password']}
🖥️ Server IP: {account_details['server_ip']}

🔗 cPanel Login: {account_details.get('cpanel_url', f"https://{subscription['domain_name']}:2083")}

📋 Nameservers:
{chr(10).join(f"• {ns}" for ns in account_details.get('nameservers', ['ns1.yourhost.com', 'ns2.yourhost.com']))}

💡 Setup Instructions:
1. Update your domain's nameservers to the ones above
2. Wait 24-48 hours for DNS propagation
3. Access cPanel to upload your website files

Need help? Contact {BrandConfig().support_contact}"""
        
        from webhook_handler import queue_user_message
        await queue_user_message(telegram_id, message)
        logger.info(f"✅ Hosting account notification sent to user {telegram_id}")
            
    except Exception as e:
        logger.error(f"Error sending hosting account notification: {e}")

# PRIORITY 2.1: DOMAIN + HOSTING BUNDLE INTEGRATION
async def show_domain_hosting_bundle(query):
    """Show domain + hosting bundle options with clear value proposition"""
    try:
        plans = cpanel.get_hosting_plans()
        
        message = f"""📦 Domain + Hosting Bundle

🎯 Complete Website Solution
✅ Domain Registration + Web Hosting
✅ Automatic DNS Configuration  
✅ Instant Setup - No Technical Knowledge Required
✅ Professional Email Included
✅ 99.9% Uptime Guarantee

💰 Bundle Savings:
• Save time with automated setup
• One-click domain configuration
• Professional nameservers included
• Priority support

🚀 Choose your hosting plan to see bundle pricing:"""
        
        keyboard = []
        
        # Add hosting plans with bundle indicators
        for plan in plans:
            plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
            monthly_price = plan.get('monthly_price', 0)
            plan_id = plan.get('id')
            
            # Calculate typical domain price for bundle display using pricing system
            from pricing_utils import PricingConfig
            pricing_config = PricingConfig()
            typical_domain_price = pricing_config.minimum_price
            bundle_total = monthly_price + typical_domain_price
            
            button_text = f"🌟 {plan_name} - ${bundle_total:.0f}/month* (Domain + Hosting)"
            keyboard.append([InlineKeyboardButton(button_text, callback_data=f"bundle_plan_{plan_id}")])
        
        keyboard.extend([
            [InlineKeyboardButton("💡 How It Works", callback_data="bundle_how_it_works")],
            [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data="main_menu")]
        ])
        
        footer_text = "\n\n*Domain price varies by extension (.com, .net, etc.)\nFinal price shown during checkout"
        message += footer_text
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error showing domain hosting bundle: {e}")
        await safe_edit_message(query, "❌ Error loading bundle options. Please try again.")

async def show_bundle_how_it_works(query):
    """Explain the domain + hosting bundle process"""
    message = f"""💡 How Bundle Works

1️⃣ Search domain → 2️⃣ Choose plan → 3️⃣ Pay → 4️⃣ Instant setup ✅

Includes: Domain + hosting + email + cPanel + 99.9% uptime

Ready to get started?"""
    
    keyboard = [
        [InlineKeyboardButton("🚀 Start Bundle Purchase", callback_data="domain_hosting_bundle")],
        [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data="main_menu")]
    ]
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    await safe_edit_message(query, message, reply_markup=reply_markup)

async def start_bundle_domain_search(query, context, plan_id):
    """Start domain search for bundle purchase"""
    try:
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        monthly_price = plan.get('monthly_price', 0)
        
        message = f"""🔍 {plan_name} Bundle (${monthly_price}/month)

Enter domain name:
<i>e.g., mybusiness.com</i>"""
        
        keyboard = [
            [InlineKeyboardButton("⬅️ Back to Bundle Plans", callback_data="domain_hosting_bundle")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await safe_edit_message(query, message, reply_markup=reply_markup)
        
        # Set context for next user message in proper context storage
        context.user_data['bundle_domain_search'] = {'plan_id': plan_id}
        
    except Exception as e:
        logger.error(f"Error starting bundle domain search: {e}")
        await safe_edit_message(query, "❌ Error starting domain search. Please try again.")

async def process_bundle_domain_search(update: Update, context: ContextTypes.DEFAULT_TYPE, domain_name: str, plan_id: str):
    """Process domain search for bundle purchase"""
    message = update.effective_message
    user = update.effective_user
    
    try:
        # Validate domain format with detailed error message
        if not is_valid_domain(domain_name):
            error_msg = get_domain_validation_error(domain_name)
            if message:
                await message.reply_text(
                    create_error_message(
                        "Invalid Domain Format",
                        f"{domain_name} - {error_msg}\n\nValid examples:\n• example.com\n• my-site.org\n• sub.domain.net"
                    ),
                    parse_mode='HTML'
                )
            return
        
        # Get hosting plan details
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            if message:
                await message.reply_text("❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        monthly_price = plan.get('monthly_price', 0)
        
        searching_msg = None
        if message:
            searching_msg = await message.reply_text(f"🔄 Searching {domain_name} for bundle...")
        
        # Check domain availability
        availability = await openprovider.check_domain_availability(domain_name)
        
        if availability is None:
            response_text = f"""⚠️ Search Unavailable: {domain_name}

Service temporarily down. Try again in a few minutes."""
            keyboard = [
                [InlineKeyboardButton("🔄 Try Again", callback_data=f"bundle_plan_{plan_id}")],
                [InlineKeyboardButton("⬅️ Back to Bundle", callback_data="domain_hosting_bundle")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            if searching_msg:
                await searching_msg.edit_text(response_text, reply_markup=reply_markup)
            return
        
        if availability.get('available'):
            # Domain is available - show bundle pricing
            price_info = availability.get('price_info', {})
            domain_price = price_info.get('create_price', 0)
            currency = price_info.get('currency', 'USD')
            is_premium = availability.get('premium', False)
            
            bundle_total = domain_price + monthly_price
            
            # Create attractive bundle presentation
            domain_display = f"💎 Premium Domain" if is_premium else f"✅ Available"
            
            response_text = f"""🎉 Bundle Available: {domain_name}

{domain_display}

📦 Bundle Breakdown:
🌐 Domain: {domain_name} - ${domain_price:.2f}/year
🏠 Hosting: {plan_name} - ${monthly_price:.2f}/month

💰 Total First Month: ${bundle_total:.2f}
💡 Then ${monthly_price:.2f}/month for hosting

🚀 Bundle Includes:
✅ Domain registered with hosting nameservers
✅ Automatic DNS configuration
✅ Instant hosting account setup
✅ Professional email hosting
✅ cPanel control panel access
✅ 99.9% uptime guarantee

Ready to complete your bundle purchase?"""
            
            keyboard = [
                [InlineKeyboardButton(f"🛒 Purchase Bundle - ${bundle_total:.2f}", callback_data=f"confirm_bundle_{plan_id}_{domain_name}")],
                [InlineKeyboardButton("🔍 Search Different Domain", callback_data=f"bundle_plan_{plan_id}")],
                [InlineKeyboardButton("⬅️ Back to Bundle Plans", callback_data="domain_hosting_bundle")]
            ]
        else:
            # Domain not available - show alternatives
            response_text = f"""❌ {domain_name} - Not Available

This domain is already registered.

💡 Try these alternatives:
• Different extension (.net, .org, .io)  
• Add a word (my{domain_name.split('.')[0]}.com)
• Use hyphens ({domain_name.replace('.', '-.')})
• Creative variations

Search for another domain?"""
            
            keyboard = [
                [InlineKeyboardButton("🔍 Search Different Domain", callback_data=f"bundle_plan_{plan_id}")],
                [InlineKeyboardButton("⬅️ Back to Bundle Plans", callback_data="domain_hosting_bundle")]
            ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        if searching_msg:
            await searching_msg.edit_text(response_text, reply_markup=reply_markup)
        
    except Exception as e:
        logger.error(f"Error processing bundle domain search: {e}")
        if message:
            await message.reply_text("❌ Error searching domain. Please try again.")

async def confirm_bundle_purchase(query, plan_id: str, domain_name: str):
    """Confirm and create bundle purchase (domain + hosting)"""
    user = query.from_user
    
    try:
        # Get final pricing and create combined order
        plans = cpanel.get_hosting_plans()
        plan = next((p for p in plans if str(p.get('id')) == str(plan_id)), None)
        
        if not plan:
            await safe_edit_message(query, "❌ Hosting plan not found.")
            return
        
        plan_name = plan.get('plan_name', plan.get('name', 'Unknown'))
        monthly_price = plan.get('monthly_price', 0)
        
        # Get final domain pricing
        availability = await openprovider.check_domain_availability(domain_name)
        if not availability or not availability.get('available'):
            await safe_edit_message(query, f"❌ Domain {domain_name} is no longer available.")
            return
        
        domain_price = availability.get('price_info', {}).get('create_price', 0)
        bundle_total = domain_price + monthly_price
        
        # Create database user record
        db_user = await get_or_create_user(telegram_id=user.id)
        
        # Create hosting provision intent for bundle orders to prevent duplicates
        existing_intent = await get_active_hosting_intent(db_user['id'], domain_name)
        if existing_intent:
            # Use existing intent for bundle orders
            logger.info(f"⚠️ Using existing hosting intent {existing_intent['id']} for bundle order")
            # Still create a temporary subscription ID for bundle flow compatibility
            subscription_id = 999999  # Temporary placeholder for bundle flow
        else:
            # Create new hosting provision intent
            intent_id = await create_hosting_intent(
                user_id=db_user['id'],
                domain_name=domain_name,
                hosting_plan_id=plan.get('id'),
                estimated_price=bundle_total,  # Use full bundle price
                service_type='hosting_domain_bundle'  # This is a domain + hosting bundle
            )
            if intent_id:
                subscription_id = intent_id  # Use intent_id as subscription_id for bundle flow
                logger.info(f"✅ Created hosting provision intent {intent_id} for bundle order")
            else:
                subscription_id = None
        
        if not subscription_id:
            await safe_edit_message(query, "❌ Error creating bundle order. Please try again.")
            return
        
        # Store bundle context in subscription (for coordinated provisioning)
        await execute_update(
            "UPDATE hosting_subscriptions SET notes = %s WHERE id = %s",
            (f"bundle_order:domain_price:{domain_price}", subscription_id)
        )
        
        # Show combined payment options (hosting price + domain price)
        await show_hosting_payment_options(query, subscription_id, bundle_total, f"{plan_name} + {domain_name}", domain_name)
        
        logger.info(f"✅ Bundle order created: User {user.id}, Domain {domain_name}, Plan {plan_name}, Total ${bundle_total}")
        
    except Exception as e:
        logger.error(f"Error confirming bundle purchase: {e}")
        await safe_edit_message(query, "❌ Error processing bundle purchase. Please try again.")

async def handle_unified_checkout_review(query, subscription_id: str):
    """Handle when user wants to change payment method - redirect to payment options"""
    try:
        # Get subscription details from database
        from database import get_hosting_subscription_details_admin
        
        subscription = await get_hosting_subscription_details_admin(int(subscription_id))
        if not subscription:
            await safe_edit_message(query, "❌ Order not found. Please start over.")
            return
        
        # Extract details
        plan_name = subscription.get('plan_name', 'Unknown Plan')
        domain_name = subscription.get('domain_name', '')
        service_type = subscription.get('service_type', 'hosting_only')
        
        # Determine items and pricing based on service type
        if service_type == 'hosting_domain_bundle' and domain_name:
            items = [f"Domain registration: {domain_name}", f"{plan_name} hosting"]
            # Get combined pricing from subscription notes if available
            notes = subscription.get('notes', '')
            if 'domain_price:' in notes:
                domain_price = float(notes.split('domain_price:')[1])
                total_price = subscription.get('total_amount', domain_price + subscription.get('period_price', 0))
            else:
                total_price = subscription.get('total_amount', subscription.get('period_price', 0))
        elif service_type == 'hosting_existing_domain' and domain_name:
            items = [f"Connect domain: {domain_name}", f"{plan_name} hosting"]
            total_price = subscription.get('period_price', 0)
        else:
            items = [f"{plan_name} hosting"]
            total_price = subscription.get('period_price', 0)
        
        # Show payment options again
        await show_unified_payment_options(
            query,
            int(subscription_id),
            float(total_price),
            plan_name,
            domain_name or f"temp_{query.from_user.id}_{int(time.time())}",
            items,
            service_type
        )
        
    except Exception as e:
        logger.error(f"Error in unified checkout review: {e}")
        await safe_edit_message(query, "❌ Error loading payment options. Please try again.")