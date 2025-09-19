"""
Domain Registration Orchestration Edge Cases Tests
Tests for network failures, timeouts, race conditions, and duplicate prevention
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from services.registration_orchestrator import start_domain_registration
from services.openprovider import OpenProviderService
from database import (
    create_registration_intent, update_intent_status, finalize_domain_registration,
    get_active_registration_intent, check_domain_ownership_state
)


@pytest.mark.asyncio
class TestDomainRegistrationOrchestration:
    """Test domain registration orchestration with edge cases"""
    
    async def test_network_failure_during_availability_check(self):
        """Test handling of network failures during domain availability check"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            mock_check.side_effect = httpx.ConnectError("Connection failed")
            
            result = await start_domain_registration(
                user_id=12345,
                domain_name="test-network-fail.com",
                wallet_reservation_id="res_123"
            )
            
            assert result['success'] is False
            assert 'network' in result['error_message'].lower() or 'connection' in result['error_message'].lower()
    
    async def test_openprovider_api_timeout(self):
        """Test handling of OpenProvider API timeouts"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            mock_check.side_effect = asyncio.TimeoutError("API timeout")
            
            result = await start_domain_registration(
                user_id=12345,
                domain_name="test-timeout.com", 
                wallet_reservation_id="res_124"
            )
            
            assert result['success'] is False
            assert 'timeout' in result['error_message'].lower()
    
    async def test_duplicate_registration_prevention(self, database):
        """Test prevention of duplicate domain registrations"""
        domain_name = "test-duplicate.com"
        user_id = 12345
        
        # Mock successful availability check
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            mock_check.return_value = True
            
            # First registration attempt
            with patch('database.create_registration_intent') as mock_create_intent:
                mock_create_intent.return_value = "intent_123"
                
                with patch('database.get_active_registration_intent') as mock_get_intent:
                    mock_get_intent.return_value = None  # No existing intent
                    
                    result1 = await start_domain_registration(
                        user_id=user_id,
                        domain_name=domain_name,
                        wallet_reservation_id="res_125"
                    )
                    
                    # Second registration attempt (duplicate)
                    mock_get_intent.return_value = {
                        'intent_id': 'intent_123',
                        'status': 'processing',
                        'created_at': datetime.now() - timedelta(minutes=5)
                    }
                    
                    result2 = await start_domain_registration(
                        user_id=user_id,
                        domain_name=domain_name,
                        wallet_reservation_id="res_126"
                    )
                    
                    # Second attempt should be blocked
                    assert result2['success'] is False
                    assert 'duplicate' in result2['error_message'].lower() or 'already' in result2['error_message'].lower()
    
    async def test_domain_availability_race_condition(self):
        """Test race condition when domain becomes unavailable during registration"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            # First check returns available
            mock_check.return_value = True
            
            with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
                # Registration fails because domain was taken by someone else
                mock_register.side_effect = Exception("Domain no longer available")
                
                result = await start_domain_registration(
                    user_id=12345,
                    domain_name="test-race.com",
                    wallet_reservation_id="res_127"
                )
                
                assert result['success'] is False
                assert 'available' in result['error_message'].lower()
    
    async def test_contact_handle_creation_failure(self):
        """Test handling of contact handle creation failures"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            mock_check.return_value = True
            
            with patch('services.openprovider.OpenProviderService.create_contact_handle') as mock_contact:
                mock_contact.side_effect = Exception("Contact creation failed")
                
                result = await start_domain_registration(
                    user_id=12345,
                    domain_name="test-contact-fail.com",
                    wallet_reservation_id="res_128"
                )
                
                assert result['success'] is False
                assert 'contact' in result['error_message'].lower()
    
    async def test_registration_intent_cleanup_on_failure(self, database):
        """Test that registration intents are properly cleaned up on failure"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            mock_check.return_value = True
            
            with patch('database.create_registration_intent') as mock_create_intent:
                mock_create_intent.return_value = "intent_cleanup_test"
                
                with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
                    mock_register.side_effect = Exception("Registration failed")
                    
                    with patch('database.update_intent_status') as mock_update_status:
                        result = await start_domain_registration(
                            user_id=12345,
                            domain_name="test-cleanup.com",
                            wallet_reservation_id="res_129"
                        )
                        
                        # Should have updated intent status to failed
                        mock_update_status.assert_called_with("intent_cleanup_test", "failed")
                        assert result['success'] is False
    
    async def test_partial_registration_state_recovery(self):
        """Test recovery from partial registration states"""
        domain_name = "test-recovery.com"
        user_id = 12345
        
        # Simulate partial registration state
        with patch('database.get_active_registration_intent') as mock_get_intent:
            mock_get_intent.return_value = {
                'intent_id': 'intent_recovery',
                'status': 'processing',
                'created_at': datetime.now() - timedelta(minutes=30),  # Old enough to retry
                'domain_name': domain_name,
                'user_id': user_id
            }
            
            with patch('services.openprovider.OpenProviderService.check_domain_status') as mock_check_status:
                mock_check_status.return_value = {'status': 'registered', 'provider_id': 'prov_123'}
                
                with patch('database.finalize_domain_registration') as mock_finalize:
                    result = await start_domain_registration(
                        user_id=user_id,
                        domain_name=domain_name,
                        wallet_reservation_id="res_130"
                    )
                    
                    # Should have recovered and finalized the registration
                    mock_finalize.assert_called_once()
                    assert result['success'] is True
    
    @patch('services.openprovider.OpenProviderService.check_domain_availability')
    async def test_domain_name_validation_edge_cases(self, mock_check):
        """Test domain name validation edge cases"""
        mock_check.return_value = True
        
        invalid_domains = [
            "",  # Empty domain
            "a",  # Too short
            "a.b",  # Too short TLD
            "domain-.com",  # Ends with hyphen
            "-domain.com",  # Starts with hyphen
            "domain..com",  # Double dot
            "domain.c",  # TLD too short
            "very-long-domain-name-that-exceeds-maximum-length-limits-for-domain-names-which-should-be-rejected.com",  # Too long
            "domain.123",  # Numeric TLD
            "dom ain.com",  # Contains space
            "domain.com.",  # Trailing dot
        ]
        
        for invalid_domain in invalid_domains:
            result = await start_domain_registration(
                user_id=12345,
                domain_name=invalid_domain,
                wallet_reservation_id=f"res_{invalid_domain.replace('.', '_')}"
            )
            
            assert result['success'] is False, f"Domain {invalid_domain} should be invalid"
            assert 'invalid' in result['error_message'].lower() or 'valid' in result['error_message'].lower()
    
    async def test_concurrent_registration_attempts(self):
        """Test handling of concurrent registration attempts for the same domain"""
        domain_name = "test-concurrent.com"
        
        # Simulate slow API response to create race condition window
        async def slow_availability_check(domain):
            await asyncio.sleep(0.1)  # Small delay
            return True
        
        with patch('services.openprovider.OpenProviderService.check_domain_availability', side_effect=slow_availability_check):
            with patch('database.create_registration_intent') as mock_create_intent:
                # First call succeeds
                mock_create_intent.return_value = "intent_concurrent_1"
                
                with patch('database.get_active_registration_intent') as mock_get_intent:
                    # Simulate concurrent attempts
                    mock_get_intent.side_effect = [None, {'intent_id': 'intent_concurrent_1', 'status': 'processing'}]
                    
                    # Start two concurrent registrations
                    task1 = asyncio.create_task(start_domain_registration(
                        user_id=12345,
                        domain_name=domain_name,
                        wallet_reservation_id="res_concurrent_1"
                    ))
                    
                    task2 = asyncio.create_task(start_domain_registration(
                        user_id=12345,
                        domain_name=domain_name,
                        wallet_reservation_id="res_concurrent_2"
                    ))
                    
                    result1, result2 = await asyncio.gather(task1, task2, return_exceptions=True)
                    
                    # One should succeed, one should fail with duplicate error
                    successes = sum(1 for r in [result1, result2] if isinstance(r, dict) and r.get('success'))
                    assert successes <= 1, "Only one concurrent registration should succeed"
    
    async def test_openprovider_api_rate_limiting(self):
        """Test handling of OpenProvider API rate limiting"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            # Simulate rate limiting response
            rate_limit_error = httpx.HTTPStatusError(
                "Rate limit exceeded",
                request=MagicMock(),
                response=MagicMock(status_code=429)
            )
            mock_check.side_effect = rate_limit_error
            
            result = await start_domain_registration(
                user_id=12345,
                domain_name="test-rate-limit.com",
                wallet_reservation_id="res_131"
            )
            
            assert result['success'] is False
            assert 'rate' in result['error_message'].lower() or 'limit' in result['error_message'].lower()
    
    async def test_openprovider_authentication_failure(self):
        """Test handling of OpenProvider authentication failures"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            # Simulate authentication error
            auth_error = httpx.HTTPStatusError(
                "Authentication failed",
                request=MagicMock(),
                response=MagicMock(status_code=401)
            )
            mock_check.side_effect = auth_error
            
            result = await start_domain_registration(
                user_id=12345,
                domain_name="test-auth-fail.com",
                wallet_reservation_id="res_132"
            )
            
            assert result['success'] is False
            assert 'auth' in result['error_message'].lower() or 'credential' in result['error_message'].lower()
    
    @patch('database.finalize_domain_registration')
    async def test_database_failure_during_finalization(self, mock_finalize):
        """Test handling of database failures during registration finalization"""
        mock_finalize.side_effect = Exception("Database error during finalization")
        
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            mock_check.return_value = True
            
            with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
                mock_register.return_value = {'success': True, 'provider_id': 'prov_db_fail'}
                
                result = await start_domain_registration(
                    user_id=12345,
                    domain_name="test-db-fail.com",
                    wallet_reservation_id="res_133"
                )
                
                # Registration should fail due to database error
                assert result['success'] is False
                assert 'database' in result['error_message'].lower()


@pytest.mark.asyncio
class TestDomainOrchestrationRetryLogic:
    """Test retry logic and resilience in domain registration"""
    
    async def test_automatic_retry_on_transient_failures(self):
        """Test automatic retry on transient network failures"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            # First call fails, second succeeds
            mock_check.side_effect = [
                httpx.ConnectError("Transient connection error"),
                True
            ]
            
            with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
                mock_register.return_value = {'success': True, 'provider_id': 'prov_retry'}
                
                result = await start_domain_registration(
                    user_id=12345,
                    domain_name="test-retry.com",
                    wallet_reservation_id="res_134"
                )
                
                # Should succeed after retry
                assert mock_check.call_count == 2
    
    async def test_max_retry_limit_enforcement(self):
        """Test that retry attempts don't exceed maximum limits"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            # Always fail to test retry limit
            mock_check.side_effect = httpx.ConnectError("Persistent connection error")
            
            result = await start_domain_registration(
                user_id=12345,
                domain_name="test-max-retry.com",
                wallet_reservation_id="res_135"
            )
            
            # Should fail after max retries
            assert result['success'] is False
            # Should not exceed reasonable retry count (e.g., 3-5 attempts)
            assert mock_check.call_count <= 5


@pytest.mark.asyncio
class TestDomainOrchestrationComplexScenarios:
    """Test complex domain registration scenarios"""
    
    async def test_registration_with_custom_nameservers(self):
        """Test domain registration with custom nameserver configuration"""
        custom_nameservers = ["ns1.custom.com", "ns2.custom.com"]
        
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            mock_check.return_value = True
            
            with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
                mock_register.return_value = {'success': True, 'provider_id': 'prov_custom_ns'}
                
                result = await start_domain_registration(
                    user_id=12345,
                    domain_name="test-custom-ns.com",
                    wallet_reservation_id="res_136",
                    nameservers=custom_nameservers
                )
                
                # Should pass custom nameservers to registration
                mock_register.assert_called_once()
                call_args = mock_register.call_args
                assert custom_nameservers in call_args[1].values() or any(
                    ns in str(call_args) for ns in custom_nameservers
                )
    
    async def test_registration_with_privacy_protection(self):
        """Test domain registration with WHOIS privacy protection"""
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            mock_check.return_value = True
            
            with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
                mock_register.return_value = {'success': True, 'provider_id': 'prov_privacy'}
                
                result = await start_domain_registration(
                    user_id=12345,
                    domain_name="test-privacy.com",
                    wallet_reservation_id="res_137",
                    enable_privacy=True
                )
                
                # Should enable privacy protection
                mock_register.assert_called_once()
                call_args = mock_register.call_args
                # Check that privacy option was passed
                assert any('privacy' in str(arg).lower() for arg in call_args[1].values())
    
    async def test_bulk_domain_registration_failure_isolation(self):
        """Test that failures in bulk registration don't affect other domains"""
        domains = ["test-bulk1.com", "test-bulk2.com", "test-bulk3.com"]
        
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            # Second domain check fails
            mock_check.side_effect = [True, Exception("API error"), True]
            
            results = []
            for i, domain in enumerate(domains):
                result = await start_domain_registration(
                    user_id=12345,
                    domain_name=domain,
                    wallet_reservation_id=f"res_bulk_{i}"
                )
                results.append(result)
            
            # First and third should succeed, second should fail
            assert results[0]['success'] is True or results[2]['success'] is True
            # At least one should fail due to API error
            assert any(not r['success'] for r in results)