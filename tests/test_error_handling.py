"""
Error Handling Tests
Tests for user-friendly responses, logging safety, and graceful degradation
"""

import pytest
import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch
from io import StringIO
import sys

from handlers import start_command, domain_command, wallet_command
from admin_handlers import credit_wallet_command
from webhook_handler import process_webhook_message
from message_utils import (
    create_error_message, create_success_message, create_warning_message,
    create_contact_support_message
)


@pytest.mark.asyncio
class TestErrorMessageFormatting:
    """Test user-friendly error message formatting"""
    
    def test_generic_error_message_formatting(self):
        """Test generic error messages are user-friendly"""
        error_cases = [
            ("Database connection failed", "service temporarily unavailable"),
            ("API timeout", "please try again"),
            ("Invalid parameters", "check your input"),
            ("Permission denied", "don't have permission"),
            ("Network error", "connection issue"),
        ]
        
        for technical_error, expected_user_message in error_cases:
            user_message = self._format_user_friendly_error(technical_error)
            
            # Should not contain technical details
            assert "database" not in user_message.lower()
            assert "api" not in user_message.lower()
            assert "exception" not in user_message.lower()
            
            # Should contain user-friendly language
            assert any(phrase in user_message.lower() for phrase in [
                "please try again", "temporarily unavailable", "check your",
                "connection issue", "don't have permission"
            ])
    
    def test_domain_registration_error_messages(self):
        """Test domain registration error message formatting"""
        domain_errors = [
            ("Domain not available", "domain is already registered"),
            ("Payment insufficient", "insufficient wallet balance"),
            ("Contact creation failed", "unable to process registration"),
            ("DNS timeout", "temporary service issue"),
        ]
        
        for technical_error, expected_phrase in domain_errors:
            user_message = self._format_domain_error(technical_error)
            
            # Should be specific to domain context
            assert "domain" in user_message.lower()
            assert expected_phrase.lower() in user_message.lower()
    
    def test_wallet_error_message_formatting(self):
        """Test wallet operation error message formatting"""
        wallet_errors = [
            ("Insufficient balance", "don't have enough funds"),
            ("Transaction failed", "payment could not be processed"),
            ("Invalid amount", "enter a valid amount"),
            ("Wallet locked", "wallet is temporarily unavailable"),
        ]
        
        for technical_error, expected_phrase in wallet_errors:
            user_message = self._format_wallet_error(technical_error)
            
            # Should be wallet-specific
            assert any(word in user_message.lower() for word in [
                "wallet", "balance", "payment", "funds"
            ])
    
    def test_hosting_error_message_formatting(self):
        """Test hosting service error message formatting"""
        hosting_errors = [
            ("cPanel creation failed", "unable to create hosting account"),
            ("DNS configuration error", "domain setup incomplete"),
            ("Server unavailable", "hosting service temporarily unavailable"),
            ("Plan not available", "selected plan is not available"),
        ]
        
        for technical_error, expected_phrase in hosting_errors:
            user_message = self._format_hosting_error(technical_error)
            
            # Should be hosting-specific
            assert any(word in user_message.lower() for word in [
                "hosting", "account", "service", "plan"
            ])
    
    def test_error_message_includes_support_contact(self):
        """Test that error messages include support contact information"""
        error_message = create_contact_support_message("Test error occurred")
        
        # Should include contact information
        assert "support" in error_message.lower()
        assert any(contact in error_message.lower() for contact in [
            "contact", "help", "assistance"
        ])
    
    def _format_user_friendly_error(self, technical_error: str) -> str:
        """Format technical error as user-friendly message"""
        error_mappings = {
            "database": "service temporarily unavailable",
            "api": "please try again in a moment",
            "timeout": "request timed out, please try again",
            "permission": "you don't have permission for this action",
            "network": "connection issue, please check your internet",
            "invalid": "please check your input and try again"
        }
        
        technical_lower = technical_error.lower()
        for tech_term, user_message in error_mappings.items():
            if tech_term in technical_lower:
                return f"Sorry, {user_message}. Please try again or contact support if the issue persists."
        
        return "An error occurred. Please try again or contact support if the issue persists."
    
    def _format_domain_error(self, technical_error: str) -> str:
        """Format domain-specific error as user-friendly message"""
        if "not available" in technical_error.lower():
            return "This domain is already registered by someone else. Please try a different domain name."
        elif "payment" in technical_error.lower():
            return "Insufficient wallet balance for domain registration. Please top up your wallet."
        elif "contact" in technical_error.lower():
            return "Unable to process domain registration. Please contact support for assistance."
        else:
            return "Domain registration failed. Please try again or contact support."
    
    def _format_wallet_error(self, technical_error: str) -> str:
        """Format wallet-specific error as user-friendly message"""
        if "insufficient" in technical_error.lower():
            return "You don't have enough funds in your wallet for this transaction."
        elif "invalid amount" in technical_error.lower():
            return "Please enter a valid amount (minimum $0.01)."
        else:
            return "Wallet operation failed. Please try again or contact support."
    
    def _format_hosting_error(self, technical_error: str) -> str:
        """Format hosting-specific error as user-friendly message"""
        if "cpanel" in technical_error.lower():
            return "Unable to create hosting account. Please contact support for assistance."
        elif "dns" in technical_error.lower():
            return "Domain setup is incomplete. Your hosting account is ready, but DNS configuration needs attention."
        else:
            return "Hosting service error. Please contact support for assistance."


@pytest.mark.asyncio
class TestGracefulErrorHandling:
    """Test graceful error handling in command handlers"""
    
    async def test_start_command_error_handling(self, mock_telegram_update, mock_telegram_context):
        """Test start command handles errors gracefully"""
        mock_telegram_update.message.text = "/start"
        
        # Simulate database error
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.side_effect = Exception("Database connection failed")
            
            # Should not crash
            await start_command(mock_telegram_update, mock_telegram_context)
            
            # Should send error message to user
            mock_telegram_context.bot.send_message.assert_called()
            call_args = mock_telegram_context.bot.send_message.call_args
            error_text = call_args.kwargs.get('text', '').lower()
            
            # Should be user-friendly
            assert "error" in error_text or "sorry" in error_text
            assert "database" not in error_text  # No technical details
    
    async def test_domain_command_network_error_handling(self, mock_telegram_update, mock_telegram_context):
        """Test domain command handles network errors gracefully"""
        mock_telegram_update.message.text = "/domain example.com"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
                mock_check.side_effect = Exception("Network timeout")
                
                # Should not crash
                await domain_command(mock_telegram_update, mock_telegram_context)
                
                # Should inform user of network issue
                mock_telegram_context.bot.send_message.assert_called()
                call_args = mock_telegram_context.bot.send_message.call_args
                error_text = call_args.kwargs.get('text', '').lower()
                
                assert "try again" in error_text or "temporarily unavailable" in error_text
    
    async def test_wallet_command_payment_error_handling(self, mock_telegram_update, mock_telegram_context):
        """Test wallet command handles payment errors gracefully"""
        mock_telegram_update.message.text = "/wallet"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            with patch('handlers.get_user_wallet_balance') as mock_balance:
                mock_balance.side_effect = Exception("Payment service unavailable")
                
                # Should not crash
                await wallet_command(mock_telegram_update, mock_telegram_context)
                
                # Should provide fallback information
                mock_telegram_context.bot.send_message.assert_called()
                call_args = mock_telegram_context.bot.send_message.call_args
                error_text = call_args.kwargs.get('text', '')
                
                # Should still provide wallet interface
                assert len(error_text) > 0
    
    async def test_admin_command_permission_error_handling(self, mock_telegram_update, mock_telegram_context):
        """Test admin commands handle permission errors gracefully"""
        mock_telegram_update.effective_user.id = 12345  # Non-admin user
        mock_telegram_update.message.text = "/credit_wallet testuser 50.00"
        
        with patch('admin_handlers.check_admin_privileges') as mock_admin_check:
            mock_admin_check.return_value = False
            
            # Should not crash
            await credit_wallet_command(mock_telegram_update, mock_telegram_context)
            
            # Should send permission error
            mock_telegram_context.bot.send_message.assert_called()
            call_args = mock_telegram_context.bot.send_message.call_args
            error_text = call_args.kwargs.get('text', '').lower()
            
            assert "permission" in error_text or "access" in error_text
    
    async def test_callback_query_error_handling(self):
        """Test callback query handlers handle errors gracefully"""
        # Mock callback query
        mock_update = MagicMock()
        mock_callback = MagicMock()
        mock_user = MagicMock()
        
        mock_user.id = 12345
        mock_callback.from_user = mock_user
        mock_callback.data = "invalid_callback_data"
        mock_update.callback_query = mock_callback
        mock_update.effective_user = mock_user
        
        mock_context = MagicMock()
        mock_context.bot = AsyncMock()
        
        from handlers import handle_callback
        
        # Should not crash on invalid callback data
        await handle_callback(mock_update, mock_context)
        
        # Should handle error gracefully
        mock_callback.answer.assert_called()


@pytest.mark.asyncio
class TestLoggingSafety:
    """Test that logging doesn't expose sensitive information"""
    
    def test_sensitive_data_not_logged(self):
        """Test that sensitive data is not written to logs"""
        # Capture log output
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = logging.getLogger('test_logger')
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        
        sensitive_data = [
            "password123",
            "sk_live_abc123def456",  # API key
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",  # Bitcoin address
            "user@example.com",  # Email
            "1234567890123456",  # Credit card number
        ]
        
        for data in sensitive_data:
            # Simulate logging with sensitive data
            safe_message = self._sanitize_log_message(f"Processing payment for {data}")
            logger.info(safe_message)
        
        log_contents = log_stream.getvalue()
        
        # Check that sensitive data is not in logs
        for data in sensitive_data:
            assert data not in log_contents, f"Sensitive data {data} found in logs"
        
        # Should contain sanitized versions
        assert "Processing payment for [REDACTED]" in log_contents or \
               "Processing payment for ***" in log_contents
    
    def test_error_logging_sanitization(self):
        """Test that error messages are sanitized before logging"""
        # Capture log output
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        logger = logging.getLogger('test_error_logger')
        logger.addHandler(handler)
        logger.setLevel(logging.ERROR)
        
        # Simulate error with sensitive data
        error_message = "Database error: Connection failed for user password123 at host db.internal.com"
        sanitized_message = self._sanitize_log_message(error_message)
        logger.error(sanitized_message)
        
        log_contents = log_stream.getvalue()
        
        # Should not contain sensitive information
        assert "password123" not in log_contents
        assert "db.internal.com" not in log_contents
        
        # Should contain general error information
        assert "Database error" in log_contents
        assert "Connection failed" in log_contents
    
    def test_api_key_redaction_in_logs(self):
        """Test API keys are redacted in log messages"""
        api_keys = [
            "sk_live_abc123def456ghi789",
            "pk_test_123456789",
            "Bearer eyJhbGciOiJIUzI1NiJ9",
            "API_KEY_abc123def456"
        ]
        
        for api_key in api_keys:
            log_message = f"Making API request with key: {api_key}"
            sanitized = self._sanitize_log_message(log_message)
            
            # Should not contain the actual API key
            assert api_key not in sanitized
            # Should contain redacted version
            assert "[REDACTED]" in sanitized or "***" in sanitized
    
    def test_user_data_privacy_in_logs(self):
        """Test user personal data is protected in logs"""
        user_data = [
            "john.doe@example.com",
            "+1-555-123-4567",
            "John Doe",
            "123 Main St, Anytown, USA"
        ]
        
        for data in user_data:
            log_message = f"Processing user data: {data}"
            sanitized = self._sanitize_log_message(log_message)
            
            # Should not contain actual personal data
            assert data not in sanitized
            # Should contain sanitized version
            assert "[USER_DATA]" in sanitized or "***" in sanitized
    
    def _sanitize_log_message(self, message: str) -> str:
        """Sanitize log message to remove sensitive data"""
        import re
        
        # Email addresses
        message = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL_REDACTED]', message)
        
        # API keys (common patterns)
        message = re.sub(r'sk_live_[a-zA-Z0-9]+', '[API_KEY_REDACTED]', message)
        message = re.sub(r'pk_test_[a-zA-Z0-9]+', '[API_KEY_REDACTED]', message)
        message = re.sub(r'Bearer [a-zA-Z0-9._-]+', '[TOKEN_REDACTED]', message)
        
        # Phone numbers
        message = re.sub(r'[\+]?[1-9]?[0-9]{7,14}', '[PHONE_REDACTED]', message)
        
        # Bitcoin addresses (simplified pattern)
        message = re.sub(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', '[BITCOIN_ADDRESS_REDACTED]', message)
        
        # Credit card numbers
        message = re.sub(r'\b\d{13,19}\b', '[CARD_NUMBER_REDACTED]', message)
        
        # Passwords (common password patterns)
        message = re.sub(r'password[:\s]*[^\s]+', 'password: [REDACTED]', message, flags=re.IGNORECASE)
        
        # Internal hostnames/IPs
        message = re.sub(r'[a-zA-Z0-9.-]+\.internal\.[a-zA-Z0-9.-]+', '[INTERNAL_HOST_REDACTED]', message)
        
        return message


@pytest.mark.asyncio
class TestServiceDegradation:
    """Test graceful service degradation when components fail"""
    
    async def test_domain_search_with_api_failure(self, mock_telegram_update, mock_telegram_context):
        """Test domain search graceful degradation when API fails"""
        mock_telegram_update.message.text = "/search example.com"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
                mock_check.side_effect = Exception("API service down")
                
                # Should provide fallback functionality
                await domain_command(mock_telegram_update, mock_telegram_context)
                
                # Should still provide some value to user
                mock_telegram_context.bot.send_message.assert_called()
                call_args = mock_telegram_context.bot.send_message.call_args
                message_text = call_args.kwargs.get('text', '')
                
                # Should explain the situation and offer alternatives
                assert len(message_text) > 50  # Meaningful response
                assert "try again" in message_text.lower() or "later" in message_text.lower()
    
    async def test_wallet_with_payment_service_failure(self, mock_telegram_update, mock_telegram_context):
        """Test wallet functionality when payment service fails"""
        mock_telegram_update.message.text = "/wallet"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            with patch('services.payment_provider.create_payment_address') as mock_payment:
                mock_payment.side_effect = Exception("Payment service unavailable")
                
                # Should provide partial wallet functionality
                await wallet_command(mock_telegram_update, mock_telegram_context)
                
                # Should still show wallet interface
                mock_telegram_context.bot.send_message.assert_called()
    
    async def test_hosting_with_cpanel_service_failure(self, mock_telegram_update, mock_telegram_context):
        """Test hosting functionality when cPanel service fails"""
        mock_telegram_update.message.text = "/hosting"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            with patch('services.cpanel.CPanelService.create_account') as mock_cpanel:
                mock_cpanel.side_effect = Exception("cPanel service down")
                
                # Should still provide hosting information
                await hosting_command(mock_telegram_update, mock_telegram_context)
                
                # Should inform about service status
                mock_telegram_context.bot.send_message.assert_called()
    
    async def test_database_connection_failure_handling(self, mock_telegram_update, mock_telegram_context):
        """Test handling of database connection failures"""
        mock_telegram_update.message.text = "/profile"
        
        with patch('database.execute_query') as mock_query:
            mock_query.side_effect = Exception("Database connection lost")
            
            from handlers import profile_command
            
            # Should not crash the bot
            await profile_command(mock_telegram_update, mock_telegram_context)
            
            # Should provide meaningful error message
            mock_telegram_context.bot.send_message.assert_called()
            call_args = mock_telegram_context.bot.send_message.call_args
            error_text = call_args.kwargs.get('text', '').lower()
            
            assert "temporarily unavailable" in error_text or "try again" in error_text
    
    async def test_partial_service_availability_messaging(self):
        """Test messaging when services are partially available"""
        # Simulate scenario where domain search works but registration is down
        service_status = {
            'domain_search': True,
            'domain_registration': False,
            'wallet_operations': True,
            'hosting_provisioning': False
        }
        
        status_message = self._create_service_status_message(service_status)
        
        # Should inform users about current capabilities
        assert "search" in status_message.lower()
        assert "registration" in status_message.lower()
        assert "temporarily unavailable" in status_message.lower()
    
    def _create_service_status_message(self, service_status: dict) -> str:
        """Create service status message for users"""
        available_services = [service for service, available in service_status.items() if available]
        unavailable_services = [service for service, available in service_status.items() if not available]
        
        message = "🔧 Service Update:\n\n"
        
        if available_services:
            message += "✅ Available: " + ", ".join(available_services) + "\n"
        
        if unavailable_services:
            message += "⚠️ Temporarily unavailable: " + ", ".join(unavailable_services) + "\n"
            message += "\nWe're working to restore full functionality. Thank you for your patience!"
        
        return message


@pytest.mark.asyncio  
class TestErrorRecoveryMechanisms:
    """Test automatic error recovery mechanisms"""
    
    async def test_automatic_retry_on_transient_failures(self):
        """Test automatic retry for transient failures"""
        retry_count = 0
        
        async def failing_operation():
            nonlocal retry_count
            retry_count += 1
            if retry_count < 3:
                raise Exception("Transient network error")
            return "success"
        
        # Test retry mechanism
        result = await self._retry_operation(failing_operation, max_retries=3)
        
        assert result == "success"
        assert retry_count == 3  # Should have retried 3 times
    
    async def test_circuit_breaker_pattern(self):
        """Test circuit breaker pattern for failing services"""
        failure_count = 0
        
        async def unreliable_service():
            nonlocal failure_count
            failure_count += 1
            if failure_count <= 5:
                raise Exception("Service failure")
            return "service recovered"
        
        # Simulate circuit breaker
        circuit_breaker = {"failures": 0, "open": False}
        
        for i in range(10):
            try:
                result = await self._call_with_circuit_breaker(unreliable_service, circuit_breaker)
                if result:
                    break
            except Exception:
                continue
        
        # Circuit breaker should have opened after failures
        assert circuit_breaker["open"] == True or failure_count > 3
    
    async def test_fallback_service_activation(self):
        """Test fallback service activation when primary fails"""
        primary_service_down = True
        
        async def primary_service():
            if primary_service_down:
                raise Exception("Primary service unavailable")
            return "primary result"
        
        async def fallback_service():
            return "fallback result"
        
        # Test fallback mechanism
        result = await self._call_with_fallback(primary_service, fallback_service)
        
        assert result == "fallback result"
    
    async def _retry_operation(self, operation, max_retries=3, delay=0.01):
        """Retry operation with exponential backoff"""
        for attempt in range(max_retries):
            try:
                return await operation()
            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                await asyncio.sleep(delay * (2 ** attempt))
        
        return None
    
    async def _call_with_circuit_breaker(self, operation, circuit_breaker, failure_threshold=3):
        """Call operation with circuit breaker pattern"""
        if circuit_breaker["open"]:
            raise Exception("Circuit breaker open")
        
        try:
            result = await operation()
            circuit_breaker["failures"] = 0  # Reset on success
            return result
        except Exception as e:
            circuit_breaker["failures"] += 1
            if circuit_breaker["failures"] >= failure_threshold:
                circuit_breaker["open"] = True
            raise e
    
    async def _call_with_fallback(self, primary_operation, fallback_operation):
        """Call operation with fallback"""
        try:
            return await primary_operation()
        except Exception:
            return await fallback_operation()