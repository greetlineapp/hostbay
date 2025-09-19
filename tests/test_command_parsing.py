"""
Command Parsing and Formatting Tests
Tests for all Telegram handlers, parameter validation, and error formatting
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from telegram import Update, Message, User, Chat, CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup

from handlers import (
    start_command, domain_command, dns_command, wallet_command,
    search_command, profile_command, hosting_command, handle_callback,
    handle_text_message
)
from admin_handlers import (
    credit_wallet_command, broadcast_command, cancel_command,
    handle_admin_broadcast_text, handle_admin_credit_text
)


@pytest.mark.asyncio
class TestCommandParsing:
    """Test Telegram command parsing and handling"""
    
    async def test_start_command_parsing(self, mock_telegram_update, mock_telegram_context):
        """Test /start command parsing and response"""
        mock_telegram_update.message.text = "/start"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {
                'user_id': 12345,
                'username': 'testuser',
                'wallet_balance': '100.00'
            }
            
            await start_command(mock_telegram_update, mock_telegram_context)
            
            # Should send welcome message
            mock_telegram_context.bot.send_message.assert_called_once()
            call_args = mock_telegram_context.bot.send_message.call_args
            assert 'welcome' in call_args.kwargs.get('text', '').lower()
    
    async def test_start_command_with_parameters(self, mock_telegram_update, mock_telegram_context):
        """Test /start command with parameters (deep linking)"""
        mock_telegram_update.message.text = "/start domain_register_example_com"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345, 'username': 'testuser'}
            
            await start_command(mock_telegram_update, mock_telegram_context)
            
            # Should handle deep link parameter
            mock_telegram_context.bot.send_message.assert_called()
            # Could test deep link processing logic here
    
    async def test_domain_command_parsing(self, mock_telegram_update, mock_telegram_context):
        """Test /domain command parsing"""
        mock_telegram_update.message.text = "/domain"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            await domain_command(mock_telegram_update, mock_telegram_context)
            
            # Should present domain management options
            mock_telegram_context.bot.send_message.assert_called_once()
            call_args = mock_telegram_context.bot.send_message.call_args
            
            # Should include inline keyboard
            assert 'reply_markup' in call_args.kwargs
    
    async def test_domain_command_with_domain_name(self, mock_telegram_update, mock_telegram_context):
        """Test /domain command with domain name parameter"""
        mock_telegram_update.message.text = "/domain example.com"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            with patch('handlers.log_domain_search') as mock_log_search:
                await domain_command(mock_telegram_update, mock_telegram_context)
                
                # Should log the domain search
                mock_log_search.assert_called_with(12345, 'example.com')
    
    async def test_wallet_command_parsing(self, mock_telegram_update, mock_telegram_context):
        """Test /wallet command parsing"""
        mock_telegram_update.message.text = "/wallet"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            with patch('handlers.get_user_wallet_balance') as mock_balance:
                mock_balance.return_value = '150.50'
                
                await wallet_command(mock_telegram_update, mock_telegram_context)
                
                mock_telegram_context.bot.send_message.assert_called_once()
                call_args = mock_telegram_context.bot.send_message.call_args
                
                # Should include wallet balance
                assert '150.50' in call_args.kwargs.get('text', '')
    
    async def test_hosting_command_parsing(self, mock_telegram_update, mock_telegram_context):
        """Test /hosting command parsing"""
        mock_telegram_update.message.text = "/hosting"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            await hosting_command(mock_telegram_update, mock_telegram_context)
            
            mock_telegram_context.bot.send_message.assert_called_once()
            call_args = mock_telegram_context.bot.send_message.call_args
            
            # Should present hosting options
            assert 'reply_markup' in call_args.kwargs
    
    async def test_search_command_parsing(self, mock_telegram_update, mock_telegram_context):
        """Test /search command parsing"""
        mock_telegram_update.message.text = "/search example.com"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
                mock_check.return_value = True
                
                await search_command(mock_telegram_update, mock_telegram_context)
                
                # Should check domain availability
                mock_check.assert_called_once_with('example.com')
    
    async def test_profile_command_parsing(self, mock_telegram_update, mock_telegram_context):
        """Test /profile command parsing"""
        mock_telegram_update.message.text = "/profile"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {
                'user_id': 12345,
                'username': 'testuser',
                'first_name': 'Test',
                'wallet_balance': '100.00',
                'terms_accepted': True
            }
            
            await profile_command(mock_telegram_update, mock_telegram_context)
            
            mock_telegram_context.bot.send_message.assert_called_once()
            call_args = mock_telegram_context.bot.send_message.call_args
            
            # Should include user profile info
            text = call_args.kwargs.get('text', '')
            assert 'testuser' in text
            assert '100.00' in text


@pytest.mark.asyncio
class TestCallbackQueryHandling:
    """Test callback query handling and parsing"""
    
    async def test_domain_search_callback_parsing(self):
        """Test domain search callback query parsing"""
        # Mock callback query
        mock_update = MagicMock()
        mock_callback_query = MagicMock()
        mock_user = MagicMock()
        
        mock_user.id = 12345
        mock_callback_query.from_user = mock_user
        mock_callback_query.data = "search_domain:example.com"
        mock_callback_query.message = MagicMock()
        mock_callback_query.message.message_id = 123
        mock_update.callback_query = mock_callback_query
        mock_update.effective_user = mock_user
        
        mock_context = MagicMock()
        mock_context.bot = AsyncMock()
        
        with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
            mock_check.return_value = True
            
            await handle_callback(mock_update, mock_context)
            
            # Should process domain search
            mock_callback_query.answer.assert_called_once()
    
    async def test_wallet_topup_callback_parsing(self):
        """Test wallet top-up callback query parsing"""
        mock_update = MagicMock()
        mock_callback_query = MagicMock()
        mock_user = MagicMock()
        
        mock_user.id = 12345
        mock_callback_query.from_user = mock_user
        mock_callback_query.data = "wallet_topup:50.00"
        mock_callback_query.message = MagicMock()
        mock_update.callback_query = mock_callback_query
        mock_update.effective_user = mock_user
        
        mock_context = MagicMock()
        mock_context.bot = AsyncMock()
        
        with patch('services.payment_provider.create_payment_address') as mock_payment:
            mock_payment.return_value = {
                'address': 'bc1test123',
                'amount': '0.001'
            }
            
            await handle_callback(mock_update, mock_context)
            
            # Should create payment address
            mock_callback_query.answer.assert_called_once()
    
    async def test_hosting_plan_callback_parsing(self):
        """Test hosting plan selection callback parsing"""
        mock_update = MagicMock()
        mock_callback_query = MagicMock()
        mock_user = MagicMock()
        
        mock_user.id = 12345
        mock_callback_query.from_user = mock_user
        mock_callback_query.data = "hosting_select:starter:7days"
        mock_callback_query.message = MagicMock()
        mock_update.callback_query = mock_callback_query
        mock_update.effective_user = mock_user
        
        mock_context = MagicMock()
        mock_context.bot = AsyncMock()
        
        with patch('handlers.get_user_wallet_balance') as mock_balance:
            mock_balance.return_value = '100.00'
            
            await handle_callback(mock_update, mock_context)
            
            # Should process hosting plan selection
            mock_callback_query.answer.assert_called_once()


@pytest.mark.asyncio
class TestTextMessageHandling:
    """Test text message handling and parsing"""
    
    async def test_domain_name_text_parsing(self, mock_telegram_update, mock_telegram_context):
        """Test domain name parsing from text messages"""
        mock_telegram_update.message.text = "example.com"
        
        # Set user data to indicate domain search context
        mock_telegram_context.user_data = {'expecting': 'domain_name'}
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            with patch('services.openprovider.OpenProviderService.check_domain_availability') as mock_check:
                mock_check.return_value = True
                
                await handle_text_message(mock_telegram_update, mock_telegram_context)
                
                # Should process domain availability
                mock_check.assert_called_with('example.com')
    
    async def test_invalid_domain_name_handling(self, mock_telegram_update, mock_telegram_context):
        """Test handling of invalid domain names"""
        invalid_domains = [
            "invalid domain",
            "domain..com",
            "domain-.com",
            "-domain.com",
            "domain.c",
            "",
            "toolongdomainamethatexceedslimits.com"
        ]
        
        mock_telegram_context.user_data = {'expecting': 'domain_name'}
        
        for invalid_domain in invalid_domains:
            mock_telegram_update.message.text = invalid_domain
            
            with patch('handlers.get_or_create_user') as mock_get_user:
                mock_get_user.return_value = {'user_id': 12345}
                
                await handle_text_message(mock_telegram_update, mock_telegram_context)
                
                # Should send error message for invalid domain
                mock_telegram_context.bot.send_message.assert_called()
                call_args = mock_telegram_context.bot.send_message.call_args
                text = call_args.kwargs.get('text', '').lower()
                assert 'invalid' in text or 'error' in text
    
    async def test_email_text_parsing(self, mock_telegram_update, mock_telegram_context):
        """Test email parsing from text messages"""
        mock_telegram_update.message.text = "user@example.com"
        mock_telegram_context.user_data = {'expecting': 'email'}
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            await handle_text_message(mock_telegram_update, mock_telegram_context)
            
            # Should accept valid email
            mock_telegram_context.bot.send_message.assert_called()
    
    async def test_payment_amount_text_parsing(self, mock_telegram_update, mock_telegram_context):
        """Test payment amount parsing from text messages"""
        mock_telegram_update.message.text = "50.00"
        mock_telegram_context.user_data = {'expecting': 'payment_amount'}
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            await handle_text_message(mock_telegram_update, mock_telegram_context)
            
            # Should process payment amount
            mock_telegram_context.bot.send_message.assert_called()


@pytest.mark.asyncio
class TestAdminCommandParsing:
    """Test admin command parsing and validation"""
    
    async def test_credit_wallet_admin_command(self, mock_telegram_update, mock_telegram_context):
        """Test admin wallet credit command parsing"""
        # Mock admin user
        mock_telegram_update.effective_user.id = 99999  # Admin user ID
        mock_telegram_update.message.text = "/credit_wallet testuser 50.00"
        
        with patch('admin_handlers.check_admin_privileges') as mock_admin_check:
            mock_admin_check.return_value = True
            
            with patch('database.get_user_by_username') as mock_get_user:
                mock_get_user.return_value = {'user_id': 12345, 'username': 'testuser'}
                
                with patch('database.credit_user_wallet') as mock_credit:
                    mock_credit.return_value = True
                    
                    await credit_wallet_command(mock_telegram_update, mock_telegram_context)
                    
                    # Should credit user wallet
                    mock_credit.assert_called_with(12345, '50.00', 'Admin credit via Telegram')
    
    async def test_broadcast_admin_command(self, mock_telegram_update, mock_telegram_context):
        """Test admin broadcast command parsing"""
        mock_telegram_update.effective_user.id = 99999  # Admin user ID
        mock_telegram_update.message.text = "/broadcast Test broadcast message"
        
        with patch('admin_handlers.check_admin_privileges') as mock_admin_check:
            mock_admin_check.return_value = True
            
            await broadcast_command(mock_telegram_update, mock_telegram_context)
            
            # Should initiate broadcast
            mock_telegram_context.bot.send_message.assert_called()
    
    async def test_non_admin_command_blocking(self, mock_telegram_update, mock_telegram_context):
        """Test that non-admin users can't use admin commands"""
        mock_telegram_update.effective_user.id = 12345  # Regular user ID
        mock_telegram_update.message.text = "/credit_wallet testuser 50.00"
        
        with patch('admin_handlers.check_admin_privileges') as mock_admin_check:
            mock_admin_check.return_value = False
            
            await credit_wallet_command(mock_telegram_update, mock_telegram_context)
            
            # Should deny access
            mock_telegram_context.bot.send_message.assert_called()
            call_args = mock_telegram_context.bot.send_message.call_args
            text = call_args.kwargs.get('text', '').lower()
            assert 'access' in text or 'permission' in text or 'admin' in text


@pytest.mark.asyncio
class TestCommandParameterValidation:
    """Test parameter validation in commands"""
    
    async def test_command_parameter_sanitization(self, mock_telegram_update, mock_telegram_context):
        """Test that command parameters are properly sanitized"""
        # Test with potentially malicious input
        malicious_inputs = [
            "/domain <script>alert('xss')</script>.com",
            "/search ' OR 1=1 --",
            "/wallet ../../../etc/passwd",
            "/domain test.com; rm -rf /",
            "/search test.com`whoami`"
        ]
        
        for malicious_input in malicious_inputs:
            mock_telegram_update.message.text = malicious_input
            
            with patch('handlers.get_or_create_user') as mock_get_user:
                mock_get_user.return_value = {'user_id': 12345}
                
                # Should handle malicious input safely
                try:
                    if malicious_input.startswith('/domain'):
                        await domain_command(mock_telegram_update, mock_telegram_context)
                    elif malicious_input.startswith('/search'):
                        await search_command(mock_telegram_update, mock_telegram_context)
                    elif malicious_input.startswith('/wallet'):
                        await wallet_command(mock_telegram_update, mock_telegram_context)
                    
                    # Commands should not crash on malicious input
                    assert True
                except Exception as e:
                    # If exception occurs, it should be handled gracefully
                    assert "sanitiz" in str(e).lower() or "invalid" in str(e).lower()
    
    async def test_numeric_parameter_validation(self, mock_telegram_update, mock_telegram_context):
        """Test validation of numeric parameters"""
        # Mock admin for credit wallet command
        mock_telegram_update.effective_user.id = 99999
        
        invalid_amounts = [
            "/credit_wallet testuser -50.00",  # Negative amount
            "/credit_wallet testuser abc",      # Non-numeric
            "/credit_wallet testuser 0.00",    # Zero amount
            "/credit_wallet testuser 99999.99", # Too large
            "/credit_wallet testuser 0.001",   # Too small (sub-cent)
        ]
        
        for invalid_command in invalid_amounts:
            mock_telegram_update.message.text = invalid_command
            
            with patch('admin_handlers.check_admin_privileges') as mock_admin_check:
                mock_admin_check.return_value = True
                
                await credit_wallet_command(mock_telegram_update, mock_telegram_context)
                
                # Should send validation error
                mock_telegram_context.bot.send_message.assert_called()
                call_args = mock_telegram_context.bot.send_message.call_args
                text = call_args.kwargs.get('text', '').lower()
                assert 'invalid' in text or 'error' in text
    
    async def test_command_length_limits(self, mock_telegram_update, mock_telegram_context):
        """Test that command parameters respect length limits"""
        # Test with very long input
        long_domain = "a" * 300 + ".com"
        mock_telegram_update.message.text = f"/domain {long_domain}"
        
        with patch('handlers.get_or_create_user') as mock_get_user:
            mock_get_user.return_value = {'user_id': 12345}
            
            await domain_command(mock_telegram_update, mock_telegram_context)
            
            # Should handle long input gracefully
            mock_telegram_context.bot.send_message.assert_called()
    
    async def test_unicode_handling_in_commands(self, mock_telegram_update, mock_telegram_context):
        """Test Unicode character handling in commands"""
        unicode_inputs = [
            "/domain тест.рф",      # Cyrillic
            "/search münchen.de",   # German umlauts  
            "/domain 测试.中国",      # Chinese characters
            "/search café.fr",      # French accents
        ]
        
        for unicode_input in unicode_inputs:
            mock_telegram_update.message.text = unicode_input
            
            with patch('handlers.get_or_create_user') as mock_get_user:
                mock_get_user.return_value = {'user_id': 12345}
                
                # Should handle Unicode input properly
                if unicode_input.startswith('/domain'):
                    await domain_command(mock_telegram_update, mock_telegram_context)
                elif unicode_input.startswith('/search'):
                    await search_command(mock_telegram_update, mock_telegram_context)
                
                # Should respond without crashing
                mock_telegram_context.bot.send_message.assert_called()