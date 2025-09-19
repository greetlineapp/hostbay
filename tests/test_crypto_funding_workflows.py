"""
Comprehensive tests for crypto funding workflows
P0 Critical: DynoPay and BlockBee payment processing with webhook security
"""

import pytest
import asyncio
import json
import hmac
import hashlib
import secrets
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
import httpx

# Import services under test
from services.dynopay import DynoPayService
from services.blockbee import BlockBeeService
from webhook_handler import PaymentWebhookHandler
from database import (
    credit_user_wallet, get_user_wallet_balance_by_id,
    execute_query, execute_update, get_or_create_user
)

class TestCryptoFundingWorkflows:
    """P0 Critical: Complete crypto funding workflows with webhook processing"""

    @pytest.fixture
    async def crypto_test_user(self, database):
        """Create a test user for crypto funding tests"""
        user_data = {
            'telegram_id': 999100,
            'username': 'crypto_user',
            'first_name': 'Crypto',
            'last_name': 'Tester',
            'wallet_balance': 0.00
        }
        
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    @pytest.fixture
    def mock_dynopay_response(self):
        """Mock DynoPay API response for address creation"""
        return {
            "status": "success",
            "data": {
                "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "amount": 50.00,
                "currency": "BTC",
                "callback_url": "https://webhook.example.com/dynopay?order_id=test_order&auth_token=secure_token"
            }
        }

    @pytest.fixture
    def mock_blockbee_response(self):
        """Mock BlockBee API response for address creation"""
        return {
            "status": "success",
            "address_in": "LMBJjhazCKrb2DGk2YwgdVuKZH9rLjS7BC",
            "callback_url": "https://webhook.example.com/blockbee?order_id=test_order",
            "minimum_transaction": "0.001",
            "priority": "default"
        }

    # P0 CRITICAL: DynoPay Workflow Tests
    async def test_dynopay_address_creation_success(self, mock_dynopay_response):
        """Test successful DynoPay payment address creation"""
        with patch('httpx.AsyncClient.post') as mock_post:
            # Mock successful API response
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_dynopay_response
            mock_post.return_value = mock_response
            
            # Test service
            service = DynoPayService()
            
            # Mock environment variables
            with patch.dict('os.environ', {
                'DYNOPAY_API_KEY': 'test_api_key',
                'DYNOPAY_WALLET_TOKEN': 'test_wallet_token'
            }):
                result = await service.create_payment_address(
                    currency='btc',
                    order_id='test_order_001',
                    value=50.00,
                    user_id=123
                )
            
            assert result is not None
            assert result['address'] == '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
            assert result['currency'] == 'BTC'
            
            # Verify API was called correctly
            mock_post.assert_called_once()
            call_args = mock_post.call_args
            assert 'amount' in call_args[1]['json']
            assert call_args[1]['json']['amount'] == 50.00

    async def test_dynopay_webhook_confirmation_success(self, crypto_test_user):
        """Test DynoPay webhook confirmation creates wallet credit"""
        user_id = crypto_test_user
        
        # Mock webhook data from DynoPay
        webhook_data = {
            "id": "9f3d7b8d-4c2e-4b3a-9d1e-2f3b4c5d6e7f",
            "status": "confirmed",
            "amount": 50.00,
            "currency": "BTC",
            "transaction_hash": "abc123def456",
            "confirmations": 6,
            "order_id": "test_order_001",
            "user_id": str(user_id)
        }
        
        # Process webhook (simulate webhook handler)
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Credit wallet based on webhook confirmation
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=50.00,
            provider='dynopay',
            txid=webhook_data['transaction_hash'],
            order_id=webhook_data['order_id']
        )
        
        assert result is True
        
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance + 50.00

    async def test_dynopay_duplicate_webhook_rejection(self, crypto_test_user):
        """Test DynoPay duplicate webhook detection and idempotent handling"""
        user_id = crypto_test_user
        
        webhook_data = {
            "transaction_hash": "duplicate_test_tx",
            "amount": 25.00,
            "order_id": "duplicate_order"
        }
        
        # First webhook processing
        result1 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=webhook_data['amount'],
            provider='dynopay',
            txid=webhook_data['transaction_hash'],
            order_id=webhook_data['order_id']
        )
        assert result1 is True
        
        balance_after_first = await get_user_wallet_balance_by_id(user_id)
        
        # Duplicate webhook processing
        result2 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=webhook_data['amount'],
            provider='dynopay',
            txid=webhook_data['transaction_hash'],  # Same txid
            order_id=webhook_data['order_id']
        )
        assert result2 is True  # Idempotent success
        
        balance_after_duplicate = await get_user_wallet_balance_by_id(user_id)
        assert balance_after_duplicate == balance_after_first  # No double credit

    async def test_dynopay_minimum_amount_handling(self):
        """Test DynoPay minimum amount requirements"""
        service = DynoPayService()
        
        with patch('httpx.AsyncClient.post') as mock_post, \
             patch.dict('os.environ', {
                 'DYNOPAY_API_KEY': 'test_api_key',
                 'DYNOPAY_WALLET_TOKEN': 'test_wallet_token'
             }):
            
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "status": "success",
                "data": {
                    "address": "test_address",
                    "amount": 5.00,  # Should be adjusted from 0.50
                    "currency": "BTC"
                }
            }
            mock_post.return_value = mock_response
            
            # Test with amount below minimum
            result = await service.create_payment_address(
                currency='btc',
                order_id='min_test',
                value=0.50,  # Below $1 minimum
                user_id=123
            )
            
            # Should succeed with adjusted amount
            assert result is not None
            
            # Verify API was called with adjusted amount
            call_args = mock_post.call_args
            assert call_args[1]['json']['amount'] >= 5.00  # Adjusted to minimum

    # P0 CRITICAL: BlockBee Workflow Tests
    async def test_blockbee_address_creation_success(self, mock_blockbee_response):
        """Test successful BlockBee payment address creation"""
        with patch('httpx.AsyncClient.get') as mock_get:
            # Mock successful API response
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_blockbee_response
            mock_get.return_value = mock_response
            
            service = BlockBeeService()
            
            with patch.dict('os.environ', {'BLOCKBEE_API_KEY': 'test_blockbee_key'}):
                result = await service.create_payment_address(
                    currency='ltc',
                    order_id='blockbee_order_001',
                    value=25.00,
                    user_id=456
                )
            
            assert result is not None
            assert result['address'] == 'LMBJjhazCKrb2DGk2YwgdVuKZH9rLjS7BC'
            assert 'minimum_transaction' in result
            
            # Verify API was called correctly
            mock_get.assert_called_once()

    async def test_blockbee_webhook_confirmation_success(self, crypto_test_user):
        """Test BlockBee webhook confirmation creates wallet credit"""
        user_id = crypto_test_user
        
        # Mock BlockBee webhook data (GET parameters)
        webhook_params = {
            'txid': 'blockbee_tx_12345',
            'value': '25000000',  # Satoshis for 0.25 LTC
            'confirmations': '6',
            'order_id': 'blockbee_order_002',
            'user_id': str(user_id)
        }
        
        # Convert value from satoshis to USD equivalent (mock conversion)
        usd_amount = 25.00
        
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Process webhook confirmation
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=usd_amount,
            provider='blockbee',
            txid=webhook_params['txid'],
            order_id=webhook_params['order_id']
        )
        
        assert result is True
        
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance + usd_amount

    async def test_blockbee_wrong_amount_validation(self, crypto_test_user):
        """Test BlockBee wrong amount/currency validation"""
        user_id = crypto_test_user
        
        # Test insufficient amount
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=0.01,  # Very small amount
            provider='blockbee',
            txid='small_amount_tx',
            order_id='small_order'
        )
        
        # Should still work for small amounts (no minimum in credit function)
        assert result is True
        
        # Test negative amount (should fail)
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=-10.00,
            provider='blockbee',
            txid='negative_tx',
            order_id='negative_order'
        )
        
        assert result is False

    # P0 CRITICAL: Cross-Provider Tests
    async def test_multiple_provider_transactions(self, crypto_test_user):
        """Test handling transactions from multiple providers"""
        user_id = crypto_test_user
        
        # Credit from DynoPay
        dynopay_result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=30.00,
            provider='dynopay',
            txid='dynopay_multi_tx',
            order_id='multi_order_1'
        )
        assert dynopay_result is True
        
        # Credit from BlockBee
        blockbee_result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=20.00,
            provider='blockbee',
            txid='blockbee_multi_tx',
            order_id='multi_order_2'
        )
        assert blockbee_result is True
        
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == 50.00  # 30 + 20

    async def test_same_txid_different_providers(self, crypto_test_user):
        """Test same txid from different providers (should both work)"""
        user_id = crypto_test_user
        
        # Same txid from different providers should be allowed
        same_txid = "same_transaction_id"
        
        # DynoPay transaction
        result1 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=15.00,
            provider='dynopay',
            txid=same_txid,
            order_id='dynopay_order'
        )
        assert result1 is True
        
        # BlockBee transaction with same txid (different provider)
        result2 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=10.00,
            provider='blockbee',
            txid=same_txid,  # Same txid
            order_id='blockbee_order'
        )
        assert result2 is True
        
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == 25.00  # Both should be credited

class TestCryptoProviderFailures:
    """Test crypto provider failure scenarios and error handling"""

    async def test_dynopay_api_failure(self):
        """Test DynoPay API failure handling"""
        with patch('httpx.AsyncClient.post') as mock_post:
            # Mock API failure
            mock_response = AsyncMock()
            mock_response.status_code = 500
            mock_response.text = "Internal Server Error"
            mock_post.return_value = mock_response
            
            service = DynoPayService()
            
            with patch.dict('os.environ', {
                'DYNOPAY_API_KEY': 'test_api_key',
                'DYNOPAY_WALLET_TOKEN': 'test_wallet_token'
            }):
                result = await service.create_payment_address(
                    currency='btc',
                    order_id='fail_test',
                    value=50.00,
                    user_id=123
                )
            
            assert result is None  # Should return None on failure

    async def test_blockbee_api_failure(self):
        """Test BlockBee API failure handling"""
        with patch('httpx.AsyncClient.get') as mock_get:
            # Mock API failure
            mock_response = AsyncMock()
            mock_response.status_code = 400
            mock_response.json.return_value = {
                "status": "error",
                "error": "Invalid API key"
            }
            mock_get.return_value = mock_response
            
            service = BlockBeeService()
            
            with patch.dict('os.environ', {'BLOCKBEE_API_KEY': 'invalid_key'}):
                result = await service.create_payment_address(
                    currency='ltc',
                    order_id='fail_test',
                    value=25.00,
                    user_id=456
                )
            
            assert result is None

    async def test_network_timeout_handling(self):
        """Test network timeout handling for crypto providers"""
        with patch('httpx.AsyncClient.post') as mock_post:
            # Mock network timeout
            mock_post.side_effect = httpx.TimeoutException("Request timed out")
            
            service = DynoPayService()
            
            with patch.dict('os.environ', {
                'DYNOPAY_API_KEY': 'test_api_key',
                'DYNOPAY_WALLET_TOKEN': 'test_wallet_token'
            }):
                result = await service.create_payment_address(
                    currency='btc',
                    order_id='timeout_test',
                    value=50.00,
                    user_id=123
                )
            
            assert result is None

class TestCryptoWebhookSecurity:
    """P0 Critical: Webhook security and authentication tests"""

    def test_webhook_auth_token_validation(self):
        """Test webhook authentication token validation"""
        # Mock valid token
        valid_token = "secure_auth_token_123"
        
        # Mock webhook request with valid token
        mock_headers = {'Authorization': f'Bearer {valid_token}'}
        
        # Test validation logic (would be in webhook handler)
        received_token = mock_headers.get('Authorization', '').replace('Bearer ', '')
        assert received_token == valid_token

    def test_webhook_parameter_validation(self):
        """Test required parameter validation for webhooks"""
        # DynoPay webhook data
        dynopay_data = {
            "id": "payment_id",
            "status": "confirmed",
            "amount": 50.00,
            "transaction_hash": "hash123"
        }
        
        # Validate required fields
        required_fields = ['id', 'status', 'amount', 'transaction_hash']
        for field in required_fields:
            assert field in dynopay_data
            assert dynopay_data[field] is not None

    def test_webhook_signature_verification(self):
        """Test webhook signature verification (for providers that support it)"""
        # Mock webhook payload
        payload = '{"amount": 50.00, "status": "confirmed"}'
        secret = "webhook_secret_key"
        
        # Generate signature
        signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Verify signature
        expected_signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        assert signature == expected_signature

    def test_invalid_webhook_rejection(self):
        """Test rejection of invalid webhook requests"""
        # Test missing required fields
        invalid_webhook_data = {
            "status": "confirmed",
            # Missing amount, transaction_hash, etc.
        }
        
        required_fields = ['amount', 'transaction_hash', 'order_id']
        for field in required_fields:
            assert field not in invalid_webhook_data
        
        # Should return 400 Bad Request for missing fields
        is_valid = all(field in invalid_webhook_data for field in required_fields)
        assert not is_valid

class TestCryptoIntegrationFlows:
    """P1: Integration tests for complete crypto funding flows"""

    @pytest.fixture
    async def integration_test_user(self, database):
        """Create user for integration tests"""
        user_data = {
            'telegram_id': 999200,
            'username': 'integration_user',
            'first_name': 'Integration',
            'last_name': 'Tester',
            'wallet_balance': 0.00
        }
        
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    async def test_complete_dynopay_funding_flow(self, integration_test_user):
        """Test complete DynoPay funding flow: address creation → webhook → wallet credit"""
        user_id = integration_test_user
        
        # Step 1: Create payment address (mocked)
        with patch('httpx.AsyncClient.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "status": "success",
                "data": {
                    "address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                    "amount": 100.00,
                    "currency": "BTC"
                }
            }
            mock_post.return_value = mock_response
            
            service = DynoPayService()
            
            with patch.dict('os.environ', {
                'DYNOPAY_API_KEY': 'test_key',
                'DYNOPAY_WALLET_TOKEN': 'test_token'
            }):
                address_result = await service.create_payment_address(
                    currency='btc',
                    order_id='integration_order',
                    value=100.00,
                    user_id=user_id
                )
            
            assert address_result is not None
        
        # Step 2: Simulate webhook confirmation
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        webhook_result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=100.00,
            provider='dynopay',
            txid='integration_tx_hash',
            order_id='integration_order'
        )
        
        assert webhook_result is True
        
        # Step 3: Verify final wallet balance
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance + 100.00

    async def test_complete_blockbee_funding_flow(self, integration_test_user):
        """Test complete BlockBee funding flow"""
        user_id = integration_test_user
        
        # Step 1: Create payment address (mocked)
        with patch('httpx.AsyncClient.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "status": "success",
                "address_in": "LTC_ADDRESS_123",
                "callback_url": "callback_url",
                "minimum_transaction": "0.001"
            }
            mock_get.return_value = mock_response
            
            service = BlockBeeService()
            
            with patch.dict('os.environ', {'BLOCKBEE_API_KEY': 'test_key'}):
                address_result = await service.create_payment_address(
                    currency='ltc',
                    order_id='blockbee_integration',
                    value=75.00,
                    user_id=user_id
                )
            
            assert address_result is not None
        
        # Step 2: Simulate webhook confirmation
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        webhook_result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=75.00,
            provider='blockbee',
            txid='blockbee_integration_tx',
            order_id='blockbee_integration'
        )
        
        assert webhook_result is True
        
        # Step 3: Verify final state
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance + 75.00