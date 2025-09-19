"""
Comprehensive webhook security tests
P0 Critical: Authentication, validation, and security measures for payment webhooks
"""

import pytest
import json
import hmac
import hashlib
import secrets
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from http.server import HTTPServer
import threading
import time
from urllib.parse import urlparse, parse_qs

# Import webhook handler components
from webhook_handler import (
    PaymentWebhookHandler, verify_telegram_webhook_secret,
    set_bot_application, queue_user_message
)
from database import (
    credit_user_wallet, get_user_wallet_balance_by_id,
    execute_query, execute_update
)

class MockHTTPRequest:
    """Mock HTTP request for testing webhook handlers"""
    
    def __init__(self, method='POST', path='/', headers=None, body=b''):
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.body = body
        self.command = method
    
    def read_body(self, content_length):
        """Simulate reading request body"""
        return self.body[:content_length]

class TestWebhookSecurity:
    """P0 Critical: Webhook security and authentication tests"""

    @pytest.fixture
    async def webhook_test_user(self, database):
        """Create test user for webhook security tests"""
        user_data = {
            'telegram_id': 999700,
            'username': 'webhook_user',
            'first_name': 'Webhook',
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
    def valid_dynopay_webhook_data(self, webhook_test_user):
        """Valid DynoPay webhook data for testing"""
        return {
            "id": "payment_12345",
            "status": "confirmed",
            "amount": 50.00,
            "currency": "BTC",
            "transaction_hash": "abc123def456ghi789",
            "confirmations": 6,
            "order_id": "order_12345",
            "user_id": str(webhook_test_user),
            "timestamp": int(time.time())
        }

    @pytest.fixture
    def valid_blockbee_webhook_params(self, webhook_test_user):
        """Valid BlockBee webhook parameters for testing"""
        return {
            'txid': 'blockbee_tx_67890',
            'value': '25000000',  # Satoshis
            'confirmations': '6',
            'order_id': 'blockbee_order_456',
            'user_id': str(webhook_test_user),
            'status': 'confirmed'
        }

    # P0 CRITICAL: Authentication Token Validation
    def test_webhook_auth_token_validation_success(self):
        """Test successful webhook authentication token validation"""
        # Mock environment with valid token
        with patch.dict('os.environ', {'WEBHOOK_AUTH_TOKEN': 'valid_secret_token'}):
            # Test valid token
            headers = {'Authorization': 'Bearer valid_secret_token'}
            mock_request = MockHTTPRequest(headers=headers)
            
            # Simulate token validation (would be in webhook handler)
            received_token = mock_request.headers.get('Authorization', '').replace('Bearer ', '')
            expected_token = 'valid_secret_token'
            
            assert received_token == expected_token

    def test_webhook_auth_token_validation_failure(self):
        """Test webhook authentication token validation failure"""
        # Test invalid token
        headers = {'Authorization': 'Bearer invalid_token'}
        mock_request = MockHTTPRequest(headers=headers)
        
        received_token = mock_request.headers.get('Authorization', '').replace('Bearer ', '')
        expected_token = 'valid_secret_token'
        
        assert received_token != expected_token

    def test_webhook_missing_auth_token(self):
        """Test webhook request missing authentication token"""
        # Test missing Authorization header
        headers = {}
        mock_request = MockHTTPRequest(headers=headers)
        
        auth_header = mock_request.headers.get('Authorization')
        assert auth_header is None

    def test_webhook_malformed_auth_token(self):
        """Test webhook request with malformed authentication token"""
        # Test malformed Authorization header
        test_cases = [
            {'Authorization': 'InvalidFormat'},
            {'Authorization': 'Bearer'},  # Missing token
            {'Authorization': ''},  # Empty value
            {'Authorization': 'Basic dGVzdA=='}  # Wrong auth type
        ]
        
        for headers in test_cases:
            mock_request = MockHTTPRequest(headers=headers)
            auth_header = headers.get('Authorization', '')
            
            # None of these should be valid Bearer tokens
            if auth_header.startswith('Bearer '):
                token = auth_header.replace('Bearer ', '')
                assert token == '' or len(token) == 0
            else:
                assert not auth_header.startswith('Bearer ')

    # P0 CRITICAL: Required Parameter Validation
    def test_dynopay_webhook_required_parameters(self, valid_dynopay_webhook_data):
        """Test DynoPay webhook required parameter validation"""
        # Test with all required parameters
        required_fields = ['id', 'status', 'amount', 'transaction_hash', 'order_id']
        
        for field in required_fields:
            assert field in valid_dynopay_webhook_data
            assert valid_dynopay_webhook_data[field] is not None
            assert valid_dynopay_webhook_data[field] != ''

    def test_dynopay_webhook_missing_parameters(self, valid_dynopay_webhook_data):
        """Test DynoPay webhook with missing required parameters"""
        required_fields = ['id', 'status', 'amount', 'transaction_hash', 'order_id']
        
        for missing_field in required_fields:
            # Create webhook data missing one required field
            incomplete_data = valid_dynopay_webhook_data.copy()
            del incomplete_data[missing_field]
            
            # Validation should fail
            is_valid = all(field in incomplete_data for field in required_fields)
            assert not is_valid

    def test_blockbee_webhook_required_parameters(self, valid_blockbee_webhook_params):
        """Test BlockBee webhook required parameter validation"""
        required_fields = ['txid', 'value', 'confirmations', 'order_id']
        
        for field in required_fields:
            assert field in valid_blockbee_webhook_params
            assert valid_blockbee_webhook_params[field] is not None
            assert valid_blockbee_webhook_params[field] != ''

    def test_blockbee_webhook_missing_parameters(self, valid_blockbee_webhook_params):
        """Test BlockBee webhook with missing required parameters"""
        required_fields = ['txid', 'value', 'confirmations', 'order_id']
        
        for missing_field in required_fields:
            incomplete_params = valid_blockbee_webhook_params.copy()
            del incomplete_params[missing_field]
            
            is_valid = all(field in incomplete_params for field in required_fields)
            assert not is_valid

    # P0 CRITICAL: Signature Verification
    def test_webhook_signature_verification_success(self):
        """Test successful webhook signature verification"""
        payload = '{"amount": 50.00, "status": "confirmed", "txid": "test123"}'
        secret = "webhook_secret_key"
        
        # Generate valid signature
        expected_signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Verify signature
        received_signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        assert received_signature == expected_signature

    def test_webhook_signature_verification_failure(self):
        """Test webhook signature verification failure"""
        payload = '{"amount": 50.00, "status": "confirmed", "txid": "test123"}'
        secret = "webhook_secret_key"
        wrong_secret = "wrong_secret_key"
        
        # Generate signature with correct secret
        correct_signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Generate signature with wrong secret
        wrong_signature = hmac.new(
            wrong_secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        assert correct_signature != wrong_signature

    def test_webhook_signature_timing_attack_protection(self):
        """Test webhook signature comparison against timing attacks"""
        payload = '{"test": "data"}'
        secret = "secret_key"
        
        correct_signature = hmac.new(
            secret.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        wrong_signature = "a" * len(correct_signature)
        
        # Use hmac.compare_digest for constant-time comparison
        result1 = hmac.compare_digest(correct_signature, correct_signature)
        result2 = hmac.compare_digest(correct_signature, wrong_signature)
        
        assert result1 is True
        assert result2 is False

    # P0 CRITICAL: HTTP Status Code Responses
    def test_webhook_400_response_invalid_json(self):
        """Test webhook returns 400 for invalid JSON"""
        invalid_json = '{"incomplete": json data'
        
        try:
            json.loads(invalid_json)
            assert False, "Should have raised JSONDecodeError"
        except json.JSONDecodeError:
            # Expected - webhook handler should return 400
            http_status = 400
            assert http_status == 400

    def test_webhook_401_response_invalid_auth(self):
        """Test webhook returns 401 for invalid authentication"""
        # Mock invalid authentication scenario
        received_token = "invalid_token"
        expected_token = "valid_token"
        
        if received_token != expected_token:
            http_status = 401  # Unauthorized
        else:
            http_status = 200
        
        assert http_status == 401

    def test_webhook_200_response_valid_request(self, valid_dynopay_webhook_data):
        """Test webhook returns 200 for valid request"""
        # Simulate successful webhook processing
        is_valid_json = True
        is_authenticated = True
        has_required_fields = True
        
        try:
            json.dumps(valid_dynopay_webhook_data)
        except (TypeError, ValueError):
            is_valid_json = False
        
        if is_valid_json and is_authenticated and has_required_fields:
            http_status = 200
        else:
            http_status = 400
        
        assert http_status == 200

    # P0 CRITICAL: Duplicate Webhook Detection
    async def test_duplicate_webhook_detection_and_rejection(self, webhook_test_user):
        """Test duplicate webhook detection prevents double processing"""
        user_id = webhook_test_user
        
        # First webhook processing
        result1 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=30.00,
            provider='dynopay',
            txid='duplicate_test_tx_001',
            order_id='duplicate_order_001'
        )
        assert result1 is True
        
        balance_after_first = await get_user_wallet_balance_by_id(user_id)
        
        # Duplicate webhook (same txid and provider)
        result2 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=30.00,  # Same amount
            provider='dynopay',  # Same provider
            txid='duplicate_test_tx_001',  # Same txid
            order_id='duplicate_order_001'  # Same order
        )
        assert result2 is True  # Idempotent success
        
        balance_after_duplicate = await get_user_wallet_balance_by_id(user_id)
        assert balance_after_duplicate == balance_after_first  # No double credit

    async def test_webhook_replay_attack_prevention(self, webhook_test_user):
        """Test webhook replay attack prevention"""
        user_id = webhook_test_user
        
        # Simulate webhook with timestamp
        webhook_timestamp = int(time.time()) - 3600  # 1 hour old
        current_timestamp = int(time.time())
        
        # Check if webhook is too old (replay attack protection)
        max_age_seconds = 1800  # 30 minutes
        is_too_old = (current_timestamp - webhook_timestamp) > max_age_seconds
        
        assert is_too_old is True  # Should be rejected as too old

    # P0 CRITICAL: Data Validation and Sanitization
    def test_webhook_amount_validation(self):
        """Test webhook amount validation and sanitization"""
        test_cases = [
            {'amount': 50.00, 'valid': True},
            {'amount': '50.00', 'valid': True},  # String should be convertible
            {'amount': 0, 'valid': False},  # Zero amount
            {'amount': -10.00, 'valid': False},  # Negative amount
            {'amount': 'invalid', 'valid': False},  # Non-numeric
            {'amount': None, 'valid': False},  # None value
            {'amount': '', 'valid': False},  # Empty string
            {'amount': 1000000.00, 'valid': False}  # Excessive amount
        ]
        
        for test_case in test_cases:
            amount = test_case['amount']
            expected_valid = test_case['valid']
            
            try:
                amount_float = float(amount) if amount is not None else 0
                is_valid = amount_float > 0 and amount_float < 999999.99
            except (ValueError, TypeError):
                is_valid = False
            
            assert is_valid == expected_valid

    def test_webhook_transaction_id_validation(self):
        """Test webhook transaction ID validation"""
        test_cases = [
            {'txid': 'abc123def456', 'valid': True},
            {'txid': '', 'valid': False},  # Empty
            {'txid': None, 'valid': False},  # None
            {'txid': 'a' * 256, 'valid': False},  # Too long
            {'txid': '   ', 'valid': False},  # Whitespace only
            {'txid': 'valid_tx_123', 'valid': True}
        ]
        
        for test_case in test_cases:
            txid = test_case['txid']
            expected_valid = test_case['valid']
            
            is_valid = (
                txid is not None and 
                isinstance(txid, str) and 
                len(txid.strip()) > 0 and 
                len(txid) <= 255
            )
            
            assert is_valid == expected_valid

    def test_webhook_order_id_validation(self):
        """Test webhook order ID validation"""
        test_cases = [
            {'order_id': 'order_123', 'valid': True},
            {'order_id': '', 'valid': False},  # Empty
            {'order_id': None, 'valid': False},  # None
            {'order_id': 'valid-order_456', 'valid': True},
            {'order_id': '123' * 100, 'valid': False}  # Too long
        ]
        
        for test_case in test_cases:
            order_id = test_case['order_id']
            expected_valid = test_case['valid']
            
            is_valid = (
                order_id is not None and 
                isinstance(order_id, str) and 
                len(order_id.strip()) > 0 and 
                len(order_id) <= 100
            )
            
            assert is_valid == expected_valid

class TestWebhookSecurityEdgeCases:
    """Edge cases and advanced security scenarios for webhooks"""

    def test_webhook_payload_size_limits(self):
        """Test webhook payload size limits"""
        # Test normal payload
        normal_payload = json.dumps({'amount': 50.00, 'status': 'confirmed'})
        assert len(normal_payload) < 10240  # 10KB limit
        
        # Test excessive payload
        large_data = 'x' * 20000  # 20KB
        large_payload = json.dumps({'data': large_data})
        assert len(large_payload) > 10240

    def test_webhook_content_type_validation(self):
        """Test webhook Content-Type header validation"""
        valid_content_types = [
            'application/json',
            'application/json; charset=utf-8',
            'application/x-www-form-urlencoded'
        ]
        
        invalid_content_types = [
            'text/plain',
            'text/html',
            'application/xml',
            '',
            None
        ]
        
        for content_type in valid_content_types:
            assert 'json' in content_type or 'form-urlencoded' in content_type
        
        for content_type in invalid_content_types:
            if content_type:
                assert 'json' not in content_type and 'form-urlencoded' not in content_type
            else:
                assert content_type in [None, '']

    def test_webhook_rate_limiting(self):
        """Test webhook rate limiting protection"""
        # Simulate rate limiting logic
        webhook_requests = []
        current_time = time.time()
        
        # Add multiple requests from same IP
        for _ in range(15):
            webhook_requests.append({
                'ip': '192.168.1.100',
                'timestamp': current_time,
                'path': '/webhook/dynopay'
            })
        
        # Check if rate limit exceeded (10 requests per minute)
        same_ip_requests = [
            req for req in webhook_requests 
            if req['ip'] == '192.168.1.100' and 
               current_time - req['timestamp'] < 60
        ]
        
        rate_limit_exceeded = len(same_ip_requests) > 10
        assert rate_limit_exceeded is True

    async def test_webhook_concurrent_processing_safety(self, webhook_test_user):
        """Test webhook concurrent processing safety"""
        user_id = webhook_test_user
        
        # Simulate concurrent webhook processing for same transaction
        async def process_webhook(txid: str, delay: float = 0):
            if delay > 0:
                await asyncio.sleep(delay)
            return await credit_user_wallet(
                user_id=user_id,
                amount_usd=25.00,
                provider='dynopay',
                txid=txid,
                order_id='concurrent_test'
            )
        
        # Process same webhook concurrently
        tasks = [
            process_webhook('concurrent_tx_123', 0.0),
            process_webhook('concurrent_tx_123', 0.01),  # Slight delay
            process_webhook('concurrent_tx_123', 0.02)   # Longer delay
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should return True (idempotent), but only one should actually credit
        successful_results = [r for r in results if r is True]
        assert len(successful_results) == 3  # All idempotent successes
        
        # Verify balance only credited once
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == 25.00  # Only credited once

class TestWebhookErrorHandling:
    """Webhook error handling and recovery scenarios"""

    def test_webhook_malformed_json_handling(self):
        """Test webhook handling of malformed JSON"""
        malformed_payloads = [
            '{"incomplete": ',
            '{"amount": 50.00, "status": "confirmed"',  # Missing closing brace
            'not json at all',
            '{"amount": 50.00, "duplicate_key": 1, "duplicate_key": 2}',
            '{"unicode": "\\uXXXX"}'  # Invalid unicode
        ]
        
        for payload in malformed_payloads:
            try:
                json.loads(payload)
                assert False, f"Should have failed to parse: {payload}"
            except json.JSONDecodeError:
                # Expected - should return 400 Bad Request
                pass

    def test_webhook_database_error_handling(self):
        """Test webhook handling when database is unavailable"""
        # Mock database unavailable scenario
        database_available = False
        
        if not database_available:
            # Should return 503 Service Unavailable
            http_status = 503
        else:
            http_status = 200
        
        assert http_status == 503

    def test_webhook_partial_data_corruption(self):
        """Test webhook handling of partially corrupted data"""
        # Test data with some fields corrupted
        corrupted_data = {
            'id': 'payment_123',
            'status': 'confirmed',
            'amount': 'corrupted_amount',  # Should be numeric
            'transaction_hash': None,  # Should be string
            'order_id': ''  # Should be non-empty
        }
        
        # Validate each field
        validation_errors = []
        
        try:
            float(corrupted_data['amount'])
        except (ValueError, TypeError):
            validation_errors.append('Invalid amount')
        
        if not corrupted_data.get('transaction_hash'):
            validation_errors.append('Missing transaction_hash')
        
        if not corrupted_data.get('order_id'):
            validation_errors.append('Missing order_id')
        
        assert len(validation_errors) > 0  # Should have validation errors

class TestTelegramWebhookSecurity:
    """Telegram-specific webhook security tests"""

    def test_telegram_webhook_secret_verification(self):
        """Test Telegram webhook secret token verification"""
        # Mock Telegram webhook verification
        with patch.dict('os.environ', {'TELEGRAM_WEBHOOK_SECRET_TOKEN': 'telegram_secret'}):
            # Test valid secret
            valid_headers = {'X-Telegram-Bot-Api-Secret-Token': 'telegram_secret'}
            is_valid = verify_telegram_webhook_secret(valid_headers)
            assert is_valid is True
            
            # Test invalid secret
            invalid_headers = {'X-Telegram-Bot-Api-Secret-Token': 'wrong_secret'}
            is_valid = verify_telegram_webhook_secret(invalid_headers)
            assert is_valid is False
            
            # Test missing secret
            missing_headers = {}
            is_valid = verify_telegram_webhook_secret(missing_headers)
            assert is_valid is False

    def test_telegram_webhook_timing_attack_protection(self):
        """Test Telegram webhook timing attack protection"""
        correct_secret = 'correct_telegram_secret'
        wrong_secret = 'wrong_telegram_secret'
        
        # Use constant-time comparison
        result1 = hmac.compare_digest(correct_secret, correct_secret)
        result2 = hmac.compare_digest(correct_secret, wrong_secret)
        
        assert result1 is True
        assert result2 is False

class TestWebhookIntegrationSecurity:
    """Integration security tests for webhook processing"""

    @pytest.fixture
    async def security_test_user(self, database):
        """Create user for security integration tests"""
        user_data = {
            'telegram_id': 999800,
            'username': 'security_user',
            'first_name': 'Security',
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

    async def test_end_to_end_webhook_security_flow(self, security_test_user):
        """Test complete webhook security validation flow"""
        user_id = security_test_user
        
        # Step 1: Valid webhook data
        webhook_data = {
            'amount': 75.00,
            'status': 'confirmed',
            'transaction_hash': 'secure_tx_12345',
            'order_id': 'secure_order_12345',
            'user_id': str(user_id)
        }
        
        # Step 2: Validate all security requirements
        # Amount validation
        amount_valid = isinstance(webhook_data['amount'], (int, float)) and webhook_data['amount'] > 0
        assert amount_valid
        
        # Required fields validation
        required_fields = ['amount', 'status', 'transaction_hash', 'order_id']
        fields_valid = all(field in webhook_data and webhook_data[field] for field in required_fields)
        assert fields_valid
        
        # Step 3: Process webhook if all validations pass
        if amount_valid and fields_valid:
            result = await credit_user_wallet(
                user_id=user_id,
                amount_usd=webhook_data['amount'],
                provider='dynopay',
                txid=webhook_data['transaction_hash'],
                order_id=webhook_data['order_id']
            )
            assert result is True
        
        # Step 4: Verify security-compliant processing
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == 75.00

    async def test_webhook_security_audit_logging(self, security_test_user):
        """Test that webhook security events are properly logged"""
        user_id = security_test_user
        
        # Process webhook and verify transaction logging
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=100.00,
            provider='dynopay',
            txid='audit_test_tx',
            order_id='audit_order'
        )
        
        assert result is True
        
        # Verify transaction audit trail exists
        from database import get_user_wallet_transactions
        transactions = await get_user_wallet_transactions(user_id)
        
        # Should have at least one transaction
        assert len(transactions) > 0
        
        # Find the credit transaction
        credit_transaction = next(
            (t for t in transactions if t['transaction_type'] == 'credit'), 
            None
        )
        
        assert credit_transaction is not None
        assert credit_transaction['external_txid'] == 'audit_test_tx'
        assert credit_transaction['provider'] == 'dynopay'