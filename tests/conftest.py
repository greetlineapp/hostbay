"""
Shared test fixtures and configuration for HostBay Telegram Bot test suite
Provides database, mocking, and bot setup for comprehensive testing
"""

import os
import pytest
import asyncio
import psycopg2
import factory
from factory.faker import Faker
from factory.declarations import Sequence, LazyFunction
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, Any, Optional, List
from unittest.mock import AsyncMock, MagicMock, patch
import logging

# Configure test logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Test environment configuration
test_env_vars = {
    'TEST_MODE': '1',  # CRITICAL: Prevent live credential usage during tests
    'DATABASE_URL': os.getenv('TEST_DATABASE_URL', os.getenv('DATABASE_URL')),
    'FINANCIAL_OPERATIONS_ENABLED': 'true',
    'TEST_STRICT_DB': 'true',
    'DOMAIN_PRICE_MARKUP_MULTIPLIER': '3.26',
    'DOMAIN_MINIMUM_PRICE': '25.00',
    'RENEWAL_WARNING_DAYS': '3',
    'RENEWAL_BATCH_SIZE': '50',
    'TELEGRAM_BOT_TOKEN': 'test_token',
    'HOSTING_BUNDLE_DISCOUNT': '15.0'
}
for key, value in test_env_vars.items():
    if value is not None:
        os.environ[key] = str(value)

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def database():
    """Clean test database fixture with transaction rollback"""
    import database
    
    # Initialize database
    await database.init_database()
    
    # Start a transaction for test isolation
    conn = database.get_connection_pool().getconn()
    conn.autocommit = False
    
    try:
        yield conn
    finally:
        # Rollback all changes and return connection
        conn.rollback()
        database.get_connection_pool().putconn(conn)

@pytest.fixture
def mock_bot_application():
    """Mock Telegram bot application for testing"""
    mock_app = MagicMock()
    mock_bot = AsyncMock()
    mock_app.bot = mock_bot
    mock_bot.send_message = AsyncMock()
    mock_bot.edit_message_text = AsyncMock()
    mock_bot.answer_callback_query = AsyncMock()
    return mock_app

@pytest.fixture
def mock_external_apis():
    """Mock all external API services for isolated testing"""
    with patch('services.openprovider.OpenProviderService') as mock_openprovider, \
         patch('services.cloudflare.CloudflareService') as mock_cloudflare, \
         patch('services.cpanel.CPanelService') as mock_cpanel, \
         patch('services.payment_provider.create_payment_address') as mock_payment, \
         patch('services.exchange_rates.get_exchange_rate') as mock_exchange:
        
        # Configure mock responses
        mock_openprovider.return_value.check_domain_availability = AsyncMock(return_value=True)
        mock_openprovider.return_value.register_domain = AsyncMock(return_value={'success': True})
        mock_cloudflare.return_value.create_zone = AsyncMock(return_value={'id': 'test_zone_id'})
        mock_cpanel.return_value.create_account = AsyncMock(return_value={'success': True})
        mock_payment.return_value = {'address': 'test_crypto_address', 'amount': '0.001'}
        mock_exchange.return_value = 1.10
        
        yield {
            'openprovider': mock_openprovider,
            'cloudflare': mock_cloudflare,
            'cpanel': mock_cpanel,
            'payment': mock_payment,
            'exchange': mock_exchange
        }

# Test data factories
class UserFactory(factory.Factory):  # type: ignore[misc]
    """Factory for creating test user data"""
    class Meta:  # type: ignore[misc]
        model = dict
    
    telegram_id = Sequence(lambda n: 100000 + n)
    username = Faker('user_name')
    first_name = Faker('first_name')
    last_name = Faker('last_name')
    language_code = 'en'
    is_admin = False
    wallet_balance = Decimal('100.00')
    terms_accepted = True

class DomainFactory(factory.Factory):  # type: ignore[misc]
    """Factory for creating test domain data"""
    class Meta:  # type: ignore[misc]
        model = dict
    
    domain_name = Faker('domain_name')
    tld = Faker('tld')
    status = 'active'
    expires_at = LazyFunction(lambda: datetime.now() + timedelta(days=365))
    auto_renew = True
    provider_id = Faker('uuid4')

class HostingSubscriptionFactory(factory.Factory):  # type: ignore[misc]
    """Factory for creating test hosting subscription data"""
    class Meta:  # type: ignore[misc]
        model = dict
    
    subscription_id = Faker('uuid4')
    plan_name = Faker('random_element', elements=('starter', 'premium', 'enterprise'))
    billing_cycle = Faker('random_element', elements=('7days', '30days', 'monthly', 'yearly'))
    status = 'active'
    expires_at = LazyFunction(lambda: datetime.now() + timedelta(days=30))
    price = Decimal('25.00')

class WalletTransactionFactory(factory.Factory):  # type: ignore[misc]
    """Factory for creating test wallet transaction data"""
    class Meta:  # type: ignore[misc]
        model = dict
    
    transaction_id = Faker('uuid4')
    amount = Faker('pydecimal', left_digits=3, right_digits=2, positive=True)
    transaction_type = Faker('random_element', elements=('credit', 'debit'))
    description = Faker('sentence')
    created_at = LazyFunction(datetime.now)

@pytest.fixture
def test_user():
    """Generate test user data"""
    return UserFactory()

@pytest.fixture
def test_domain():
    """Generate test domain data"""
    return DomainFactory()

@pytest.fixture
def test_hosting_subscription():
    """Generate test hosting subscription data"""
    return HostingSubscriptionFactory()

@pytest.fixture
def test_wallet_transaction():
    """Generate test wallet transaction data"""
    return WalletTransactionFactory()

@pytest.fixture
def multiple_test_users():
    """Generate multiple test users for load testing"""
    return UserFactory.build_batch(50)

@pytest.fixture
def multiple_test_domains():
    """Generate multiple test domains for load testing"""
    return DomainFactory.build_batch(25)

@pytest.fixture
def multiple_test_subscriptions():
    """Generate multiple hosting subscriptions for load testing"""
    return HostingSubscriptionFactory.build_batch(30)

@pytest.fixture
async def performance_test_setup():
    """Setup for performance and load testing"""
    import database
    import threading
    import time
    
    # Create connection pool for testing
    original_pool_size = database.get_connection_pool().maxconn
    
    # Performance tracking
    performance_data = {
        'start_time': time.time(),
        'operations': [],
        'errors': [],
        'max_connections': 0
    }
    
    yield performance_data
    
    # Cleanup and report
    performance_data['end_time'] = time.time()
    performance_data['duration'] = performance_data['end_time'] - performance_data['start_time']
    logger.info(f"Performance test completed in {performance_data['duration']:.2f}s")

@pytest.fixture
def mock_telegram_update():
    """Mock Telegram update object for handler testing"""
    from telegram import Update, Message, User, Chat
    
    mock_update = MagicMock(spec=Update)
    mock_user = MagicMock(spec=User)
    mock_chat = MagicMock(spec=Chat)
    mock_message = MagicMock(spec=Message)
    
    # Configure mock objects
    mock_user.id = 123456789
    mock_user.username = "testuser"
    mock_user.first_name = "Test"
    mock_user.language_code = "en"
    
    mock_chat.id = 123456789
    mock_chat.type = "private"
    
    mock_message.from_user = mock_user
    mock_message.chat = mock_chat
    mock_message.text = "/start"
    mock_message.message_id = 1
    
    mock_update.effective_user = mock_user
    mock_update.effective_chat = mock_chat
    mock_update.message = mock_message
    
    return mock_update

@pytest.fixture
def mock_telegram_context():
    """Mock Telegram context for handler testing"""
    from telegram.ext import ContextTypes
    
    mock_context = MagicMock()
    mock_context.bot = AsyncMock()
    mock_context.user_data = {}
    mock_context.chat_data = {}
    mock_context.application = MagicMock()
    
    return mock_context

@pytest.fixture
def crypto_payment_config():
    """Configuration for crypto payment testing"""
    return {
        'bitcoin': {
            'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'network': 'bitcoin',
            'confirmations_required': 1
        },
        'ethereum': {
            'address': '0x742d35Cc6639C0532fEb5001b20ecD6A4C4d3667',
            'network': 'ethereum',
            'confirmations_required': 12
        },
        'litecoin': {
            'address': 'LMBJjhazCKrb2DGk2YwgdVuKZH9rLjS7BC',
            'network': 'litecoin',
            'confirmations_required': 6
        }
    }

@pytest.fixture
def webhook_test_data():
    """Test data for webhook testing"""
    return {
        'payment_success': {
            'txid': 'test_transaction_id',
            'amount': '0.001',
            'confirmations': 6,
            'status': 'confirmed'
        },
        'payment_pending': {
            'txid': 'test_pending_transaction',
            'amount': '0.001',
            'confirmations': 0,
            'status': 'pending'
        },
        'payment_failed': {
            'txid': 'test_failed_transaction',
            'amount': '0.0005',
            'confirmations': 0,
            'status': 'failed'
        }
    }

@pytest.fixture
def bundle_pricing_scenarios():
    """Test scenarios for bundle pricing calculations"""
    return [
        {
            'domain_tld': 'com',
            'hosting_plan': 'starter',
            'billing_cycle': '30days',
            'discount_code': None,
            'expected_discount_percentage': 15.0
        },
        {
            'domain_tld': 'org',
            'hosting_plan': 'premium',
            'billing_cycle': 'yearly',
            'discount_code': 'SAVE20',
            'expected_discount_percentage': 35.0  # 15% bundle + 20% code
        },
        {
            'domain_tld': 'net',
            'hosting_plan': 'enterprise',
            'billing_cycle': 'monthly',
            'discount_code': 'EXPIRED2024',
            'expected_discount_percentage': 15.0  # Only bundle discount
        }
    ]

@pytest.fixture
async def concurrent_test_user(database):
    """Create a test user for concurrency testing with higher balance"""
    from database import execute_query
    
    user_data = {
        'telegram_id': 999003,
        'username': 'concurrent_test_user',
        'first_name': 'Concurrent',
        'last_name': 'Tester',
        'wallet_balance': Decimal('1000.00')  # Higher balance for concurrent operations
    }
    
    user_id = await execute_query(
        """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
           VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
           RETURNING id""",
        user_data
    )
    
    return user_id[0]['id'] if user_id else None

@pytest.fixture
def hosting_plan_configs():
    """Hosting plan configurations for testing"""
    return {
        'starter': {
            'price_7days': Decimal('5.00'),
            'price_30days': Decimal('15.00'),
            'price_monthly': Decimal('19.99'),
            'price_yearly': Decimal('199.99'),
            'grace_period_7days': 1,
            'grace_period_30days': 2,
            'grace_period_monthly': 7,
            'grace_period_yearly': 7
        },
        'premium': {
            'price_7days': Decimal('10.00'),
            'price_30days': Decimal('25.00'),
            'price_monthly': Decimal('39.99'),
            'price_yearly': Decimal('399.99'),
            'grace_period_7days': 1,
            'grace_period_30days': 2,
            'grace_period_monthly': 7,
            'grace_period_yearly': 7
        },
        'enterprise': {
            'price_7days': Decimal('20.00'),
            'price_30days': Decimal('50.00'),
            'price_monthly': Decimal('79.99'),
            'price_yearly': Decimal('799.99'),
            'grace_period_7days': 1,
            'grace_period_30days': 2,
            'grace_period_monthly': 7,
            'grace_period_yearly': 7
        }
    }

# Utility functions for tests
def create_test_database_tables():
    """Create test database tables if they don't exist"""
    # This would normally create tables, but we'll use the existing database
    pass

def cleanup_test_data():
    """Clean up test data after tests"""
    # This would clean up test data, handled by database fixture rollback
    pass

def assert_valid_decimal(value, expected_range=None):
    """Assert that a value is a valid decimal within expected range"""
    assert isinstance(value, Decimal), f"Expected Decimal, got {type(value)}"
    if expected_range:
        min_val, max_val = expected_range
        assert min_val <= value <= max_val, f"Value {value} not in range {min_val}-{max_val}"

def assert_valid_timestamp(timestamp):
    """Assert that a timestamp is valid and recent"""
    assert isinstance(timestamp, datetime), f"Expected datetime, got {type(timestamp)}"
    now = datetime.now()
    assert timestamp <= now, f"Timestamp {timestamp} is in the future"
    assert timestamp >= now - timedelta(hours=24), f"Timestamp {timestamp} is too old"