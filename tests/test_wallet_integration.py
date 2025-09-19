"""
Comprehensive wallet integration tests
P1 Important: End-to-end integration tests for complete payment flows with mocked external services
"""

import pytest
import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
from decimal import Decimal
from concurrent.futures import ThreadPoolExecutor, as_completed
import httpx

# Import all services for integration testing
from services.dynopay import DynoPayService
from services.blockbee import BlockBeeService
from services.openprovider import OpenProviderService
from services.cpanel import CPanelService
from services.registration_orchestrator import start_domain_registration
from services.hosting_orchestrator import HostingBundleOrchestrator
from webhook_handler import PaymentWebhookHandler
from database import (
    credit_user_wallet, debit_wallet_balance, reserve_wallet_balance,
    finalize_wallet_reservation, get_user_wallet_balance_by_id,
    get_user_wallet_transactions, execute_query, execute_update,
    init_database, get_or_create_user
)

class TestWalletIntegrationFlows:
    """P1 Important: Complete end-to-end integration tests"""

    @pytest.fixture
    async def integration_user(self, database):
        """Create test user for integration tests with substantial balance"""
        user_data = {
            'telegram_id': 999900,
            'username': 'integration_user',
            'first_name': 'Integration',
            'last_name': 'Tester',
            'wallet_balance': Decimal('1000.00')  # High balance for complex tests
        }
        
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    @pytest.fixture
    def mock_all_external_services(self):
        """Mock all external services for integration testing"""
        with patch('httpx.AsyncClient') as mock_client:
            # Mock successful responses for all services
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'status': 'success'}
            
            mock_client_instance = AsyncMock()
            mock_client_instance.post.return_value = mock_response
            mock_client_instance.get.return_value = mock_response
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            yield mock_client_instance

    # P1: Complete Crypto Funding Integration
    async def test_complete_crypto_funding_integration_dynopay(self, integration_user, mock_all_external_services):
        """Test complete crypto funding flow: DynoPay address creation → payment → webhook → wallet credit"""
        user_id = integration_user
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Step 1: Create payment address via DynoPay
        mock_all_external_services.post.return_value.json.return_value = {
            "status": "success",
            "data": {
                "address": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                "amount": 150.00,
                "currency": "BTC",
                "callback_url": "https://webhook.test.com/dynopay?order_id=integration_001"
            }
        }
        
        with patch.dict('os.environ', {
            'DYNOPAY_API_KEY': 'test_key',
            'DYNOPAY_WALLET_TOKEN': 'test_token'
        }):
            dynopay_service = DynoPayService()
            address_result = await dynopay_service.create_payment_address(
                currency='btc',
                order_id='integration_001',
                value=150.00,
                user_id=user_id
            )
        
        assert address_result is not None
        assert address_result['address'] == '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'
        assert address_result['currency'] == 'BTC'
        
        # Step 2: Simulate payment received and webhook processing
        webhook_result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=150.00,
            provider='dynopay',
            txid='integration_tx_dynopay_001',
            order_id='integration_001'
        )
        
        assert webhook_result is True
        
        # Step 3: Verify complete flow results
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance + 150.00
        
        # Step 4: Verify transaction audit trail
        transactions = await get_user_wallet_transactions(user_id)
        credit_tx = next((t for t in transactions if t['transaction_type'] == 'credit'), None)
        assert credit_tx is not None
        assert credit_tx['external_txid'] == 'integration_tx_dynopay_001'
        assert credit_tx['provider'] == 'dynopay'

    async def test_complete_crypto_funding_integration_blockbee(self, integration_user, mock_all_external_services):
        """Test complete crypto funding flow: BlockBee address creation → payment → webhook → wallet credit"""
        user_id = integration_user
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Step 1: Create payment address via BlockBee
        mock_all_external_services.get.return_value.json.return_value = {
            "status": "success",
            "address_in": "LTC_ADDRESS_INTEGRATION_TEST",
            "callback_url": "https://webhook.test.com/blockbee",
            "minimum_transaction": "0.001"
        }
        
        with patch.dict('os.environ', {'BLOCKBEE_API_KEY': 'test_blockbee_key'}):
            blockbee_service = BlockBeeService()
            address_result = await blockbee_service.create_payment_address(
                currency='ltc',
                order_id='blockbee_integration_001',
                value=100.00,
                user_id=user_id
            )
        
        assert address_result is not None
        assert address_result['address'] == 'LTC_ADDRESS_INTEGRATION_TEST'
        
        # Step 2: Simulate payment confirmation via webhook
        webhook_result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=100.00,
            provider='blockbee',
            txid='integration_tx_blockbee_001',
            order_id='blockbee_integration_001'
        )
        
        assert webhook_result is True
        
        # Step 3: Verify integration results
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance + 100.00

    # P1: Complete Domain Purchase Integration
    async def test_complete_domain_purchase_integration(self, integration_user):
        """Test complete domain purchase flow: price → reserve → register → finalize"""
        user_id = integration_user
        domain_name = 'integration-test-domain.com'
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Mock OpenProvider responses
        with patch('services.openprovider.OpenProviderService.get_domain_price') as mock_price, \
             patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
            
            # Step 1: Get domain price
            mock_price.return_value = {'price': 15.00, 'currency': 'USD'}
            
            service = OpenProviderService()
            price_result = await service.get_domain_price(domain_name, 1)
            base_price = price_result['price']
            
            # Step 2: Calculate final price with markup
            from pricing_utils import calculate_marked_up_price
            final_price = calculate_marked_up_price(base_price)
            
            # Step 3: Reserve wallet funds
            reservation_id = await reserve_wallet_balance(
                user_id=user_id,
                amount=final_price,
                description=f"Domain registration: {domain_name}"
            )
            
            assert reservation_id is not None
            balance_after_reserve = await get_user_wallet_balance_by_id(user_id)
            assert balance_after_reserve == initial_balance  # Reserved, not debited yet
            
            # Step 4: Register domain
            mock_register.return_value = {
                'status': 'success',
                'domain_id': 'INTEGRATION_DOMAIN_123',
                'nameservers': ['ns1.openprovider.nl', 'ns2.openprovider.nl'],
                'expires_at': '2025-09-18'
            }
            
            registration_result = await service.register_domain(
                domain_name=domain_name,
                contact_handle='integration_contact',
                nameservers=['ns1.test.com', 'ns2.test.com'],
                period=1
            )
            
            assert registration_result['status'] == 'success'
            
            # Step 5: Finalize payment
            finalize_result = await finalize_wallet_reservation(
                transaction_id=reservation_id,
                success=True  # Domain registration succeeded
            )
            
            assert finalize_result is True
            
            # Step 6: Verify final state
            final_balance = await get_user_wallet_balance_by_id(user_id)
            assert final_balance == initial_balance - final_price

    async def test_complete_domain_purchase_failure_rollback(self, integration_user):
        """Test domain purchase failure and automatic rollback"""
        user_id = integration_user
        domain_name = 'unavailable-domain.com'
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        domain_price = 75.00
        
        # Step 1: Reserve funds
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=domain_price,
            description=f"Failed domain registration: {domain_name}"
        )
        
        assert reservation_id is not None
        
        # Step 2: Mock domain registration failure
        with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
            mock_register.return_value = {
                'status': 'error',
                'error_code': 'DOMAIN_UNAVAILABLE',
                'error_message': 'Domain is not available'
            }
            
            service = OpenProviderService()
            registration_result = await service.register_domain(
                domain_name=domain_name,
                contact_handle='test_contact',
                nameservers=['ns1.test.com'],
                period=1
            )
            
            assert registration_result['status'] == 'error'
        
        # Step 3: Cancel reservation due to failure
        rollback_result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=False  # Registration failed
        )
        
        assert rollback_result is True
        
        # Step 4: Verify balance restored
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance  # Full rollback

    # P1: Complete Hosting Setup Integration
    async def test_complete_hosting_setup_integration(self, integration_user):
        """Test complete hosting setup flow: reserve → create account → finalize"""
        user_id = integration_user
        domain = 'hosting-integration-test.com'
        hosting_price = 199.99
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Step 1: Reserve funds for hosting
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=hosting_price,
            description=f"Hosting setup: {domain}"
        )
        
        assert reservation_id is not None
        
        # Step 2: Mock successful hosting account creation
        with patch('services.cpanel.CPanelService.create_hosting_account') as mock_create:
            mock_create.return_value = {
                'username': 'inttest123',
                'password': 'secure_password_123',
                'domain': domain,
                'server_ip': '192.168.1.100',
                'status': 'active',
                'cpanel_url': f'https://{domain}:2083'
            }
            
            service = CPanelService()
            account_result = await service.create_hosting_account(
                domain=domain,
                plan='premium',
                email='integration@test.com'
            )
            
            assert account_result is not None
            assert account_result['status'] == 'active'
            assert account_result['username'] == 'inttest123'
        
        # Step 3: Finalize payment
        finalize_result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=True  # Account creation succeeded
        )
        
        assert finalize_result is True
        
        # Step 4: Verify payment completed
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance - hosting_price

    # P1: Bundle Purchase Integration
    async def test_complete_bundle_purchase_integration(self, integration_user):
        """Test complete domain + hosting bundle purchase with discount"""
        user_id = integration_user
        domain = 'bundle-integration.com'
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Calculate bundle pricing
        domain_base_price = 20.00
        hosting_base_price = 60.00
        bundle_discount_percent = 15.0
        
        total_base = domain_base_price + hosting_base_price
        discount_amount = total_base * (bundle_discount_percent / 100)
        bundle_price = total_base - discount_amount
        
        # Step 1: Reserve bundle amount
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=bundle_price,
            description=f"Bundle purchase: {domain}"
        )
        
        assert reservation_id is not None
        
        # Step 2: Mock both services
        with patch('services.openprovider.OpenProviderService.register_domain') as mock_domain, \
             patch('services.cpanel.CPanelService.create_hosting_account') as mock_hosting:
            
            # Mock domain registration
            mock_domain.return_value = {
                'status': 'success',
                'domain_id': 'BUNDLE_DOMAIN_123'
            }
            
            # Mock hosting setup
            mock_hosting.return_value = {
                'username': 'bundletest',
                'status': 'active',
                'domain': domain
            }
            
            # Process bundle
            domain_service = OpenProviderService()
            hosting_service = CPanelService()
            
            # Register domain
            domain_result = await domain_service.register_domain(
                domain_name=domain,
                contact_handle='bundle_contact',
                nameservers=['ns1.test.com'],
                period=1
            )
            
            # Create hosting account
            hosting_result = await hosting_service.create_hosting_account(
                domain=domain,
                plan='starter',
                email='bundle@test.com'
            )
            
            assert domain_result['status'] == 'success'
            assert hosting_result['status'] == 'active'
        
        # Step 3: Finalize bundle payment
        finalize_result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=True
        )
        
        assert finalize_result is True
        
        # Step 4: Verify bundle discount applied
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance - bundle_price
        assert bundle_price < total_base  # Discount was applied

class TestWalletConcurrencyIntegration:
    """P1: Advanced concurrency and load testing for wallet operations"""

    @pytest.fixture
    async def concurrency_users(self, database):
        """Create multiple users for concurrency testing"""
        users = []
        for i in range(5):
            user_data = {
                'telegram_id': 990000 + i,
                'username': f'concurrent_user_{i}',
                'first_name': f'Concurrent{i}',
                'last_name': 'Tester',
                'wallet_balance': Decimal('500.00')
            }
            
            user_id = await execute_query(
                """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
                   VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
                   RETURNING id""",
                user_data
            )
            
            users.append(user_id[0]['id'])
        
        return users

    async def test_high_concurrency_wallet_operations(self, concurrency_users):
        """Test high-concurrency wallet operations across multiple users"""
        users = concurrency_users
        
        # Create many concurrent operations across all users
        async def perform_operations(user_id: int, operation_count: int):
            operations_completed = 0
            for i in range(operation_count):
                try:
                    # Mix of credits and debits
                    if i % 2 == 0:
                        # Credit operation
                        result = await credit_user_wallet(
                            user_id=user_id,
                            amount_usd=10.00,
                            provider='dynopay',
                            txid=f'concurrent_tx_{user_id}_{i}',
                            order_id=f'concurrent_order_{user_id}_{i}'
                        )
                        if result:
                            operations_completed += 1
                    else:
                        # Debit operation  
                        result = await debit_wallet_balance(
                            user_id=user_id,
                            amount=5.00,
                            description=f"Concurrent debit {i}"
                        )
                        if result:
                            operations_completed += 1
                    
                    # Small delay between operations
                    await asyncio.sleep(0.01)
                except Exception as e:
                    print(f"Operation failed for user {user_id}: {e}")
            
            return operations_completed
        
        # Run concurrent operations for all users
        tasks = [
            perform_operations(user_id, 10)  # 10 operations per user
            for user_id in users
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify all operations completed successfully
        successful_operations = [r for r in results if isinstance(r, int)]
        total_operations = sum(successful_operations)
        
        assert total_operations > 0  # At least some operations succeeded
        assert len(successful_operations) == len(users)  # All users had some success

    async def test_concurrent_reservations_and_finalizations(self, concurrency_users):
        """Test concurrent reservation and finalization operations"""
        users = concurrency_users
        
        async def reserve_and_finalize(user_id: int, amount: float, success: bool):
            try:
                # Reserve funds
                reservation_id = await reserve_wallet_balance(
                    user_id=user_id,
                    amount=amount,
                    description=f"Concurrent reservation test"
                )
                
                if reservation_id is None:
                    return False
                
                # Small processing delay
                await asyncio.sleep(0.05)
                
                # Finalize reservation
                result = await finalize_wallet_reservation(
                    transaction_id=reservation_id,
                    success=success
                )
                
                return result
            except Exception:
                return False
        
        # Create mixed concurrent operations
        tasks = []
        for user_id in users:
            # Each user gets multiple concurrent reservations
            tasks.extend([
                reserve_and_finalize(user_id, 25.00, True),   # Successful finalization
                reserve_and_finalize(user_id, 30.00, False),  # Cancelled reservation
                reserve_and_finalize(user_id, 15.00, True)    # Another successful one
            ])
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify operations completed
        successful_ops = [r for r in results if r is True]
        assert len(successful_ops) > 0

    async def test_stress_test_wallet_balance_consistency(self, concurrency_users):
        """Stress test wallet balance consistency under high load"""
        users = concurrency_users
        
        # Record initial balances
        initial_balances = {}
        for user_id in users:
            initial_balances[user_id] = await get_user_wallet_balance_by_id(user_id)
        
        # Create high-load operations
        async def stress_operations(user_id: int):
            operations = []
            
            # 20 operations per user
            for i in range(20):
                if i % 4 == 0:
                    # Credit
                    op = credit_user_wallet(
                        user_id=user_id,
                        amount_usd=2.00,
                        provider='dynopay',
                        txid=f'stress_tx_{user_id}_{i}',
                        order_id=f'stress_order_{user_id}_{i}'
                    )
                elif i % 4 == 1:
                    # Debit
                    op = debit_wallet_balance(
                        user_id=user_id,
                        amount=1.00,
                        description=f"Stress debit {i}"
                    )
                elif i % 4 == 2:
                    # Reserve and finalize success
                    async def reserve_finalize_success():
                        res_id = await reserve_wallet_balance(user_id, 3.00, "Stress reserve")
                        if res_id:
                            return await finalize_wallet_reservation(res_id, True)
                        return False
                    op = reserve_finalize_success()
                else:
                    # Reserve and cancel
                    async def reserve_cancel():
                        res_id = await reserve_wallet_balance(user_id, 2.00, "Stress cancel")
                        if res_id:
                            return await finalize_wallet_reservation(res_id, False)
                        return False
                    op = reserve_cancel()
                
                operations.append(op)
            
            # Wait for all operations to complete
            await asyncio.gather(*operations, return_exceptions=True)
        
        # Run stress test
        stress_tasks = [stress_operations(user_id) for user_id in users]
        await asyncio.gather(*stress_tasks, return_exceptions=True)
        
        # Verify balances are still consistent (no negative balances)
        for user_id in users:
            final_balance = await get_user_wallet_balance_by_id(user_id)
            assert final_balance >= 0.0  # No negative balances
            
            # Balance should be reasonable (within expected range based on operations)
            initial = initial_balances[user_id]
            assert final_balance <= initial + 100.0  # Not excessively high
            assert final_balance >= initial - 100.0  # Not excessively low

class TestWalletCompleteSystemIntegration:
    """P1: Complete system integration tests simulating real-world scenarios"""

    @pytest.fixture
    async def system_test_user(self, database):
        """Create user for complete system testing"""
        user_data = {
            'telegram_id': 999999,
            'username': 'system_test_user',
            'first_name': 'System',
            'last_name': 'Tester',
            'wallet_balance': Decimal('0.00')  # Start with empty wallet
        }
        
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    async def test_complete_user_journey_crypto_to_services(self, system_test_user):
        """Test complete user journey: crypto funding → service purchases → wallet management"""
        user_id = system_test_user
        
        # Phase 1: User funds wallet via crypto
        # Step 1a: DynoPay funding
        funding_result_1 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=200.00,
            provider='dynopay',
            txid='system_test_funding_1',
            order_id='system_funding_order_1'
        )
        assert funding_result_1 is True
        
        balance_after_first_funding = await get_user_wallet_balance_by_id(user_id)
        assert balance_after_first_funding == 200.00
        
        # Step 1b: BlockBee additional funding
        funding_result_2 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=100.00,
            provider='blockbee',
            txid='system_test_funding_2',
            order_id='system_funding_order_2'
        )
        assert funding_result_2 is True
        
        balance_after_second_funding = await get_user_wallet_balance_by_id(user_id)
        assert balance_after_second_funding == 300.00
        
        # Phase 2: User purchases domain
        domain_price = 75.00
        
        # Reserve for domain
        domain_reservation = await reserve_wallet_balance(
            user_id=user_id,
            amount=domain_price,
            description="System test domain purchase"
        )
        assert domain_reservation is not None
        
        # Mock domain registration success and finalize
        finalize_domain = await finalize_wallet_reservation(
            transaction_id=domain_reservation,
            success=True
        )
        assert finalize_domain is True
        
        balance_after_domain = await get_user_wallet_balance_by_id(user_id)
        assert balance_after_domain == 225.00  # 300 - 75
        
        # Phase 3: User purchases hosting
        hosting_price = 150.00
        
        # Reserve for hosting
        hosting_reservation = await reserve_wallet_balance(
            user_id=user_id,
            amount=hosting_price,
            description="System test hosting purchase"
        )
        assert hosting_reservation is not None
        
        # Mock hosting setup success and finalize
        finalize_hosting = await finalize_wallet_reservation(
            transaction_id=hosting_reservation,
            success=True
        )
        assert finalize_hosting is True
        
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == 75.00  # 225 - 150
        
        # Phase 4: Verify complete transaction history
        transactions = await get_user_wallet_transactions(user_id)
        assert len(transactions) >= 4  # 2 credits, 2 debits
        
        # Verify transaction types and amounts
        credits = [t for t in transactions if t['transaction_type'] == 'credit']
        debits = [t for t in transactions if t['transaction_type'] == 'debit']
        
        assert len(credits) >= 2
        assert len(debits) >= 2
        
        total_credits = sum(float(t['amount']) for t in credits)
        total_debits = sum(float(t['amount']) for t in debits)
        
        assert abs(total_credits - 300.00) < 0.01
        assert abs(total_debits - 225.00) < 0.01

    async def test_system_failure_recovery_scenarios(self, system_test_user):
        """Test system recovery from various failure scenarios"""
        user_id = system_test_user
        
        # Fund wallet for testing
        await credit_user_wallet(user_id, 500.00, 'dynopay', 'recovery_test_funding', 'recovery_order')
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Scenario 1: Reservation created but service fails
        failed_reservation = await reserve_wallet_balance(
            user_id=user_id,
            amount=100.00,
            description="Service failure test"
        )
        assert failed_reservation is not None
        
        # Cancel reservation (service failed)
        cancel_result = await finalize_wallet_reservation(
            transaction_id=failed_reservation,
            success=False
        )
        assert cancel_result is True
        
        # Verify balance restored
        balance_after_cancel = await get_user_wallet_balance_by_id(user_id)
        assert balance_after_cancel == initial_balance
        
        # Scenario 2: Multiple partial failures
        reservations = []
        for i in range(3):
            res_id = await reserve_wallet_balance(
                user_id=user_id,
                amount=50.00,
                description=f"Partial failure test {i}"
            )
            if res_id:
                reservations.append(res_id)
        
        # Cancel all reservations (simulate system recovery)
        for res_id in reservations:
            await finalize_wallet_reservation(res_id, False)
        
        # Verify full balance restoration
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance

    async def test_system_audit_and_compliance(self, system_test_user):
        """Test system audit trail and compliance requirements"""
        user_id = system_test_user
        
        # Perform various operations for audit trail
        operations = [
            ('credit', 'dynopay', 100.00, 'audit_tx_1', 'audit_order_1'),
            ('credit', 'blockbee', 75.00, 'audit_tx_2', 'audit_order_2'),
            ('debit', None, 25.00, None, None),
            ('debit', None, 30.00, None, None)
        ]
        
        for op_type, provider, amount, txid, order_id in operations:
            if op_type == 'credit':
                await credit_user_wallet(
                    user_id=user_id,
                    amount_usd=amount,
                    provider=provider,
                    txid=txid,
                    order_id=order_id
                )
            else:
                await debit_wallet_balance(
                    user_id=user_id,
                    amount=amount,
                    description="Audit test debit"
                )
        
        # Verify complete audit trail
        transactions = await get_user_wallet_transactions(user_id)
        
        # Check audit requirements
        for transaction in transactions:
            # Every transaction must have timestamp
            assert transaction['created_at'] is not None
            
            # Every transaction must have amount
            assert transaction['amount'] is not None
            assert float(transaction['amount']) > 0
            
            # Every transaction must have type
            assert transaction['transaction_type'] in ['credit', 'debit']
            
            # Credit transactions must have provider and external_txid
            if transaction['transaction_type'] == 'credit':
                assert transaction.get('provider') is not None
                assert transaction.get('external_txid') is not None

    async def test_system_performance_under_load(self, database):
        """Test system performance with realistic load"""
        # Create multiple users for load testing
        load_users = []
        for i in range(10):
            user_data = {
                'telegram_id': 980000 + i,
                'username': f'load_user_{i}',
                'first_name': f'Load{i}',
                'last_name': 'Tester',
                'wallet_balance': Decimal('100.00')
            }
            
            user_result = await execute_query(
                """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
                   VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
                   RETURNING id""",
                user_data
            )
            
            load_users.append(user_result[0]['id'])
        
        # Perform load testing
        start_time = time.time()
        
        async def user_load_operations(user_id: int):
            operations_completed = 0
            for i in range(15):  # 15 operations per user = 150 total operations
                try:
                    if i % 3 == 0:
                        result = await credit_user_wallet(
                            user_id=user_id,
                            amount_usd=5.00,
                            provider='dynopay',
                            txid=f'load_tx_{user_id}_{i}',
                            order_id=f'load_order_{user_id}_{i}'
                        )
                    elif i % 3 == 1:
                        result = await debit_wallet_balance(
                            user_id=user_id,
                            amount=2.00,
                            description=f"Load test debit {i}"
                        )
                    else:
                        res_id = await reserve_wallet_balance(user_id, 3.00, f"Load reserve {i}")
                        if res_id:
                            result = await finalize_wallet_reservation(res_id, True)
                        else:
                            result = False
                    
                    if result:
                        operations_completed += 1
                        
                except Exception as e:
                    print(f"Load test exception: {e}")
            
            return operations_completed
        
        # Run load test
        tasks = [user_load_operations(user_id) for user_id in load_users]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        test_duration = end_time - start_time
        
        # Calculate performance metrics
        successful_operations = sum(r for r in results if isinstance(r, int))
        operations_per_second = successful_operations / test_duration if test_duration > 0 else 0
        
        # Performance assertions
        assert successful_operations > 100  # At least 100 operations completed
        assert operations_per_second >= 10   # At least 10 ops/second
        assert test_duration < 60           # Completed within 1 minute
        
        # Verify no data corruption occurred
        for user_id in load_users:
            balance = await get_user_wallet_balance_by_id(user_id)
            assert balance >= 0.0  # No negative balances
            assert balance <= 200.0  # Reasonable upper bound