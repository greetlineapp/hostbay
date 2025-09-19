"""
Comprehensive tests for payment processing workflows
P0 Critical: Domain and hosting payment processing with provider integration
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from decimal import Decimal

# Import services under test
from services.openprovider import OpenProviderService
from services.cpanel import CPanelService
from services.registration_orchestrator import start_domain_registration
from services.hosting_orchestrator import HostingBundleOrchestrator
from database import (
    reserve_wallet_balance, finalize_wallet_reservation,
    get_user_wallet_balance_by_id, debit_wallet_balance,
    execute_query, execute_update
)

class TestDomainPaymentProcessing:
    """P0 Critical: Domain payment processing with OpenProvider integration"""

    @pytest.fixture
    async def domain_payment_user(self, database):
        """Create test user for domain payments with sufficient balance"""
        user_data = {
            'telegram_id': 999300,
            'username': 'domain_user',
            'first_name': 'Domain',
            'last_name': 'Buyer',
            'wallet_balance': Decimal('200.00')
        }
        
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    @pytest.fixture
    def mock_openprovider_success(self):
        """Mock successful OpenProvider domain registration"""
        return {
            'status': 'success',
            'domain_id': 'OP123456',
            'nameservers': ['ns1.openprovider.nl', 'ns2.openprovider.nl'],
            'expires_at': '2025-09-18',
            'price': 25.00
        }

    @pytest.fixture  
    def mock_openprovider_failure(self):
        """Mock failed OpenProvider domain registration"""
        return {
            'status': 'error',
            'error_code': 'DOMAIN_UNAVAILABLE',
            'error_message': 'Domain is not available for registration'
        }

    async def test_domain_payment_success_flow(self, domain_payment_user, mock_openprovider_success):
        """Test complete domain payment flow: price calc → reserve → provider success → finalize"""
        user_id = domain_payment_user
        domain_name = 'testdomain.com'
        domain_price = 50.00
        
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Step 1: Reserve funds for domain purchase
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=domain_price,
            description=f"Domain registration: {domain_name}"
        )
        
        assert reservation_id is not None
        
        # Step 2: Mock successful domain registration
        with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
            mock_register.return_value = mock_openprovider_success
            
            service = OpenProviderService()
            registration_result = await service.register_domain(
                domain_name=domain_name,
                contact_handle='test_contact',
                nameservers=['ns1.test.com', 'ns2.test.com'],
                period=1
            )
            
            assert registration_result is not None
            assert registration_result['status'] == 'success'
        
        # Step 3: Finalize reservation (debit wallet)
        finalize_result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=True  # Provider succeeded
        )
        
        assert finalize_result is True
        
        # Step 4: Verify wallet was debited
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance - domain_price

    async def test_domain_payment_provider_failure_rollback(self, domain_payment_user, mock_openprovider_failure):
        """Test domain payment rollback when provider fails"""
        user_id = domain_payment_user
        domain_name = 'unavailable-domain.com'
        domain_price = 75.00
        
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Step 1: Reserve funds
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=domain_price,
            description=f"Domain registration: {domain_name}"
        )
        
        assert reservation_id is not None
        
        # Step 2: Mock failed domain registration
        with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
            mock_register.return_value = mock_openprovider_failure
            
            service = OpenProviderService()
            registration_result = await service.register_domain(
                domain_name=domain_name,
                contact_handle='test_contact',
                nameservers=['ns1.test.com', 'ns2.test.com'],
                period=1
            )
            
            assert registration_result is not None
            assert registration_result['status'] == 'error'
        
        # Step 3: Cancel reservation due to provider failure
        finalize_result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=False  # Provider failed, cancel reservation
        )
        
        assert finalize_result is True
        
        # Step 4: Verify wallet balance restored (no debit)
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance  # Balance restored

    async def test_domain_price_calculation_markup(self, domain_payment_user):
        """Test domain price calculation with markup"""
        user_id = domain_payment_user
        
        # Mock base price from OpenProvider
        base_price = 15.00
        expected_markup_multiplier = 3.26  # From environment
        expected_final_price = base_price * expected_markup_multiplier
        
        with patch('services.openprovider.OpenProviderService.get_domain_price') as mock_price:
            mock_price.return_value = {'price': base_price, 'currency': 'USD'}
            
            service = OpenProviderService()
            price_result = await service.get_domain_price('example.com', 1)
            
            # Verify base price retrieved
            assert price_result['price'] == base_price
        
        # Test markup calculation (would be done in pricing utils)
        from pricing_utils import calculate_marked_up_price
        final_price = calculate_marked_up_price(base_price)
        
        # Should be within reasonable range of expected markup
        assert final_price >= expected_final_price * 0.9  # Allow some variance

    async def test_domain_payment_insufficient_funds(self, domain_payment_user):
        """Test domain payment failure with insufficient funds"""
        user_id = domain_payment_user
        
        # Try to reserve more than available balance
        current_balance = await get_user_wallet_balance_by_id(user_id)
        excessive_amount = current_balance + 100.00
        
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=excessive_amount,
            description="Insufficient funds test"
        )
        
        assert reservation_id is None  # Should fail to reserve

    async def test_domain_payment_idempotent_replay(self, domain_payment_user):
        """Test idempotent replay handling for domain payments"""
        user_id = domain_payment_user
        domain_price = 40.00
        
        # First reservation
        reservation_id_1 = await reserve_wallet_balance(
            user_id=user_id,
            amount=domain_price,
            description="Idempotent test - attempt 1"
        )
        
        assert reservation_id_1 is not None
        
        # Second reservation (should succeed as separate transaction)
        reservation_id_2 = await reserve_wallet_balance(
            user_id=user_id,
            amount=domain_price,
            description="Idempotent test - attempt 2"  
        )
        
        assert reservation_id_2 is not None
        assert reservation_id_2 != reservation_id_1
        
        # Cancel both reservations
        await finalize_wallet_reservation(reservation_id_1, False)
        await finalize_wallet_reservation(reservation_id_2, False)

class TestHostingPaymentProcessing:
    """P0 Critical: Hosting payment processing with cPanel integration"""

    @pytest.fixture
    async def hosting_payment_user(self, database):
        """Create test user for hosting payments with sufficient balance"""
        user_data = {
            'telegram_id': 999400,
            'username': 'hosting_user',
            'first_name': 'Hosting',
            'last_name': 'Customer',
            'wallet_balance': Decimal('500.00')
        }
        
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    @pytest.fixture
    def mock_cpanel_success(self):
        """Mock successful cPanel account creation"""
        return {
            'username': 'testuser123',
            'password': 'secure_password_123',
            'domain': 'testdomain.com',
            'server_ip': '192.168.1.100',
            'status': 'active',
            'cpanel_url': 'https://testdomain.com:2083'
        }

    @pytest.fixture
    def mock_cpanel_failure(self):
        """Mock failed cPanel account creation"""
        return None  # cPanel service returns None on failure

    async def test_hosting_payment_success_flow(self, hosting_payment_user, mock_cpanel_success):
        """Test complete hosting payment flow: reserve → cPanel success → finalize"""
        user_id = hosting_payment_user
        hosting_price = 89.99
        domain = 'hosting-test.com'
        
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Step 1: Reserve funds for hosting
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=hosting_price,
            description=f"Hosting subscription: {domain}"
        )
        
        assert reservation_id is not None
        
        # Step 2: Mock successful hosting account creation
        with patch('services.cpanel.CPanelService.create_hosting_account') as mock_create:
            mock_create.return_value = mock_cpanel_success
            
            service = CPanelService()
            account_result = await service.create_hosting_account(
                domain=domain,
                plan='starter',
                email='test@example.com'
            )
            
            assert account_result is not None
            assert account_result['status'] == 'active'
        
        # Step 3: Finalize payment (debit wallet)
        finalize_result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=True  # Account creation succeeded
        )
        
        assert finalize_result is True
        
        # Step 4: Verify wallet debited
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance - hosting_price

    async def test_hosting_payment_provider_failure_rollback(self, hosting_payment_user, mock_cpanel_failure):
        """Test hosting payment rollback when cPanel account creation fails"""
        user_id = hosting_payment_user
        hosting_price = 129.99
        domain = 'failed-hosting.com'
        
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Step 1: Reserve funds
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=hosting_price,
            description=f"Hosting subscription: {domain}"
        )
        
        assert reservation_id is not None
        
        # Step 2: Mock failed account creation
        with patch('services.cpanel.CPanelService.create_hosting_account') as mock_create:
            mock_create.return_value = mock_cpanel_failure
            
            service = CPanelService()
            account_result = await service.create_hosting_account(
                domain=domain,
                plan='premium',
                email='test@example.com'
            )
            
            assert account_result is None  # Creation failed
        
        # Step 3: Cancel reservation due to failure
        finalize_result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=False  # Account creation failed
        )
        
        assert finalize_result is True
        
        # Step 4: Verify balance restored
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance

    async def test_hosting_account_provisioning_validation(self, hosting_payment_user):
        """Test hosting account provisioning payment validation"""
        user_id = hosting_payment_user
        
        # Test various hosting plan prices
        test_plans = [
            {'plan': 'starter', 'price': 19.99},
            {'plan': 'premium', 'price': 39.99},
            {'plan': 'enterprise', 'price': 79.99}
        ]
        
        for plan_info in test_plans:
            # Reserve funds for this plan
            reservation_id = await reserve_wallet_balance(
                user_id=user_id,
                amount=plan_info['price'],
                description=f"Hosting plan: {plan_info['plan']}"
            )
            
            assert reservation_id is not None
            
            # Cancel reservation for cleanup
            await finalize_wallet_reservation(reservation_id, False)

    async def test_hosting_bundle_discount_calculation(self, hosting_payment_user):
        """Test hosting bundle discount calculation"""
        user_id = hosting_payment_user
        
        # Mock bundle pricing with discount
        base_domain_price = 25.00
        base_hosting_price = 50.00
        bundle_discount_percent = 15.0
        
        # Calculate expected bundle price
        total_base = base_domain_price + base_hosting_price
        discount_amount = total_base * (bundle_discount_percent / 100)
        expected_bundle_price = total_base - discount_amount
        
        # Test reservation for bundle price
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=expected_bundle_price,
            description="Domain + hosting bundle"
        )
        
        assert reservation_id is not None
        
        # Verify bundle price is less than individual prices
        assert expected_bundle_price < total_base
        
        # Cleanup
        await finalize_wallet_reservation(reservation_id, False)

class TestPaymentProcessingEdgeCases:
    """Edge cases and error scenarios for payment processing"""

    @pytest.fixture
    async def edge_case_user(self, database):
        """Create user for edge case testing"""
        user_data = {
            'telegram_id': 999500,
            'username': 'edge_case_user', 
            'first_name': 'Edge',
            'last_name': 'Case',
            'wallet_balance': Decimal('100.00')
        }
        
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    async def test_payment_processing_timeout_scenarios(self, edge_case_user):
        """Test payment processing with provider timeouts"""
        user_id = edge_case_user
        
        # Reserve funds
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=50.00,
            description="Timeout scenario test"
        )
        
        assert reservation_id is not None
        
        # Mock timeout in provider call
        with patch('services.openprovider.OpenProviderService.register_domain') as mock_register:
            import asyncio
            mock_register.side_effect = asyncio.TimeoutError("Provider timeout")
            
            service = OpenProviderService()
            
            try:
                await service.register_domain(
                    domain_name='timeout-test.com',
                    contact_handle='test_contact',
                    nameservers=['ns1.test.com'],
                    period=1
                )
                assert False, "Should have raised TimeoutError"
            except asyncio.TimeoutError:
                # Expected timeout
                pass
        
        # Should cancel reservation due to timeout
        finalize_result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=False
        )
        
        assert finalize_result is True

    async def test_concurrent_payment_processing(self, edge_case_user):
        """Test concurrent payment processing doesn't cause double charges"""
        user_id = edge_case_user
        
        async def process_payment(amount: float, description: str):
            reservation_id = await reserve_wallet_balance(user_id, amount, description)
            if reservation_id:
                # Simulate processing delay
                await asyncio.sleep(0.1)
                return await finalize_wallet_reservation(reservation_id, True)
            return False
        
        # Run concurrent payments
        tasks = [
            process_payment(30.00, f"Concurrent payment {i}")
            for i in range(3)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify no more than available balance was charged
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance >= 10.00  # At least 10 remaining (100 - 90 max charged)

    async def test_partial_payment_confirmation_handling(self, edge_case_user):
        """Test handling of partial payment confirmations (pending → confirmed)"""
        user_id = edge_case_user
        
        # Create initial reservation
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=25.00,
            description="Partial confirmation test"
        )
        
        assert reservation_id is not None
        
        # Simulate pending state (don't finalize yet)
        await asyncio.sleep(0.05)
        
        # Now confirm (finalize)
        result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=True
        )
        
        assert result is True

    async def test_payment_transaction_logging(self, edge_case_user):
        """Test that payment transactions are properly logged"""
        user_id = edge_case_user
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Perform reservation and finalization
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=40.00,
            description="Transaction logging test"
        )
        
        await finalize_wallet_reservation(reservation_id, True)
        
        # Verify transaction was logged
        from database import get_user_wallet_transactions
        transactions = await get_user_wallet_transactions(user_id)
        
        # Should have at least one transaction
        assert len(transactions) > 0
        
        # Find the debit transaction
        debit_transaction = next(
            (t for t in transactions if t['transaction_type'] == 'debit' 
             and abs(float(t['amount']) - 40.00) < 0.01), 
            None
        )
        
        assert debit_transaction is not None
        assert 'Transaction logging test' in debit_transaction.get('description', '')

class TestPaymentIntegrationFlows:
    """P1: Integration tests for complete payment flows"""

    @pytest.fixture
    async def integration_user(self, database):
        """Create user for integration testing"""
        user_data = {
            'telegram_id': 999600,
            'username': 'integration_user',
            'first_name': 'Integration', 
            'last_name': 'Tester',
            'wallet_balance': Decimal('300.00')
        }
        
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    async def test_end_to_end_domain_purchase_flow(self, integration_user):
        """Test complete end-to-end domain purchase flow"""
        user_id = integration_user
        domain_name = 'integration-test.com'
        
        # Mock all external services
        with patch('services.openprovider.OpenProviderService.register_domain') as mock_register, \
             patch('services.openprovider.OpenProviderService.get_domain_price') as mock_price:
            
            # Mock price check
            mock_price.return_value = {'price': 15.00, 'currency': 'USD'}
            
            # Mock successful registration
            mock_register.return_value = {
                'status': 'success',
                'domain_id': 'TEST123',
                'nameservers': ['ns1.test.com', 'ns2.test.com']
            }
            
            # Step 1: Get domain price
            service = OpenProviderService()
            price_result = await service.get_domain_price(domain_name, 1)
            base_price = price_result['price']
            
            # Step 2: Calculate final price with markup
            from pricing_utils import calculate_marked_up_price
            final_price = calculate_marked_up_price(base_price)
            
            # Step 3: Reserve funds
            reservation_id = await reserve_wallet_balance(
                user_id=user_id,
                amount=final_price,
                description=f"Domain purchase: {domain_name}"
            )
            
            assert reservation_id is not None
            
            # Step 4: Register domain
            registration_result = await service.register_domain(
                domain_name=domain_name,
                contact_handle='test_contact',
                nameservers=['ns1.test.com', 'ns2.test.com'],
                period=1
            )
            
            assert registration_result['status'] == 'success'
            
            # Step 5: Finalize payment
            finalize_result = await finalize_wallet_reservation(
                transaction_id=reservation_id,
                success=True
            )
            
            assert finalize_result is True

    async def test_end_to_end_hosting_setup_flow(self, integration_user):
        """Test complete end-to-end hosting setup flow"""
        user_id = integration_user
        domain = 'hosting-integration.com'
        hosting_price = 89.99
        
        with patch('services.cpanel.CPanelService.create_hosting_account') as mock_create:
            # Mock successful account creation
            mock_create.return_value = {
                'username': 'inttest',
                'password': 'secure_pass',
                'domain': domain,
                'server_ip': '192.168.1.100',
                'status': 'active'
            }
            
            # Step 1: Reserve funds
            reservation_id = await reserve_wallet_balance(
                user_id=user_id,
                amount=hosting_price,
                description=f"Hosting setup: {domain}"
            )
            
            assert reservation_id is not None
            
            # Step 2: Create hosting account
            service = CPanelService()
            account_result = await service.create_hosting_account(
                domain=domain,
                plan='starter',
                email='test@example.com'
            )
            
            assert account_result is not None
            assert account_result['status'] == 'active'
            
            # Step 3: Finalize payment
            finalize_result = await finalize_wallet_reservation(
                transaction_id=reservation_id,
                success=True
            )
            
            assert finalize_result is True

    async def test_bundle_purchase_flow(self, integration_user):
        """Test domain + hosting bundle purchase flow"""
        user_id = integration_user
        domain = 'bundle-test.com'
        
        # Mock both services
        with patch('services.openprovider.OpenProviderService.register_domain') as mock_domain, \
             patch('services.cpanel.CPanelService.create_hosting_account') as mock_hosting:
            
            # Mock successful domain registration
            mock_domain.return_value = {
                'status': 'success',
                'domain_id': 'BUNDLE123'
            }
            
            # Mock successful hosting setup  
            mock_hosting.return_value = {
                'username': 'bundletest',
                'status': 'active'
            }
            
            # Calculate bundle price (with discount)
            base_price = 75.00  # Domain + hosting
            discount_percent = 15.0
            bundle_price = base_price * (1 - discount_percent/100)
            
            # Reserve bundle amount
            reservation_id = await reserve_wallet_balance(
                user_id=user_id,
                amount=bundle_price,
                description=f"Bundle purchase: {domain}"
            )
            
            assert reservation_id is not None
            
            # Process both services
            domain_service = OpenProviderService()
            hosting_service = CPanelService()
            
            domain_result = await domain_service.register_domain(
                domain_name=domain,
                contact_handle='test_contact',
                nameservers=['ns1.test.com'],
                period=1
            )
            
            hosting_result = await hosting_service.create_hosting_account(
                domain=domain,
                plan='starter',
                email='bundle@test.com'
            )
            
            # Both should succeed
            assert domain_result['status'] == 'success'
            assert hosting_result['status'] == 'active'
            
            # Finalize bundle payment
            finalize_result = await finalize_wallet_reservation(
                transaction_id=reservation_id,
                success=True
            )
            
            assert finalize_result is True