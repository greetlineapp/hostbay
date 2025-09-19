"""
Comprehensive unit tests for wallet operations
P0 Critical: Wallet balance operations with atomicity and negative balance prevention
"""

import pytest
import asyncio
import logging
import threading
import time
from decimal import Decimal
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import AsyncMock, MagicMock, patch
import psycopg2
from psycopg2.extras import RealDictCursor

# Import functions under test
from database import (
    credit_user_wallet, debit_wallet_balance, reserve_wallet_balance,
    finalize_wallet_reservation, get_user_wallet_balance_by_id,
    get_user_wallet_transactions, get_connection, return_connection,
    init_database, get_or_create_user, execute_query, execute_update
)

logger = logging.getLogger(__name__)

class TestWalletOperations:
    """P0 Critical Tests: Core wallet operations with atomicity and safety"""

    @pytest.fixture
    async def test_user_with_balance(self, database):
        """Create a test user with initial balance"""
        user_data = {
            'telegram_id': 999001,
            'username': 'wallet_test_user',
            'first_name': 'Wallet',
            'last_name': 'Tester',
            'wallet_balance': Decimal('100.00')
        }
        
        # Create user with wallet balance
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    @pytest.fixture
    async def zero_balance_user(self, database):
        """Create a test user with zero balance"""
        user_data = {
            'telegram_id': 999002,
            'username': 'zero_balance_user',
            'first_name': 'Zero',
            'last_name': 'Balance',
            'wallet_balance': Decimal('0.00')
        }
        
        user_id = await execute_query(
            """INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance) 
               VALUES (%(telegram_id)s, %(username)s, %(first_name)s, %(last_name)s, %(wallet_balance)s) 
               RETURNING id""",
            user_data
        )
        
        return user_id[0]['id'] if user_id else None

    # P0 CRITICAL: Credit Wallet Operations
    async def test_credit_user_wallet_success(self, test_user_with_balance):
        """Test successful wallet credit with idempotency"""
        user_id = test_user_with_balance
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Test successful credit
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=25.00,
            provider='dynopay',
            txid='test_tx_001',
            order_id='order_001'
        )
        
        assert result is True
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance + 25.00
        
        # Test idempotency - same credit should not add again
        duplicate_result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=25.00,
            provider='dynopay',
            txid='test_tx_001',
            order_id='order_001'
        )
        
        assert duplicate_result is True  # Returns success for duplicate
        duplicate_balance = await get_user_wallet_balance_by_id(user_id)
        assert duplicate_balance == final_balance  # Balance unchanged

    async def test_credit_user_wallet_duplicate_detection(self, test_user_with_balance):
        """Test duplicate transaction detection and rejection"""
        user_id = test_user_with_balance
        
        # First credit
        result1 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=50.00,
            provider='blockbee',
            txid='unique_tx_002',
            order_id='order_002'
        )
        assert result1 is True
        
        balance_after_first = await get_user_wallet_balance_by_id(user_id)
        
        # Duplicate with same txid and provider should be idempotent
        result2 = await credit_user_wallet(
            user_id=user_id,
            amount_usd=50.00,  # Same amount
            provider='blockbee',  # Same provider
            txid='unique_tx_002',  # Same txid
            order_id='order_002'
        )
        assert result2 is True
        
        balance_after_duplicate = await get_user_wallet_balance_by_id(user_id)
        assert balance_after_duplicate == balance_after_first  # No double credit

    async def test_credit_user_wallet_validation(self, test_user_with_balance):
        """Test input validation for credit operations"""
        user_id = test_user_with_balance
        
        # Test invalid amount (negative)
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=-10.00,
            provider='dynopay',
            txid='invalid_negative',
            order_id='order_negative'
        )
        assert result is False
        
        # Test invalid amount (zero)
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=0.00,
            provider='dynopay',
            txid='invalid_zero',
            order_id='order_zero'
        )
        assert result is False
        
        # Test invalid user ID
        result = await credit_user_wallet(
            user_id=999999,  # Non-existent user
            amount_usd=25.00,
            provider='dynopay',
            txid='invalid_user',
            order_id='order_invalid_user'
        )
        assert result is False

    # P0 CRITICAL: Debit Wallet Operations with Negative Balance Prevention
    async def test_debit_wallet_balance_success(self, test_user_with_balance):
        """Test successful wallet debit within available balance"""
        user_id = test_user_with_balance
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Debit within available balance
        result = await debit_wallet_balance(
            user_id=user_id,
            amount=30.00,
            description="Test debit"
        )
        
        assert result is True
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance - 30.00

    async def test_debit_wallet_balance_negative_prevention(self, test_user_with_balance):
        """CRITICAL: Test negative balance prevention"""
        user_id = test_user_with_balance
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Try to debit more than available balance
        result = await debit_wallet_balance(
            user_id=user_id,
            amount=initial_balance + 50.00,  # More than available
            description="Overdraft attempt"
        )
        
        assert result is False  # Should fail
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance  # Balance unchanged

    async def test_debit_wallet_balance_zero_user(self, zero_balance_user):
        """Test debit attempt on zero balance user"""
        user_id = zero_balance_user
        
        result = await debit_wallet_balance(
            user_id=user_id,
            amount=1.00,
            description="Debit from zero balance"
        )
        
        assert result is False
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == 0.00

    async def test_debit_wallet_validation(self, test_user_with_balance):
        """Test debit input validation"""
        user_id = test_user_with_balance
        
        # Test invalid amount (negative)
        result = await debit_wallet_balance(
            user_id=user_id,
            amount=-10.00,
            description="Negative debit"
        )
        assert result is False
        
        # Test invalid amount (zero)
        result = await debit_wallet_balance(
            user_id=user_id,
            amount=0.00,
            description="Zero debit"
        )
        assert result is False
        
        # Test excessive amount
        result = await debit_wallet_balance(
            user_id=user_id,
            amount=1000000.00,  # Above maximum
            description="Excessive debit"
        )
        assert result is False

    # P0 CRITICAL: Wallet Reservations with Atomicity
    async def test_reserve_wallet_balance_success(self, test_user_with_balance):
        """Test successful wallet balance reservation"""
        user_id = test_user_with_balance
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Reserve within available balance
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=40.00,
            description="Domain purchase reservation"
        )
        
        assert reservation_id is not None
        assert isinstance(reservation_id, int)
        
        # Balance should remain the same (it's reserved, not debited yet)
        balance_after_reserve = await get_user_wallet_balance_by_id(user_id)
        assert balance_after_reserve == initial_balance

    async def test_reserve_wallet_balance_insufficient_funds(self, test_user_with_balance):
        """Test reservation failure due to insufficient funds"""
        user_id = test_user_with_balance
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Try to reserve more than available balance
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=initial_balance + 100.00,
            description="Excessive reservation"
        )
        
        assert reservation_id is None  # Should fail

    async def test_finalize_wallet_reservation_success(self, test_user_with_balance):
        """Test successful finalization of wallet reservation"""
        user_id = test_user_with_balance
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Create reservation
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=25.00,
            description="Test reservation"
        )
        assert reservation_id is not None
        
        # Finalize reservation (success = True means debit)
        result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=True
        )
        
        assert result is True
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance - 25.00

    async def test_finalize_wallet_reservation_cancellation(self, test_user_with_balance):
        """Test cancellation of wallet reservation (rollback)"""
        user_id = test_user_with_balance
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Create reservation
        reservation_id = await reserve_wallet_balance(
            user_id=user_id,
            amount=30.00,
            description="Test reservation for cancellation"
        )
        assert reservation_id is not None
        
        # Cancel reservation (success = False means refund/cancel)
        result = await finalize_wallet_reservation(
            transaction_id=reservation_id,
            success=False
        )
        
        assert result is True
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance  # Balance restored

    async def test_finalize_nonexistent_reservation(self):
        """Test finalization of non-existent reservation"""
        result = await finalize_wallet_reservation(
            transaction_id=999999,  # Non-existent
            success=True
        )
        
        assert result is False

    # P0 CRITICAL: Atomicity Testing with Simulated Errors
    async def test_atomicity_reserve_to_finalize_success(self, test_user_with_balance):
        """Test complete reserve → finalize flow atomicity"""
        user_id = test_user_with_balance
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Multi-step atomic operation
        reservation_id = await reserve_wallet_balance(user_id, 45.00, "Atomic test")
        assert reservation_id is not None
        
        # Simulate some processing time
        await asyncio.sleep(0.1)
        
        # Finalize successfully
        success = await finalize_wallet_reservation(reservation_id, True)
        assert success is True
        
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance - 45.00

    @patch('database.get_connection')
    async def test_atomicity_with_connection_failure(self, mock_get_connection, test_user_with_balance):
        """Test atomicity when database connection fails during operation"""
        user_id = test_user_with_balance
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Mock connection failure during debit
        mock_get_connection.side_effect = psycopg2.OperationalError("Connection failed")
        
        result = await debit_wallet_balance(
            user_id=user_id,
            amount=20.00,
            description="Connection failure test"
        )
        
        # Should fail gracefully
        assert result is False
        
        # Verify balance unchanged (no partial debit)
        # Reset mock to allow balance check
        mock_get_connection.side_effect = None
        mock_get_connection.return_value = get_connection()
        
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance == initial_balance

    # P1: Transaction Logging and Audit Trails
    async def test_transaction_audit_trail(self, test_user_with_balance):
        """Test that all wallet operations create proper audit trail"""
        user_id = test_user_with_balance
        
        # Perform various operations
        await credit_user_wallet(user_id, 75.00, 'dynopay', 'audit_tx_001', 'audit_order_001')
        await debit_wallet_balance(user_id, 25.00, "Audit trail test debit")
        
        # Check transaction history
        transactions = await get_user_wallet_transactions(user_id)
        assert len(transactions) >= 2
        
        # Verify transaction details
        credit_transaction = next((t for t in transactions if t['transaction_type'] == 'credit'), None)
        debit_transaction = next((t for t in transactions if t['transaction_type'] == 'debit'), None)
        
        assert credit_transaction is not None
        assert debit_transaction is not None
        assert abs(float(credit_transaction['amount']) - 75.00) < 0.01
        assert abs(float(debit_transaction['amount']) - 25.00) < 0.01

class TestWalletConcurrency:
    """P1 Important: Concurrency testing for simultaneous operations"""


    async def test_concurrent_debits(self, concurrent_test_user):
        """Test simultaneous debits don't cause race conditions or negative balance"""
        user_id = concurrent_test_user
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Create multiple concurrent debit operations
        async def perform_debit(amount: float, description: str) -> bool:
            return await debit_wallet_balance(user_id, amount, description)
        
        # Run 5 concurrent debits of 50 each (250 total)
        tasks = [
            perform_debit(50.00, f"Concurrent debit {i+1}")
            for i in range(5)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful operations
        successful_debits = sum(1 for result in results if result is True)
        
        # Check final balance
        final_balance = await get_user_wallet_balance_by_id(user_id)
        expected_final_balance = initial_balance - (successful_debits * 50.00)
        
        assert final_balance == expected_final_balance
        assert final_balance >= 0  # Never negative
        assert successful_debits <= 5  # Can't exceed number of operations

    async def test_concurrent_reservations(self, concurrent_test_user):
        """Test concurrent reservations respect balance limits"""
        user_id = concurrent_test_user
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Try to reserve more than balance with concurrent operations
        async def perform_reservation(amount: float, desc: str) -> int:
            return await reserve_wallet_balance(user_id, amount, desc)
        
        # Each reservation is 300, total would be 1500 (exceeds 1000 balance)
        tasks = [
            perform_reservation(300.00, f"Concurrent reservation {i+1}")
            for i in range(5)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful reservations
        successful_reservations = sum(1 for result in results if result is not None)
        
        # Should not be able to reserve more than available balance allows
        # 1000 balance / 300 per reservation = max 3 reservations
        assert successful_reservations <= 3

    async def test_mixed_concurrent_operations(self, concurrent_test_user):
        """Test mixed concurrent operations maintain balance consistency"""
        user_id = concurrent_test_user
        initial_balance = await get_user_wallet_balance_by_id(user_id)
        
        # Mix of operations
        async def credit_operation():
            return await credit_user_wallet(user_id, 100.00, 'dynopay', f'concurrent_tx_{time.time()}', 'concurrent_order')
            
        async def debit_operation():
            return await debit_wallet_balance(user_id, 75.00, "Concurrent debit")
            
        async def reserve_operation():
            return await reserve_wallet_balance(user_id, 60.00, "Concurrent reservation")
        
        # Run mixed operations concurrently
        tasks = []
        for i in range(3):
            tasks.extend([
                credit_operation(),
                debit_operation(),
                reserve_operation()
            ])
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Verify balance is never negative
        final_balance = await get_user_wallet_balance_by_id(user_id)
        assert final_balance >= 0

class TestWalletEdgeCases:
    """Edge cases and error scenarios"""

    async def test_wallet_balance_precision(self, test_user_with_balance):
        """Test decimal precision in wallet operations"""
        user_id = test_user_with_balance
        
        # Credit with high precision
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=0.01,  # 1 cent
            provider='dynopay',
            txid='precision_test',
            order_id='precision_order'
        )
        
        assert result is True
        
        # Debit exact amount
        result = await debit_wallet_balance(
            user_id=user_id,
            amount=0.01,
            description="Precision debit test"
        )
        
        assert result is True

    async def test_large_transaction_amounts(self, test_user_with_balance):
        """Test handling of large transaction amounts"""
        user_id = test_user_with_balance
        
        # Test large credit (within limits)
        result = await credit_user_wallet(
            user_id=user_id,
            amount_usd=99999.99,
            provider='dynopay',
            txid='large_tx',
            order_id='large_order'
        )
        
        assert result is True
        
        balance = await get_user_wallet_balance_by_id(user_id)
        assert balance >= 99999.99

    async def test_rapid_sequential_operations(self, test_user_with_balance):
        """Test rapid sequential operations don't cause issues"""
        user_id = test_user_with_balance
        
        # Rapid sequence of small operations
        for i in range(10):
            await credit_user_wallet(
                user_id=user_id,
                amount_usd=1.00,
                provider='dynopay',
                txid=f'rapid_tx_{i}',
                order_id=f'rapid_order_{i}'
            )
            await asyncio.sleep(0.01)  # Small delay
        
        balance = await get_user_wallet_balance_by_id(user_id)
        assert balance >= 110.00  # 100 initial + 10 credits