"""
Hosting Renewal Logic Tests
Tests for grace periods, new pricing structure, and renewal failure scenarios
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

from services.renewal_processor import HostingRenewalProcessor
from database import (
    execute_query, execute_update, get_user_wallet_balance,
    create_hosting_subscription_with_id, update_hosting_subscription_status
)


@pytest.mark.asyncio
class TestHostingRenewalLogic:
    """Test hosting renewal logic with new pricing and grace periods"""
    
    async def test_grace_period_calculation_7days_plan(self):
        """Test grace period for 7-day plans (should be 1 day)"""
        processor = HostingRenewalProcessor()
        grace_days = processor.get_grace_period_days('7days')
        assert grace_days == 1, f"7-day plans should have 1-day grace period, got {grace_days}"
    
    async def test_grace_period_calculation_30days_plan(self):
        """Test grace period for 30-day plans (should be 2 days)"""
        processor = HostingRenewalProcessor()
        grace_days = processor.get_grace_period_days('30days')
        assert grace_days == 2, f"30-day plans should have 2-day grace period, got {grace_days}"
    
    async def test_grace_period_calculation_monthly_plan(self):
        """Test grace period for monthly plans (should be 7 days)"""
        processor = HostingRenewalProcessor()
        grace_days = processor.get_grace_period_days('monthly')
        assert grace_days == 7, f"Monthly plans should have 7-day grace period, got {grace_days}"
    
    async def test_grace_period_calculation_yearly_plan(self):
        """Test grace period for yearly plans (should be 7 days)"""
        processor = HostingRenewalProcessor()
        grace_days = processor.get_grace_period_days('yearly')
        assert grace_days == 7, f"Yearly plans should have 7-day grace period, got {grace_days}"
    
    @patch('services.renewal_processor.get_hosting_plan')
    @patch('services.renewal_processor.get_user_wallet_balance')
    @patch('services.renewal_processor.debit_wallet_balance')
    async def test_renewal_pricing_7day_plan(self, mock_debit, mock_balance, mock_plan):
        """Test renewal pricing for 7-day plan ($50)"""
        # Setup mocks
        mock_plan.return_value = {
            'plan_name': 'starter',
            'billing_cycle': '7days',
            'price': Decimal('50.00')
        }
        mock_balance.return_value = Decimal('100.00')
        mock_debit.return_value = True
        
        processor = HostingRenewalProcessor()
        
        # Mock database calls
        with patch('services.renewal_processor.get_user_hosting_subscriptions') as mock_subscriptions:
            mock_subscriptions.return_value = [
                {
                    'user_id': 12345,
                    'subscription_id': 'sub_123',
                    'expires_at': datetime.now() - timedelta(hours=1),
                    'billing_cycle': '7days',
                    'price': Decimal('50.00'),
                    'plan_name': 'starter'
                }
            ]
            
            # Test renewal processing
            result = await processor.process_all_renewals()
            
            # Verify renewal was attempted with correct price
            assert result['status'] in ['completed', 'partial']
            mock_debit.assert_called_with(12345, Decimal('50.00'), 'Hosting renewal: starter (7days)')
    
    @patch('services.renewal_processor.get_hosting_plan')
    @patch('services.renewal_processor.get_user_wallet_balance')
    @patch('services.renewal_processor.debit_wallet_balance')
    async def test_renewal_pricing_30day_plan(self, mock_debit, mock_balance, mock_plan):
        """Test renewal pricing for 30-day plan ($120)"""
        # Setup mocks
        mock_plan.return_value = {
            'plan_name': 'premium',
            'billing_cycle': '30days',
            'price': Decimal('120.00')
        }
        mock_balance.return_value = Decimal('150.00')
        mock_debit.return_value = True
        
        processor = HostingRenewalProcessor()
        
        # Mock database calls
        with patch('services.renewal_processor.get_user_hosting_subscriptions') as mock_subscriptions:
            mock_subscriptions.return_value = [
                {
                    'user_id': 12345,
                    'subscription_id': 'sub_456',
                    'expires_at': datetime.now() - timedelta(hours=1),
                    'billing_cycle': '30days',
                    'price': Decimal('120.00'),
                    'plan_name': 'premium'
                }
            ]
            
            # Test renewal processing
            result = await processor.process_all_renewals()
            
            # Verify renewal was attempted with correct price
            assert result['status'] in ['completed', 'partial']
            mock_debit.assert_called_with(12345, Decimal('120.00'), 'Hosting renewal: premium (30days)')
    
    @patch('services.renewal_processor.get_user_wallet_balance')
    async def test_renewal_failure_insufficient_funds(self, mock_balance):
        """Test renewal failure when user has insufficient wallet funds"""
        mock_balance.return_value = Decimal('25.00')  # Insufficient for $50 renewal
        
        processor = HostingRenewalProcessor()
        
        with patch('services.renewal_processor.get_user_hosting_subscriptions') as mock_subscriptions:
            mock_subscriptions.return_value = [
                {
                    'user_id': 12345,
                    'subscription_id': 'sub_789',
                    'expires_at': datetime.now() - timedelta(hours=1),
                    'billing_cycle': '7days',
                    'price': Decimal('50.00'),
                    'plan_name': 'starter'
                }
            ]
            
            # Test renewal processing
            result = await processor.process_all_renewals()
            
            # Should have recorded failure
            assert result['stats']['failed'] >= 1
    
    @patch('services.renewal_processor.get_user_hosting_subscriptions')
    async def test_grace_period_handling_7day_plan(self, mock_subscriptions):
        """Test that 7-day plans get 1-day grace period before suspension"""
        processor = HostingRenewalProcessor()
        
        # Subscription expired 12 hours ago (within 1-day grace period)
        mock_subscriptions.return_value = [
            {
                'user_id': 12345,
                'subscription_id': 'sub_grace',
                'expires_at': datetime.now() - timedelta(hours=12),
                'billing_cycle': '7days',
                'price': Decimal('50.00'),
                'plan_name': 'starter',
                'status': 'active'
            }
        ]
        
        # Mock wallet balance as insufficient
        with patch('services.renewal_processor.get_user_wallet_balance') as mock_balance:
            mock_balance.return_value = Decimal('10.00')
            
            result = await processor.process_all_renewals()
            
            # Should be in grace period, not suspended yet
            assert result['stats']['grace_period'] >= 1
    
    @patch('services.renewal_processor.get_user_hosting_subscriptions')
    async def test_suspension_after_grace_period_7day_plan(self, mock_subscriptions):
        """Test that 7-day plans are suspended after 1-day grace period"""
        processor = HostingRenewalProcessor()
        
        # Subscription expired 2 days ago (beyond 1-day grace period)
        mock_subscriptions.return_value = [
            {
                'user_id': 12345,
                'subscription_id': 'sub_suspend',
                'expires_at': datetime.now() - timedelta(days=2),
                'billing_cycle': '7days',
                'price': Decimal('50.00'),
                'plan_name': 'starter',
                'status': 'active'
            }
        ]
        
        # Mock wallet balance as insufficient
        with patch('services.renewal_processor.get_user_wallet_balance') as mock_balance:
            mock_balance.return_value = Decimal('10.00')
            
            result = await processor.process_all_renewals()
            
            # Should be suspended after grace period
            assert result['stats']['suspended'] >= 1
    
    async def test_renewal_processor_stats_tracking(self):
        """Test that renewal processor correctly tracks statistics"""
        processor = HostingRenewalProcessor()
        
        # Check initial stats
        initial_stats = processor.stats
        assert 'processed' in initial_stats
        assert 'successful' in initial_stats
        assert 'failed' in initial_stats
        assert 'warnings_sent' in initial_stats
        assert 'grace_period' in initial_stats
        assert 'suspended' in initial_stats
        
        # All should start at 0
        for key, value in initial_stats.items():
            assert value == 0, f"Initial stat {key} should be 0, got {value}"
    
    @patch('services.renewal_processor.get_user_hosting_subscriptions')
    async def test_renewal_batch_processing_limits(self, mock_subscriptions):
        """Test that renewal processor respects batch size limits"""
        processor = HostingRenewalProcessor()
        
        # Create more subscriptions than the batch size (50)
        large_subscription_list = []
        for i in range(75):  # More than batch size
            large_subscription_list.append({
                'user_id': 10000 + i,
                'subscription_id': f'sub_{i}',
                'expires_at': datetime.now() - timedelta(hours=1),
                'billing_cycle': '7days',
                'price': Decimal('50.00'),
                'plan_name': 'starter',
                'status': 'active'
            })
        
        mock_subscriptions.return_value = large_subscription_list
        
        with patch('services.renewal_processor.get_user_wallet_balance') as mock_balance:
            mock_balance.return_value = Decimal('100.00')
            
            result = await processor.process_all_renewals()
            
            # Should process in batches, respecting the limit
            assert result['stats']['processed'] <= processor.batch_size
    
    async def test_renewal_processor_disabled_mode(self):
        """Test renewal processor when processing is disabled"""
        processor = HostingRenewalProcessor()
        processor.processing_enabled = False
        
        result = await processor.process_all_renewals()
        
        assert result['status'] == 'disabled'
        assert result['reason'] == 'Processing disabled'
    
    @patch('services.renewal_processor.verify_financial_operation_safety')
    async def test_renewal_processor_financial_safety_check(self, mock_safety):
        """Test renewal processor financial safety verification"""
        mock_safety.return_value = False  # Block financial operations
        
        processor = HostingRenewalProcessor()
        result = await processor.process_all_renewals()
        
        assert result['status'] == 'blocked'
        assert result['reason'] == 'Financial operations blocked'
        mock_safety.assert_called_once_with('hosting_renewal_processing')


@pytest.mark.asyncio
class TestHostingRenewalNotifications:
    """Test renewal notification system"""
    
    async def test_bot_application_reference_setting(self):
        """Test setting bot application reference for notifications"""
        processor = HostingRenewalProcessor()
        mock_bot_app = MagicMock()
        
        processor.set_bot_application(mock_bot_app)
        assert processor._bot_application == mock_bot_app
    
    @patch('services.renewal_processor.get_user_hosting_subscriptions')
    async def test_renewal_warning_notifications(self, mock_subscriptions):
        """Test that renewal warnings are sent before expiration"""
        processor = HostingRenewalProcessor()
        mock_bot_app = MagicMock()
        processor.set_bot_application(mock_bot_app)
        
        # Subscription expires in 2 days (within warning period)
        mock_subscriptions.return_value = [
            {
                'user_id': 12345,
                'subscription_id': 'sub_warning',
                'expires_at': datetime.now() + timedelta(days=2),
                'billing_cycle': '7days',
                'price': Decimal('50.00'),
                'plan_name': 'starter',
                'status': 'active'
            }
        ]
        
        result = await processor.process_all_renewals()
        
        # Should have sent warning notifications
        assert result['stats']['warnings_sent'] >= 1


@pytest.mark.asyncio
class TestHostingRenewalEdgeCases:
    """Test edge cases and error scenarios in hosting renewals"""
    
    async def test_renewal_with_invalid_billing_cycle(self):
        """Test handling of invalid billing cycles"""
        processor = HostingRenewalProcessor()
        
        # Test unknown billing cycle
        grace_days = processor.get_grace_period_days('invalid_cycle')
        assert grace_days == 2, "Unknown billing cycles should default to 2-day grace period"
    
    @patch('services.renewal_processor.get_user_hosting_subscriptions')
    async def test_renewal_processor_database_error_handling(self, mock_subscriptions):
        """Test renewal processor handles database errors gracefully"""
        mock_subscriptions.side_effect = Exception("Database connection failed")
        
        processor = HostingRenewalProcessor()
        result = await processor.process_all_renewals()
        
        # Should handle error gracefully and return error status
        assert result['status'] == 'error'
        assert 'database' in result.get('error_message', '').lower()
    
    @patch('services.renewal_processor.get_user_wallet_balance')
    async def test_renewal_with_wallet_balance_decimal_precision(self, mock_balance):
        """Test renewal calculations with precise decimal amounts"""
        # Test with exact balance
        mock_balance.return_value = Decimal('50.00')
        
        processor = HostingRenewalProcessor()
        
        with patch('services.renewal_processor.get_user_hosting_subscriptions') as mock_subscriptions:
            mock_subscriptions.return_value = [
                {
                    'user_id': 12345,
                    'subscription_id': 'sub_precision',
                    'expires_at': datetime.now() - timedelta(hours=1),
                    'billing_cycle': '7days',
                    'price': Decimal('50.00'),
                    'plan_name': 'starter',
                    'status': 'active'
                }
            ]
            
            with patch('services.renewal_processor.debit_wallet_balance') as mock_debit:
                mock_debit.return_value = True
                
                result = await processor.process_all_renewals()
                
                # Should handle exact balance correctly
                mock_debit.assert_called_with(12345, Decimal('50.00'), 'Hosting renewal: starter (7days)')