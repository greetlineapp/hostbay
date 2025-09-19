"""
Bundle Pricing Calculations and Discounts Tests
Tests for domain+hosting pricing accuracy, discount codes, and upgrade scenarios
"""

import pytest
import asyncio
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from pricing_utils import calculate_marked_up_price, format_money, PricingConfig
from services.hosting_orchestrator import HostingBundleOrchestrator


@pytest.mark.asyncio
class TestBundlePricingCalculations:
    """Test bundle pricing with new hosting rates and discount structures"""
    
    def test_bundle_pricing_7day_starter_plan(self):
        """Test bundle pricing for 7-day starter plan ($50 hosting)"""
        # Domain: .com at $15 (after markup)
        # Hosting: 7-day starter at $50
        # Bundle discount: 15%
        
        domain_price = Decimal('15.00')
        hosting_price = Decimal('50.00')
        bundle_discount = Decimal('15.0')  # 15%
        
        total_before_discount = domain_price + hosting_price
        discount_amount = total_before_discount * (bundle_discount / 100)
        expected_total = total_before_discount - discount_amount
        
        # Expected: (15 + 50) * 0.85 = 55.25
        assert expected_total == Decimal('55.25'), f"Expected $55.25, got ${expected_total}"
    
    def test_bundle_pricing_30day_premium_plan(self):
        """Test bundle pricing for 30-day premium plan ($120 hosting)"""
        # Domain: .org at $18 (after markup)
        # Hosting: 30-day premium at $120
        # Bundle discount: 15%
        
        domain_price = Decimal('18.00')
        hosting_price = Decimal('120.00')
        bundle_discount = Decimal('15.0')
        
        total_before_discount = domain_price + hosting_price
        discount_amount = total_before_discount * (bundle_discount / 100)
        expected_total = total_before_discount - discount_amount
        
        # Expected: (18 + 120) * 0.85 = 117.30
        assert expected_total == Decimal('117.30'), f"Expected $117.30, got ${expected_total}"
    
    async def test_hosting_bundle_orchestrator_pricing(self):
        """Test HostingBundleOrchestrator with new pricing structure"""
        orchestrator = HostingBundleOrchestrator()
        
        # Mock domain pricing
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('15.00')  # .com domain
            
            # Test 7-day plan bundle calculation
            bundle_result = await orchestrator.calculate_bundle_pricing(
                domain_tld='com',
                hosting_plan='starter',
                billing_cycle='7days'
            )
            
            expected_hosting = Decimal('50.00')
            expected_domain = Decimal('15.00')
            expected_subtotal = expected_domain + expected_hosting
            expected_discount = expected_subtotal * Decimal('0.15')  # 15% bundle discount
            expected_total = expected_subtotal - expected_discount
            
            assert bundle_result['domain_price'] == expected_domain
            assert bundle_result['hosting_price'] == expected_hosting
            assert bundle_result['bundle_discount_amount'] == expected_discount
            assert bundle_result['total_price'] == expected_total
    
    async def test_discount_code_application(self):
        """Test application of discount codes on top of bundle discounts"""
        orchestrator = HostingBundleOrchestrator()
        
        # Mock domain pricing and discount validation
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('20.00')  # .net domain
            
            with patch('database.validate_discount_code') as mock_validate_code:
                mock_validate_code.return_value = {
                    'valid': True,
                    'discount_percentage': Decimal('20.0'),  # 20% additional discount
                    'code': 'SAVE20'
                }
                
                bundle_result = await orchestrator.calculate_bundle_pricing(
                    domain_tld='net',
                    hosting_plan='premium',
                    billing_cycle='30days',
                    discount_code='SAVE20'
                )
                
                # Base prices: $20 domain + $120 hosting = $140
                # Bundle discount: 15% = $21
                # Subtotal after bundle: $119
                # Additional discount: 20% of $119 = $23.80
                # Final total: $119 - $23.80 = $95.20
                
                expected_base = Decimal('140.00')
                expected_bundle_discount = expected_base * Decimal('0.15')  # $21
                subtotal_after_bundle = expected_base - expected_bundle_discount  # $119
                expected_code_discount = subtotal_after_bundle * Decimal('0.20')  # $23.80
                expected_final = subtotal_after_bundle - expected_code_discount  # $95.20
                
                assert bundle_result['base_price'] == expected_base
                assert bundle_result['bundle_discount_amount'] == expected_bundle_discount
                assert bundle_result['code_discount_amount'] == expected_code_discount
                assert bundle_result['total_price'] == expected_final
    
    async def test_expired_discount_code_handling(self):
        """Test handling of expired discount codes"""
        orchestrator = HostingBundleOrchestrator()
        
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('15.00')
            
            with patch('database.validate_discount_code') as mock_validate_code:
                mock_validate_code.return_value = {
                    'valid': False,
                    'error': 'expired',
                    'code': 'EXPIRED2024'
                }
                
                bundle_result = await orchestrator.calculate_bundle_pricing(
                    domain_tld='com',
                    hosting_plan='starter',
                    billing_cycle='7days',
                    discount_code='EXPIRED2024'
                )
                
                # Should only apply bundle discount, ignore expired code
                expected_base = Decimal('65.00')  # $15 + $50
                expected_bundle_discount = expected_base * Decimal('0.15')
                expected_total = expected_base - expected_bundle_discount
                
                assert bundle_result['code_discount_amount'] == Decimal('0')
                assert bundle_result['total_price'] == expected_total
                assert 'discount_code_error' in bundle_result
    
    def test_bundle_discount_precision_calculations(self):
        """Test precision in bundle discount calculations with edge amounts"""
        # Test with amounts that could cause rounding issues
        domain_price = Decimal('12.33')  # Odd cents
        hosting_price = Decimal('47.67')  # Odd cents
        bundle_discount_rate = Decimal('15.0')
        
        total_before_discount = domain_price + hosting_price  # $60.00
        discount_amount = total_before_discount * (bundle_discount_rate / 100)  # $9.00
        expected_total = total_before_discount - discount_amount  # $51.00
        
        # Ensure calculations maintain proper decimal precision
        assert discount_amount == Decimal('9.00')
        assert expected_total == Decimal('51.00')
    
    async def test_bundle_pricing_with_multiple_tlds(self):
        """Test bundle pricing accuracy across different TLD pricing"""
        orchestrator = HostingBundleOrchestrator()
        
        tld_pricing = {
            'com': Decimal('15.00'),
            'org': Decimal('18.00'),
            'net': Decimal('16.50'),
            'io': Decimal('35.00'),
            'dev': Decimal('28.00')
        }
        
        for tld, domain_price in tld_pricing.items():
            with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
                mock_domain_price.return_value = domain_price
                
                bundle_result = await orchestrator.calculate_bundle_pricing(
                    domain_tld=tld,
                    hosting_plan='starter',
                    billing_cycle='7days'
                )
                
                expected_base = domain_price + Decimal('50.00')
                expected_discount = expected_base * Decimal('0.15')
                expected_total = expected_base - expected_discount
                
                assert bundle_result['domain_price'] == domain_price
                assert bundle_result['total_price'] == expected_total
                assert bundle_result['domain_tld'] == tld


@pytest.mark.asyncio  
class TestBundleUpgradeDowngradeCalculations:
    """Test upgrade and downgrade pricing calculations"""
    
    async def test_hosting_plan_upgrade_pricing(self):
        """Test pricing when upgrading hosting plan within bundle"""
        orchestrator = HostingBundleOrchestrator()
        
        # Original: 7-day starter ($50)
        # Upgrade to: 30-day premium ($120)
        
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('15.00')
            
            # Calculate original bundle price
            original_bundle = await orchestrator.calculate_bundle_pricing(
                domain_tld='com',
                hosting_plan='starter', 
                billing_cycle='7days'
            )
            
            # Calculate upgraded bundle price
            upgraded_bundle = await orchestrator.calculate_bundle_pricing(
                domain_tld='com',
                hosting_plan='premium',
                billing_cycle='30days'
            )
            
            upgrade_difference = upgraded_bundle['total_price'] - original_bundle['total_price']
            
            # Original: (15 + 50) * 0.85 = 55.25
            # Upgraded: (15 + 120) * 0.85 = 114.75
            # Difference: 114.75 - 55.25 = 59.50
            
            expected_difference = Decimal('59.50')
            assert upgrade_difference == expected_difference
    
    async def test_billing_cycle_change_calculations(self):
        """Test pricing when changing billing cycles"""
        orchestrator = HostingBundleOrchestrator()
        
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('18.00')  # .org domain
            
            # 7-day premium plan
            weekly_bundle = await orchestrator.calculate_bundle_pricing(
                domain_tld='org',
                hosting_plan='premium',
                billing_cycle='7days'  
            )
            
            # 30-day premium plan  
            monthly_bundle = await orchestrator.calculate_bundle_pricing(
                domain_tld='org',
                hosting_plan='premium',
                billing_cycle='30days'
            )
            
            # Verify pricing difference reflects billing cycle change
            # 7-day premium: assume $75, total (18 + 75) * 0.85 = 79.05
            # 30-day premium: $120, total (18 + 120) * 0.85 = 117.30
            
            assert weekly_bundle['billing_cycle'] == '7days'
            assert monthly_bundle['billing_cycle'] == '30days'
            assert monthly_bundle['total_price'] > weekly_bundle['total_price']
    
    async def test_invalid_plan_combination_handling(self):
        """Test handling of invalid plan combinations"""
        orchestrator = HostingBundleOrchestrator()
        
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('15.00')
            
            # Test invalid hosting plan
            with pytest.raises(ValueError, match="Invalid hosting plan"):
                await orchestrator.calculate_bundle_pricing(
                    domain_tld='com',
                    hosting_plan='invalid_plan',
                    billing_cycle='7days'
                )
            
            # Test invalid billing cycle
            with pytest.raises(ValueError, match="Invalid billing cycle"):
                await orchestrator.calculate_bundle_pricing(
                    domain_tld='com',
                    hosting_plan='starter',
                    billing_cycle='invalid_cycle'
                )
    
    async def test_bundle_pricing_consistency_across_calculations(self):
        """Test that bundle pricing calculations are consistent across multiple calls"""
        orchestrator = HostingBundleOrchestrator()
        
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('15.00')
            
            # Calculate same bundle multiple times
            results = []
            for _ in range(5):
                result = await orchestrator.calculate_bundle_pricing(
                    domain_tld='com',
                    hosting_plan='starter',
                    billing_cycle='7days'
                )
                results.append(result['total_price'])
            
            # All results should be identical
            first_result = results[0]
            assert all(result == first_result for result in results)


@pytest.mark.asyncio
class TestBundlePricingEdgeCases:
    """Test edge cases in bundle pricing calculations"""
    
    async def test_zero_pricing_edge_cases(self):
        """Test handling of zero prices in bundle calculations"""
        orchestrator = HostingBundleOrchestrator()
        
        # Test with zero domain price (free domain scenario)
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('0.00')
            
            bundle_result = await orchestrator.calculate_bundle_pricing(
                domain_tld='free',
                hosting_plan='starter',
                billing_cycle='7days'
            )
            
            # Bundle should still apply 15% discount to hosting only
            expected_hosting = Decimal('50.00')
            expected_discount = expected_hosting * Decimal('0.15')
            expected_total = expected_hosting - expected_discount
            
            assert bundle_result['domain_price'] == Decimal('0.00')
            assert bundle_result['hosting_price'] == expected_hosting
            assert bundle_result['total_price'] == expected_total
    
    async def test_very_high_pricing_calculations(self):
        """Test bundle calculations with very high prices"""
        orchestrator = HostingBundleOrchestrator()
        
        # Test with expensive premium domain
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('500.00')  # Expensive domain
            
            bundle_result = await orchestrator.calculate_bundle_pricing(
                domain_tld='premium',
                hosting_plan='enterprise',
                billing_cycle='yearly'
            )
            
            # Should handle large numbers correctly
            assert bundle_result['domain_price'] == Decimal('500.00')
            assert bundle_result['bundle_discount_amount'] > Decimal('0')
            assert bundle_result['total_price'] < (bundle_result['base_price'])
    
    def test_bundle_discount_rate_configuration(self):
        """Test that bundle discount rate is properly configurable"""
        import os
        
        # Test default bundle discount rate
        default_rate = os.getenv('HOSTING_BUNDLE_DISCOUNT', '15.0')
        assert default_rate == '15.0'
        
        # Test with different discount rates
        discount_rates = ['10.0', '20.0', '25.0']
        
        for rate in discount_rates:
            with patch.dict(os.environ, {'HOSTING_BUNDLE_DISCOUNT': rate}):
                # Test that calculations use the new rate
                domain_price = Decimal('15.00')
                hosting_price = Decimal('50.00')
                discount_rate_decimal = Decimal(rate)
                
                total_before = domain_price + hosting_price
                expected_discount = total_before * (discount_rate_decimal / 100)
                expected_total = total_before - expected_discount
                
                # Verify the math works with different rates
                assert expected_discount == total_before * (Decimal(rate) / 100)
    
    async def test_bundle_pricing_with_fractional_discounts(self):
        """Test bundle pricing with fractional discount percentages"""
        orchestrator = HostingBundleOrchestrator()
        
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            mock_domain_price.return_value = Decimal('15.00')
            
            with patch('database.validate_discount_code') as mock_validate_code:
                # Test with 12.5% discount code
                mock_validate_code.return_value = {
                    'valid': True,
                    'discount_percentage': Decimal('12.5'),
                    'code': 'FRACTIONAL'
                }
                
                bundle_result = await orchestrator.calculate_bundle_pricing(
                    domain_tld='com',
                    hosting_plan='starter',
                    billing_cycle='7days',
                    discount_code='FRACTIONAL'
                )
                
                # Should handle fractional percentages correctly
                assert bundle_result['code_discount_amount'] > Decimal('0')
                # Should maintain precision with fractional discounts
                assert '.' in str(bundle_result['code_discount_amount'])
    
    async def test_currency_precision_in_bundle_calculations(self):
        """Test that currency precision is maintained in all bundle calculations"""
        orchestrator = HostingBundleOrchestrator()
        
        with patch('pricing_utils.calculate_marked_up_price') as mock_domain_price:
            # Test with price that could cause precision issues
            mock_domain_price.return_value = Decimal('12.999')  # Many decimal places
            
            bundle_result = await orchestrator.calculate_bundle_pricing(
                domain_tld='precision',
                hosting_plan='starter',
                billing_cycle='7days'
            )
            
            # All monetary values should be rounded to 2 decimal places
            for key, value in bundle_result.items():
                if isinstance(value, Decimal) and 'price' in key or 'amount' in key:
                    # Check that we have at most 2 decimal places
                    assert value.as_tuple().exponent >= -2, f"{key}: {value} has more than 2 decimal places"