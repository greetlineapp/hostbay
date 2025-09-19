#!/usr/bin/env python3
"""
WORKING Domain Registration Test Suite - Production Bug Identification

Simple, robust test suite that actually works to identify critical production issues.
Based on successful approach from wallet crediting tests that found "Error: 1" bug.
"""

import asyncio
import logging
import os
import sys
import time
import json
from datetime import datetime
from decimal import Decimal

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class WorkingDomainTester:
    """Simple, working domain registration tester"""
    
    def __init__(self):
        self.results = {
            'start_time': datetime.now(),
            'tests': {},
            'issues': [],
            'fixes_applied': [],
            'production_status': 'unknown'
        }
    
    async def test_1_domain_search(self):
        """Test 1: Domain Search & Availability"""
        logger.info("🔍 TEST 1: Domain Search & Availability")
        result = {'status': 'unknown', 'details': []}
        
        try:
            # Import here to handle any import issues gracefully
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from services.openprovider import OpenProviderService
            
            openprovider = OpenProviderService()
            test_domains = [
                'working-test-domain-001.com',
                'production-test-domain.org',
                'domain-search-validation.net'
            ]
            
            successful_searches = 0
            for domain in test_domains:
                try:
                    logger.info(f"  Checking: {domain}")
                    start = time.time()
                    
                    availability = await openprovider.check_domain_availability(domain)
                    response_time = time.time() - start
                    
                    if availability:
                        successful_searches += 1
                        result['details'].append({
                            'domain': domain,
                            'available': availability.get('available', False),
                            'price_usd': availability.get('price_usd', 0),
                            'response_time': response_time,
                            'status': 'success'
                        })
                        logger.info(f"  ✅ {domain}: Available={availability.get('available')}, ${availability.get('price_usd', 'N/A')}")
                    else:
                        result['details'].append({'domain': domain, 'status': 'failed'})
                        logger.warning(f"  ❌ {domain}: No response")
                    
                except Exception as e:
                    result['details'].append({'domain': domain, 'status': 'error', 'error': str(e)})
                    logger.error(f"  ❌ {domain}: {e}")
                
                await asyncio.sleep(1)  # Rate limiting
            
            if successful_searches >= 2:
                result['status'] = 'PASSED'
            elif successful_searches >= 1:
                result['status'] = 'PARTIAL'
                self.results['issues'].append('Some domain searches failing')
            else:
                result['status'] = 'FAILED'
                self.results['issues'].append('CRITICAL: All domain searches failing - OpenProvider API issues')
            
            result['success_count'] = successful_searches
            result['total_count'] = len(test_domains)
            
        except Exception as e:
            result['status'] = 'FAILED'
            result['error'] = str(e)
            self.results['issues'].append(f'Domain search test failed: {e}')
            logger.error(f"❌ Domain search test failed: {e}")
        
        self.results['tests']['domain_search'] = result
        return result
    
    async def test_2_pricing_system(self):
        """Test 2: Pricing System"""
        logger.info("💰 TEST 2: Pricing System")
        result = {'status': 'unknown', 'details': []}
        
        try:
            from pricing_utils import calculate_marked_up_price
            
            test_cases = [
                {'base': Decimal('10.00'), 'currency': 'EUR', 'expect_min': True},
                {'base': Decimal('15.00'), 'currency': 'EUR', 'expect_markup': True},
                {'base': Decimal('20.00'), 'currency': 'EUR', 'expect_markup': True}
            ]
            
            passed = 0
            for case in test_cases:
                try:
                    calculated = calculate_marked_up_price(case['base'], case['currency'])
                    
                    test_detail = {
                        'base_price': float(case['base']),
                        'calculated': float(calculated),
                        'currency': case['currency']
                    }
                    
                    # Simple validation
                    if case.get('expect_min') and calculated >= Decimal('25.00'):
                        test_detail['status'] = 'passed'
                        passed += 1
                        logger.info(f"  ✅ Minimum price enforced: €{case['base']} → ${calculated}")
                    elif case.get('expect_markup') and calculated > case['base'] * 2:
                        test_detail['status'] = 'passed'
                        passed += 1
                        logger.info(f"  ✅ Markup applied: €{case['base']} → ${calculated}")
                    else:
                        test_detail['status'] = 'failed'
                        logger.warning(f"  ❌ Pricing issue: €{case['base']} → ${calculated}")
                    
                    result['details'].append(test_detail)
                    
                except Exception as e:
                    result['details'].append({'base_price': float(case['base']), 'error': str(e)})
                    logger.error(f"  ❌ Pricing calculation error: {e}")
            
            if passed >= 2:
                result['status'] = 'PASSED'
            elif passed >= 1:
                result['status'] = 'PARTIAL'
                self.results['issues'].append('Some pricing calculations failing')
            else:
                result['status'] = 'FAILED'
                self.results['issues'].append('CRITICAL: Pricing system completely broken')
            
            result['passed_count'] = passed
            result['total_count'] = len(test_cases)
            
        except Exception as e:
            result['status'] = 'FAILED'
            result['error'] = str(e)
            self.results['issues'].append(f'Pricing test failed: {e}')
            logger.error(f"❌ Pricing test failed: {e}")
        
        self.results['tests']['pricing_system'] = result
        return result
    
    async def test_3_user_creation_and_wallet(self):
        """Test 3: User Creation and Wallet Operations"""
        logger.info("👤 TEST 3: User Creation & Wallet Operations")
        result = {'status': 'unknown', 'details': []}
        
        try:
            from database import get_or_create_user, get_user_wallet_balance, credit_user_wallet, run_db
            
            # Create test user with proper async handling
            test_telegram_id = 888888888
            logger.info(f"  Creating test user: {test_telegram_id}")
            
            # Use run_db to properly handle async operations
            user_data = await run_db(get_or_create_user, test_telegram_id, 'working_test_user', 'Working', 'Tester')
            
            # Extract user ID properly
            if isinstance(user_data, dict):
                user_id = user_data.get('id')
                logger.info(f"  ✅ User created (dict): ID {user_id}")
            else:
                user_id = user_data
                logger.info(f"  ✅ User created (direct): ID {user_id}")
            
            if user_id:
                result['details'].append({'test': 'user_creation', 'user_id': user_id, 'status': 'passed'})
                
                # Test wallet balance check
                try:
                    balance = await run_db(get_user_wallet_balance, user_id)
                    logger.info(f"  ✅ Wallet balance retrieved: ${balance}")
                    result['details'].append({'test': 'wallet_balance_check', 'balance': float(balance), 'status': 'passed'})
                    
                    # Test wallet credit
                    credit_amount = Decimal('10.00')
                    credit_success = await run_db(credit_user_wallet, user_id, credit_amount, 'Working test credit')
                    
                    if credit_success:
                        logger.info(f"  ✅ Wallet credited: +${credit_amount}")
                        result['details'].append({'test': 'wallet_credit', 'amount': float(credit_amount), 'status': 'passed'})
                        result['status'] = 'PASSED'
                        result['user_id'] = user_id  # Store for use in other tests
                    else:
                        logger.warning(f"  ❌ Wallet credit failed")
                        result['details'].append({'test': 'wallet_credit', 'status': 'failed'})
                        result['status'] = 'PARTIAL'
                        self.results['issues'].append('Wallet credit functionality not working')
                    
                except Exception as wallet_error:
                    logger.error(f"  ❌ Wallet operations failed: {wallet_error}")
                    result['details'].append({'test': 'wallet_operations', 'error': str(wallet_error)})
                    result['status'] = 'PARTIAL'
                    self.results['issues'].append(f'Wallet operations failed: {wallet_error}')
            else:
                result['status'] = 'FAILED'
                self.results['issues'].append('CRITICAL: User creation completely failed')
                
        except Exception as e:
            result['status'] = 'FAILED'
            result['error'] = str(e)
            self.results['issues'].append(f'User/wallet test failed: {e}')
            logger.error(f"❌ User/wallet test failed: {e}")
        
        self.results['tests']['user_wallet'] = result
        return result
    
    async def test_4_database_operations(self):
        """Test 4: Core Database Operations"""
        logger.info("🗄️ TEST 4: Database Operations")
        result = {'status': 'unknown', 'details': []}
        
        try:
            from database import create_registration_intent, create_payment_intent, run_db
            
            # Get test user ID from previous test
            user_test_result = self.results['tests'].get('user_wallet', {})
            user_id = user_test_result.get('user_id')
            
            if not user_id:
                # Fallback - create new test user for database tests
                from database import get_or_create_user
                user_data = await run_db(get_or_create_user, 777777777, 'db_test_user', 'DB', 'Tester')
                user_id = user_data.get('id') if isinstance(user_data, dict) else user_data
            
            if user_id:
                logger.info(f"  Using test user ID: {user_id}")
                
                # Test registration intent creation
                try:
                    test_domain = 'database-test-domain.com'
                    intent_id = await run_db(
                        create_registration_intent,
                        user_id,
                        test_domain,
                        Decimal('25.00'),
                        'wallet'
                    )
                    
                    if intent_id:
                        logger.info(f"  ✅ Registration intent created: {intent_id}")
                        result['details'].append({'test': 'registration_intent', 'intent_id': intent_id, 'status': 'passed'})
                        
                        # Test payment intent creation
                        try:
                            payment_intent_id = await run_db(
                                create_payment_intent,
                                f'db-test-order-{int(time.time())}',
                                user_id,
                                Decimal('25.00'),
                                'USD',
                                'btc'
                            )
                            
                            if payment_intent_id:
                                logger.info(f"  ✅ Payment intent created: {payment_intent_id}")
                                result['details'].append({'test': 'payment_intent', 'intent_id': payment_intent_id, 'status': 'passed'})
                                result['status'] = 'PASSED'
                            else:
                                logger.warning(f"  ❌ Payment intent creation failed")
                                result['details'].append({'test': 'payment_intent', 'status': 'failed'})
                                result['status'] = 'PARTIAL'
                                self.results['issues'].append('Payment intent creation not working')
                                
                        except Exception as payment_error:
                            logger.error(f"  ❌ Payment intent error: {payment_error}")
                            result['details'].append({'test': 'payment_intent', 'error': str(payment_error)})
                            result['status'] = 'PARTIAL'
                            self.results['issues'].append(f'Payment intent creation failed: {payment_error}')
                    else:
                        logger.warning(f"  ❌ Registration intent creation failed")
                        result['details'].append({'test': 'registration_intent', 'status': 'failed'})
                        result['status'] = 'FAILED'
                        self.results['issues'].append('CRITICAL: Registration intent creation completely broken')
                        
                except Exception as intent_error:
                    logger.error(f"  ❌ Registration intent error: {intent_error}")
                    result['details'].append({'test': 'registration_intent', 'error': str(intent_error)})
                    result['status'] = 'FAILED'
                    self.results['issues'].append(f'Registration intent creation failed: {intent_error}')
            else:
                result['status'] = 'FAILED'
                self.results['issues'].append('CRITICAL: No valid user ID for database testing')
                
        except Exception as e:
            result['status'] = 'FAILED'
            result['error'] = str(e)
            self.results['issues'].append(f'Database operations test failed: {e}')
            logger.error(f"❌ Database operations test failed: {e}")
        
        self.results['tests']['database_operations'] = result
        return result
    
    async def test_5_payment_address_generation(self):
        """Test 5: Crypto Payment Address Generation"""
        logger.info("💳 TEST 5: Crypto Payment Address Generation")
        result = {'status': 'unknown', 'details': []}
        
        try:
            from services.payment_provider import PaymentProviderFactory
            
            # Get test user ID from previous test
            user_test_result = self.results['tests'].get('user_wallet', {})
            user_id = user_test_result.get('user_id', 777777777)  # Fallback ID
            
            logger.info(f"  Using user ID for payment tests: {user_id}")
            
            currencies = ['btc', 'eth']  # Simplified test
            successful_payments = 0
            
            for currency in currencies:
                try:
                    order_id = f'working-test-{currency}-{int(time.time())}'
                    logger.info(f"  Testing {currency.upper()} payment address...")
                    
                    payment_result = await PaymentProviderFactory.create_payment_address_with_fallback(
                        currency=currency,
                        order_id=order_id,
                        value=5.0,
                        user_id=user_id
                    )
                    
                    if payment_result and payment_result.get('address'):
                        successful_payments += 1
                        result['details'].append({
                            'currency': currency,
                            'order_id': order_id,
                            'address_preview': payment_result['address'][:16] + '...',
                            'provider': payment_result.get('provider', 'unknown'),
                            'status': 'passed'
                        })
                        logger.info(f"  ✅ {currency.upper()}: Address created via {payment_result.get('provider')}")
                    else:
                        result['details'].append({
                            'currency': currency,
                            'order_id': order_id,
                            'status': 'failed',
                            'error': 'No address returned'
                        })
                        logger.warning(f"  ❌ {currency.upper()}: No address generated")
                    
                except Exception as crypto_error:
                    result['details'].append({
                        'currency': currency,
                        'status': 'error',
                        'error': str(crypto_error)
                    })
                    logger.error(f"  ❌ {currency.upper()}: {crypto_error}")
                
                await asyncio.sleep(2)  # Rate limiting
            
            if successful_payments >= 1:
                result['status'] = 'PASSED' if successful_payments == len(currencies) else 'PARTIAL'
                if successful_payments < len(currencies):
                    self.results['issues'].append(f'Some crypto payment providers not working')
            else:
                result['status'] = 'FAILED'
                self.results['issues'].append('CRITICAL: All crypto payment address generation failing')
            
            result['successful_payments'] = successful_payments
            result['total_currencies'] = len(currencies)
            
        except Exception as e:
            result['status'] = 'FAILED'
            result['error'] = str(e)
            self.results['issues'].append(f'Payment address generation test failed: {e}')
            logger.error(f"❌ Payment address generation test failed: {e}")
        
        self.results['tests']['payment_address_generation'] = result
        return result
    
    async def run_working_tests(self):
        """Run all working tests"""
        logger.info("🚀 WORKING DOMAIN REGISTRATION TEST SUITE")
        logger.info("="*60)
        
        test_functions = [
            self.test_1_domain_search,
            self.test_2_pricing_system,
            self.test_3_user_creation_and_wallet,
            self.test_4_database_operations,
            self.test_5_payment_address_generation
        ]
        
        for test_func in test_functions:
            try:
                await test_func()
                logger.info("-" * 40)
            except Exception as e:
                logger.error(f"❌ Test {test_func.__name__} crashed: {e}")
                self.results['issues'].append(f'Test {test_func.__name__} crashed: {e}')
        
        # Calculate final assessment
        passed_tests = sum(1 for t in self.results['tests'].values() if t.get('status') == 'PASSED')
        partial_tests = sum(1 for t in self.results['tests'].values() if t.get('status') == 'PARTIAL')
        failed_tests = sum(1 for t in self.results['tests'].values() if t.get('status') == 'FAILED')
        total_tests = len(self.results['tests'])
        
        if total_tests > 0:
            success_rate = (passed_tests + (partial_tests * 0.5)) / total_tests * 100
            
            if success_rate >= 80 and len([i for i in self.results['issues'] if 'CRITICAL' in i]) == 0:
                self.results['production_status'] = 'READY'
            elif success_rate >= 60:
                self.results['production_status'] = 'NEEDS_FIXES'
            else:
                self.results['production_status'] = 'NOT_READY'
            
            self.results['success_rate'] = success_rate
            self.results['test_summary'] = {
                'passed': passed_tests,
                'partial': partial_tests,
                'failed': failed_tests,
                'total': total_tests
            }
        
        return self.results
    
    def print_working_summary(self):
        """Print working test results"""
        logger.info("="*60)
        logger.info("🎯 WORKING DOMAIN REGISTRATION TEST RESULTS")
        logger.info("="*60)
        
        summary = self.results.get('test_summary', {})
        logger.info(f"📊 Success Rate: {self.results.get('success_rate', 0):.1f}%")
        logger.info(f"📈 Tests: {summary.get('passed', 0)} passed, {summary.get('partial', 0)} partial, {summary.get('failed', 0)} failed")
        logger.info(f"🏭 Production Status: {self.results.get('production_status', 'UNKNOWN')}")
        
        # Critical Issues
        critical_issues = [i for i in self.results['issues'] if 'CRITICAL' in i]
        if critical_issues:
            logger.error(f"🚨 CRITICAL ISSUES ({len(critical_issues)}):")
            for issue in critical_issues:
                logger.error(f"  - {issue}")
        
        # All Issues
        if self.results['issues']:
            logger.warning(f"⚠️ ALL ISSUES ({len(self.results['issues'])}):")
            for issue in self.results['issues']:
                logger.warning(f"  - {issue}")
        
        # Test Details
        logger.info("\n📋 DETAILED TEST RESULTS:")
        for test_name, test_result in self.results['tests'].items():
            status_icon = "✅" if test_result['status'] == 'PASSED' else "⚠️" if test_result['status'] == 'PARTIAL' else "❌"
            logger.info(f"{status_icon} {test_name}: {test_result['status']}")
        
        logger.info("="*60)

async def main():
    """Main execution"""
    tester = WorkingDomainTester()
    results = await tester.run_working_tests()
    
    # Save results
    with open('working_domain_test_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    tester.print_working_summary()
    return results

if __name__ == "__main__":
    asyncio.run(main())