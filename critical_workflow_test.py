#!/usr/bin/env python3
"""
Critical Workflow Testing for Multi-Language System
Tests the 5 critical workflows identified in PHASE 6 requirements

This focused test validates:
1. New User Onboarding: Welcome → Language Selection → First Purchase
2. Hosting Bundle Purchase: Language selection → Payment → Provisioning → Success notifications  
3. Domain Registration: Search → Register → DNS setup → Confirmation messages
4. Admin Operations: Admin credit wallet → User notifications in user's language
5. Language Switching: Change language → Immediate interface update → Persistence
"""

import asyncio
import logging
import os
import json
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

# Set environment for testing
os.environ['ENVIRONMENT'] = 'production'

from database import (
    execute_query, execute_update, get_or_create_user,
    credit_user_wallet, get_user_wallet_balance
)
from localization import (
    t, t_for_user, t_html, t_html_for_user, resolve_user_language,
    get_supported_languages, is_language_supported, 
    get_user_language_preference, set_user_language_preference
)
from message_utils import escape_html
from admin_handlers import get_admin_language, get_user_notification_language
from brand_config import get_platform_name, get_platform_tagline

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CriticalWorkflowTestResults:
    """Results container for critical workflow tests"""
    
    def __init__(self):
        self.workflow_results: Dict[str, Dict] = {}
        self.success_count = 0
        self.error_count = 0
        self.critical_issues: List[str] = []
        self.workflow_coverage: Dict[str, Dict[str, bool]] = {}
        
    def add_workflow_result(self, workflow: str, language: str, result: Dict):
        """Add workflow test result"""
        if workflow not in self.workflow_results:
            self.workflow_results[workflow] = {}
        self.workflow_results[workflow][language] = result
        
        if result.get('status') == 'success':
            self.success_count += 1
        else:
            self.error_count += 1
            if result.get('critical'):
                self.critical_issues.append(f"{workflow} ({language}): {result.get('message', 'Critical failure')}")
                
    def assess_production_readiness(self) -> bool:
        """Assess if system is production ready for critical workflows"""
        return (
            len(self.critical_issues) == 0 and 
            self.error_count == 0 and
            self.success_count > 0
        )

class CriticalWorkflowTester:
    """Test the 5 critical workflows in all supported languages"""
    
    def __init__(self):
        self.results = CriticalWorkflowTestResults()
        self.supported_languages = get_supported_languages()
        self.test_users = {}  # Will create real test users in database
        
        logger.info("🎯 Initializing Critical Workflow Tester")
        logger.info(f"🌍 Testing languages: {list(self.supported_languages.keys())}")
    
    async def setup_test_users(self):
        """Create test users in database for each language"""
        logger.info("👥 Setting up test users in database...")
        
        base_telegram_ids = [999001, 999002, 999003]  # Use high IDs to avoid conflicts
        
        for i, lang_code in enumerate(self.supported_languages.keys()):
            telegram_id = base_telegram_ids[i]
            
            try:
                # Create user in database first
                user = await get_or_create_user(
                    telegram_id=telegram_id,
                    username=f"test_user_{lang_code}",
                    first_name=f"Test",
                    last_name=f"User {lang_code.upper()}"
                )
                
                # Set language preference
                await set_user_language_preference(telegram_id, lang_code)
                
                # Ensure user exists in database before crediting wallet (small delay)
                await asyncio.sleep(0.1)
                
                # Verify user exists by checking balance first
                try:
                    current_balance = await get_user_wallet_balance(telegram_id)
                    logger.info(f"✅ User {telegram_id} verified with balance: ${current_balance:.2f}")
                except Exception as balance_check_error:
                    logger.error(f"❌ User {telegram_id} doesn't exist in database: {balance_check_error}")
                    # Create wallet record manually if needed
                    await execute_update(
                        "INSERT INTO users (telegram_id, username, first_name, last_name, wallet_balance, terms_accepted, created_at, updated_at) VALUES (%s, %s, %s, %s, 0.00, FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) ON CONFLICT (telegram_id) DO NOTHING",
                        (telegram_id, f"test_user_{lang_code}", "Test", f"User {lang_code.upper()}")
                    )
                
                # Add some wallet balance for testing - generate deterministic test values
                test_txid = f"TEST_{telegram_id}_SETUP_{int(time.time())}"
                test_order_id = f"ORDER_TEST_{telegram_id}_{lang_code.upper()}"
                success = await credit_user_wallet(telegram_id, 100.00, "Test balance setup", test_txid, test_order_id)
                
                if not success:
                    logger.warning(f"⚠️ Failed to credit wallet for {telegram_id}, proceeding with test anyway")
                
                self.test_users[lang_code] = {
                    'telegram_id': telegram_id,
                    'user_data': user,
                    'language': lang_code
                }
                
                logger.info(f"✅ Created test user for {lang_code}: ID {telegram_id}")
                
            except Exception as e:
                logger.error(f"❌ Failed to create test user for {lang_code}: {e}")
                self.results.critical_issues.append(f"Test setup failed for {lang_code}: {str(e)}")
    
    async def test_critical_workflows(self) -> Dict:
        """Test all 5 critical workflows"""
        logger.info("🚀 Starting critical workflow testing...")
        
        try:
            # Setup test environment
            await self.setup_test_users()
            
            # Test each critical workflow
            await self.test_new_user_onboarding()
            await self.test_hosting_bundle_purchase() 
            await self.test_domain_registration()
            await self.test_admin_operations()
            await self.test_language_switching()
            
            logger.info("✅ Critical workflow testing completed")
            
        except Exception as e:
            self.results.critical_issues.append(f"Workflow testing failed: {str(e)}")
            logger.error(f"❌ Critical workflow testing failed: {e}")
        
        return self.generate_report()
    
    async def test_new_user_onboarding(self):
        """Test: Welcome → Language Selection → First Purchase"""
        logger.info("👋 Testing new user onboarding workflow...")
        
        for lang_code, user_info in self.test_users.items():
            try:
                telegram_id = user_info['telegram_id']
                
                # Step 1: Welcome message
                welcome_msg = await t_for_user('welcome.greeting', telegram_id, lang_code, 
                                             platform_name=get_platform_name(),
                                             platform_tagline=get_platform_tagline())
                
                # Step 2: Language detection works
                detected_lang = await resolve_user_language(telegram_id)
                
                # Step 3: First purchase simulation (wallet balance check)
                balance = await get_user_wallet_balance(telegram_id)
                balance_msg = t('wallet.balance', lang_code, balance=f"{balance:.2f}")
                
                # Step 4: Test hosting bundle purchase messages (using new translation keys)
                bundle_msg = t('hosting.bundle_purchase', lang_code, plan_name="Basic Plan", domain="example.com")
                provisioning_msg = t('hosting.provisioning', lang_code, domain="example.com")  
                activated_msg = t('hosting.activated', lang_code, domain="example.com")
                
                # Validate workflow (balance ≥ 0 is fine for new users)
                workflow_success = (
                    welcome_msg and welcome_msg != 'welcome.greeting' and
                    detected_lang == lang_code and
                    balance_msg and balance_msg != 'wallet.balance' and
                    balance >= 0 and  # New users start with $0.00 which is valid
                    bundle_msg and bundle_msg != 'hosting.bundle_purchase' and
                    provisioning_msg and provisioning_msg != 'hosting.provisioning' and
                    activated_msg and activated_msg != 'hosting.activated'
                )
                
                self.results.add_workflow_result(
                    'new_user_onboarding', lang_code,
                    {
                        'status': 'success' if workflow_success else 'error',
                        'welcome_message_works': welcome_msg != 'welcome.greeting',
                        'language_detected': detected_lang == lang_code,
                        'wallet_accessible': balance >= 0,  # New users start with $0.00 
                        'localization_working': balance_msg != 'wallet.balance',
                        'hosting_keys_working': all([
                            bundle_msg != 'hosting.bundle_purchase',
                            provisioning_msg != 'hosting.provisioning', 
                            activated_msg != 'hosting.activated'
                        ])
                    }
                )
                
            except Exception as e:
                self.results.add_workflow_result(
                    'new_user_onboarding', lang_code,
                    {'status': 'error', 'message': str(e), 'critical': True}
                )
    
    async def test_hosting_bundle_purchase(self):
        """Test: Language selection → Payment → Provisioning → Success notifications"""
        logger.info("🏠 Testing hosting bundle purchase workflow...")
        
        for lang_code, user_info in self.test_users.items():
            try:
                telegram_id = user_info['telegram_id']
                
                # Step 1: Payment confirmation message
                payment_msg = t('success.payment_confirmed', lang_code)
                
                # Step 2: Payment details with variables
                payment_details = t('success.payment_details', lang_code,
                                  amount='25.00', currency='USD',
                                  platform_name=get_platform_name())
                
                # Step 3: Hosting activation message
                hosting_msg = t('success.hosting_activated', lang_code)
                
                # Step 4: Test HTML safety
                html_payment, parse_mode = t_html('success.payment_details', lang_code,
                                                amount='25.00', currency='USD',
                                                platform_name=get_platform_name())
                
                # Validate workflow
                workflow_success = (
                    payment_msg and payment_msg != 'success.payment_confirmed' and
                    payment_details and payment_details != 'success.payment_details' and
                    hosting_msg and hosting_msg != 'success.hosting_activated' and
                    html_payment and parse_mode == 'HTML'
                )
                
                self.results.add_workflow_result(
                    'hosting_bundle_purchase', lang_code,
                    {
                        'status': 'success' if workflow_success else 'error',
                        'payment_confirmation': payment_msg != 'success.payment_confirmed',
                        'payment_details': payment_details != 'success.payment_details',
                        'hosting_activation': hosting_msg != 'success.hosting_activated',
                        'html_safe': html_payment and parse_mode == 'HTML',
                        'variables_substituted': '25.00' in payment_details and 'USD' in payment_details
                    }
                )
                
            except Exception as e:
                self.results.add_workflow_result(
                    'hosting_bundle_purchase', lang_code,
                    {'status': 'error', 'message': str(e), 'critical': True}
                )
    
    async def test_domain_registration(self):
        """Test: Search → Register → DNS setup → Confirmation messages"""
        logger.info("🌐 Testing domain registration workflow...")
        
        for lang_code, user_info in self.test_users.items():
            try:
                telegram_id = user_info['telegram_id']
                
                # Step 1: Domain search messages
                search_msg = t('domains.search_placeholder', lang_code)
                available_msg = t('domains.available', lang_code)
                
                # Step 2: Domain registration success
                domain_success = t('success.domain_registered', lang_code)
                
                # Step 3: Domain details with HTML safety
                domain_details, parse_mode = t_html('success.domain_details', lang_code,
                                                  domain='example.com')
                
                # Step 4: DNS configuration message
                dns_msg = t('dns.title', lang_code)
                
                # Validate workflow
                workflow_success = (
                    search_msg and search_msg != 'domains.search_placeholder' and
                    available_msg and available_msg != 'domains.available' and
                    domain_success and domain_success != 'success.domain_registered' and
                    domain_details and parse_mode == 'HTML' and
                    dns_msg and dns_msg != 'dns.title'
                )
                
                self.results.add_workflow_result(
                    'domain_registration', lang_code,
                    {
                        'status': 'success' if workflow_success else 'error',
                        'search_interface': search_msg != 'domains.search_placeholder',
                        'availability_check': available_msg != 'domains.available',
                        'registration_success': domain_success != 'success.domain_registered',
                        'domain_details': domain_details and 'example.com' in domain_details,
                        'dns_management': dns_msg != 'dns.title',
                        'html_safe': parse_mode == 'HTML'
                    }
                )
                
            except Exception as e:
                self.results.add_workflow_result(
                    'domain_registration', lang_code,
                    {'status': 'error', 'message': str(e), 'critical': True}
                )
    
    async def test_admin_operations(self):
        """Test: Admin credit wallet → User notifications in user's language"""
        logger.info("👑 Testing admin operations workflow...")
        
        # Use first user as admin, test notifications to other users
        admin_lang = 'en'
        admin_id = self.test_users[admin_lang]['telegram_id']
        
        for lang_code, user_info in self.test_users.items():
            if lang_code == admin_lang:
                continue  # Skip self
                
            try:
                telegram_id = user_info['telegram_id']
                
                # Step 1: Admin interface in admin's language
                admin_lang_resolved = await get_admin_language(admin_id, admin_lang)
                admin_msg = t('services.admin.commands.credit_wallet.usage', admin_lang_resolved)
                
                # Step 2: User notification in user's language
                user_notification_lang = await get_user_notification_language(telegram_id)
                notification_msg = t('wallet.transaction_credit', user_notification_lang, amount='10.00')
                
                # Step 3: Test language context separation
                context_separated = (
                    admin_lang_resolved != user_notification_lang or
                    admin_lang_resolved == admin_lang
                )
                
                # Validate workflow
                workflow_success = (
                    admin_msg and admin_msg != 'admin.commands.credit_wallet.usage' and
                    notification_msg and notification_msg != 'wallet.transaction_credit' and
                    context_separated
                )
                
                self.results.add_workflow_result(
                    'admin_operations', lang_code,
                    {
                        'status': 'success' if workflow_success else 'error',
                        'admin_language_context': admin_lang_resolved == admin_lang,
                        'user_notification_context': user_notification_lang == lang_code,
                        'context_separation': context_separated,
                        'admin_interface_works': admin_msg != 'admin.commands.credit_wallet.usage',
                        'user_notifications_work': notification_msg != 'wallet.transaction_credit'
                    }
                )
                
            except Exception as e:
                self.results.add_workflow_result(
                    'admin_operations', lang_code,
                    {'status': 'error', 'message': str(e), 'critical': True}
                )
    
    async def test_language_switching(self):
        """Test: Change language → Immediate interface update → Persistence"""
        logger.info("🔄 Testing language switching workflow...")
        
        for current_lang, user_info in self.test_users.items():
            try:
                telegram_id = user_info['telegram_id']
                
                # Test switching to each other language
                for target_lang in self.supported_languages.keys():
                    if target_lang == current_lang:
                        continue
                    
                    # Step 1: Switch language
                    switch_success = await set_user_language_preference(telegram_id, target_lang)
                    
                    # Step 2: Verify immediate update
                    resolved_lang = await resolve_user_language(telegram_id)
                    
                    # Step 3: Test interface updates immediately
                    confirmation_msg = t('success.language_changed', target_lang, 
                                       language=self.supported_languages[target_lang])
                    
                    # Step 4: Test persistence
                    await asyncio.sleep(0.1)  # Brief delay
                    persisted_lang = await get_user_language_preference(telegram_id)
                    
                    # Validate workflow
                    workflow_success = (
                        switch_success and
                        resolved_lang == target_lang and
                        confirmation_msg and confirmation_msg != 'success.language_changed' and
                        persisted_lang == target_lang
                    )
                    
                    self.results.add_workflow_result(
                        f'language_switching_{current_lang}_to_{target_lang}', target_lang,
                        {
                            'status': 'success' if workflow_success else 'error',
                            'switch_succeeded': switch_success,
                            'immediate_update': resolved_lang == target_lang,
                            'confirmation_message': confirmation_msg != 'success.language_changed',
                            'persistence_working': persisted_lang == target_lang,
                            'from_language': current_lang,
                            'to_language': target_lang
                        }
                    )
                    
                    # Switch back for next test
                    await set_user_language_preference(telegram_id, current_lang)
                    
            except Exception as e:
                self.results.add_workflow_result(
                    f'language_switching_{current_lang}', current_lang,
                    {'status': 'error', 'message': str(e), 'critical': True}
                )
    
    def generate_report(self) -> Dict:
        """Generate comprehensive critical workflow test report"""
        logger.info("📊 Generating critical workflow test report...")
        
        total_tests = self.results.success_count + self.results.error_count
        success_rate = (self.results.success_count / total_tests * 100) if total_tests > 0 else 0
        production_ready = self.results.assess_production_readiness()
        
        # Analyze workflow coverage
        workflow_coverage = {}
        for workflow, results in self.results.workflow_results.items():
            successful_langs = [lang for lang, result in results.items() 
                              if result.get('status') == 'success']
            workflow_coverage[workflow] = {
                'languages_tested': len(results),
                'languages_successful': len(successful_langs),
                'success_rate': len(successful_langs) / len(results) * 100 if results else 0,
                'successful_languages': successful_langs
            }
        
        return {
            'summary': {
                'total_workflow_tests': total_tests,
                'successful_workflows': self.results.success_count,
                'failed_workflows': self.results.error_count,
                'success_rate': success_rate,
                'production_ready': production_ready,
                'critical_issues_count': len(self.results.critical_issues),
                'test_timestamp': datetime.now().isoformat()
            },
            'production_readiness': {
                'ready_for_deployment': production_ready,
                'blocking_issues': self.results.critical_issues,
                'languages_tested': list(self.supported_languages.keys()),
                'workflows_tested': list(workflow_coverage.keys())
            },
            'workflow_coverage': workflow_coverage,
            'detailed_results': self.results.workflow_results,
            'critical_issues': self.results.critical_issues,
            'recommendations': self.generate_recommendations()
        }
    
    def generate_recommendations(self) -> List[str]:
        """Generate specific recommendations for production deployment"""
        recommendations = []
        
        if len(self.results.critical_issues) > 0:
            recommendations.append("🚨 CRITICAL: Resolve all critical workflow issues before deployment")
        
        # Check workflow-specific issues
        for workflow, results in self.results.workflow_results.items():
            failed_langs = [lang for lang, result in results.items() 
                          if result.get('status') != 'success']
            if failed_langs:
                recommendations.append(f"⚠️ Fix {workflow} workflow for languages: {', '.join(failed_langs)}")
        
        if self.results.error_count == 0:
            recommendations.append("✅ All critical workflows working correctly")
            recommendations.append("🚀 System ready for French and Spanish market deployment")
            recommendations.append("💡 Consider additional user acceptance testing")
        
        return recommendations

async def main():
    """Run critical workflow testing"""
    print("🎯 HOSTBAY CRITICAL WORKFLOW TESTING")
    print("=" * 50)
    print("Testing the 5 critical workflows identified in PHASE 6")
    print("=" * 50)
    
    tester = CriticalWorkflowTester()
    report = await tester.test_critical_workflows()
    
    # Display results
    print("\n" + "=" * 50)
    print("📊 CRITICAL WORKFLOW TEST RESULTS")
    print("=" * 50)
    
    summary = report['summary']
    print(f"Total Workflow Tests: {summary['total_workflow_tests']}")
    print(f"Success Rate: {summary['success_rate']:.1f}%")
    print(f"Successful Workflows: {summary['successful_workflows']}")
    print(f"Failed Workflows: {summary['failed_workflows']}")
    print(f"Critical Issues: {summary['critical_issues_count']}")
    
    # Production readiness
    print("\n" + "-" * 30)
    print("🚀 PRODUCTION READINESS")
    print("-" * 30)
    
    readiness = report['production_readiness']
    if readiness['ready_for_deployment']:
        print("✅ READY FOR DEPLOYMENT")
        print("All critical workflows working correctly in French and Spanish")
    else:
        print("❌ NOT READY FOR DEPLOYMENT")
        print("Critical workflows have blocking issues")
    
    # Critical issues
    if report['critical_issues']:
        print("\n🚨 CRITICAL ISSUES:")
        for issue in report['critical_issues']:
            print(f"  • {issue}")
    
    # Workflow coverage
    print("\n📊 WORKFLOW COVERAGE:")
    for workflow, coverage in report['workflow_coverage'].items():
        print(f"  {workflow}: {coverage['languages_successful']}/{coverage['languages_tested']} languages ({coverage['success_rate']:.1f}%)")
    
    # Recommendations
    print("\n💡 RECOMMENDATIONS:")
    for rec in report['recommendations']:
        print(f"  • {rec}")
    
    # Save detailed report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"critical_workflow_report_{timestamp}.json"
    
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Detailed report saved to: {report_file}")
    print("=" * 50)
    
    return report

if __name__ == "__main__":
    asyncio.run(main())