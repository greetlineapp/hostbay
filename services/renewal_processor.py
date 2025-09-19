"""
Hosting Renewal Processor Service
Automated wallet-based billing for hosting subscriptions with comprehensive renewal management
"""

import os
import logging
import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple, Any, cast
from decimal import Decimal, ROUND_HALF_UP

# Import database functions
from database import (
    execute_query, execute_update, debit_wallet_balance, get_user_wallet_balance,
    get_user_hosting_subscriptions, get_hosting_subscription_details, 
    get_hosting_plan, update_hosting_subscription_status, get_or_create_user_with_status,
    ensure_financial_operations_allowed, verify_financial_operation_safety, run_db
)

# Import existing utilities
from pricing_utils import format_money, PricingConfig
from message_utils import create_success_message, create_error_message, format_bold, format_inline_code
from brand_config import get_platform_name, get_service_error_message

logger = logging.getLogger(__name__)

class HostingRenewalProcessor:
    """
    Production hosting renewal processor with automated wallet-based billing
    Handles subscription renewals, grace periods, and comprehensive user notifications
    """
    
    def __init__(self):
        self.warning_days_before = int(os.getenv('RENEWAL_WARNING_DAYS', '3'))
        self.batch_size = int(os.getenv('RENEWAL_BATCH_SIZE', '50'))
        self.max_retries = int(os.getenv('RENEWAL_MAX_RETRIES', '3'))
        self.processing_enabled = True
        self.stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'warnings_sent': 0,
            'grace_period': 0,
            'suspended': 0,
            'errors': 0
        }
        
        # Global bot application reference for notifications
        self._bot_application = None
        
        logger.info(f"🔄 HostingRenewalProcessor initialized: plan-specific grace periods (7d→1d, 30d→2d), warning={self.warning_days_before}d ahead")
    
    def get_grace_period_days(self, billing_cycle: str) -> int:
        """Get grace period days based on billing cycle duration"""
        if billing_cycle == '7days':
            return 1  # 7 days plan has only 1 day grace
        elif billing_cycle == '30days':
            return 2  # 30 days plan has 2 days grace
        else:
            # Default grace periods for other cycles
            if billing_cycle in ('monthly', 'yearly'):
                return 7  # Traditional monthly/yearly plans keep 7 days
            else:
                return 2  # Default fallback
    
    def set_bot_application(self, bot_application):
        """Set bot application reference for sending notifications"""
        self._bot_application = bot_application
        logger.info("🤖 Bot application reference set for renewal notifications")
    
    async def process_all_renewals(self) -> Dict[str, Any]:
        """
        Main entry point for processing all hosting renewals
        Designed to be called by APScheduler or manual admin trigger
        """
        if not self.processing_enabled:
            logger.debug("🔇 Renewal processing is disabled")
            return {"status": "disabled", "reason": "Processing disabled"}
        
        try:
            # Security check for financial operations with comprehensive error handling
            try:
                safety_check = verify_financial_operation_safety("hosting_renewal_processing")
                if not safety_check:
                    logger.error("🚫 RENEWAL BLOCKED: Financial operations not allowed")
                    return {"status": "blocked", "reason": "Financial operations blocked"}
            except Exception as safety_error:
                # Handle case where safety check raises exception instead of returning False
                logger.error(f"🚫 RENEWAL BLOCKED: Financial safety check exception: {safety_error}")
                return {"status": "blocked", "reason": f"Financial operations blocked: {str(safety_error)}"}
            
            logger.info("🔄 Starting automated hosting renewal processing...")
            
            # Reset statistics
            self._reset_stats()
            
            # Get subscriptions due for renewal
            subscriptions_to_process = await self._get_subscriptions_for_renewal()
            
            if not subscriptions_to_process:
                logger.info("✅ No hosting subscriptions require renewal processing")
                return {"status": "success", "message": "No renewals needed", "stats": self.stats}
            
            logger.info(f"📊 Found {len(subscriptions_to_process)} subscriptions requiring renewal processing")
            
            # Process renewals in batches
            batch_results = []
            for i in range(0, len(subscriptions_to_process), self.batch_size):
                batch = subscriptions_to_process[i:i + self.batch_size]
                batch_result = await self._process_renewal_batch(batch, i // self.batch_size + 1)
                batch_results.append(batch_result)
                
                # Small delay between batches to prevent overwhelming the system
                if i + self.batch_size < len(subscriptions_to_process):
                    await asyncio.sleep(2)
            
            # Generate final summary
            final_stats = self.stats.copy()
            success_rate = (final_stats['successful'] / final_stats['processed'] * 100) if final_stats['processed'] > 0 else 0
            
            logger.info(f"✅ Renewal processing completed: {final_stats['successful']}/{final_stats['processed']} successful ({success_rate:.1f}%)")
            if final_stats['failed'] > 0:
                logger.warning(f"⚠️ {final_stats['failed']} renewals failed, {final_stats['grace_period']} in grace period")
            
            return {
                "status": "success",
                "stats": final_stats,
                "success_rate": success_rate,
                "batch_results": batch_results
            }
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"❌ Critical error in renewal processing: {e}")
            return {"status": "error", "error": str(e), "stats": self.stats}
    
    async def _get_subscriptions_for_renewal(self) -> List[Dict]:
        """Get all subscriptions that need renewal processing"""
        try:
            # Calculate dates for renewal logic
            now = datetime.now(timezone.utc)
            warning_threshold = now + timedelta(days=self.warning_days_before)
            # Use maximum grace period for query (7 days) to capture all potentially expiring subscriptions
            max_grace_period = 7  # Conservative approach to catch all subscriptions that might need processing
            grace_cutoff = now - timedelta(days=max_grace_period)
            
            query = """
                SELECT hs.*, hp.plan_name, hp.monthly_price, hp.yearly_price,
                       u.telegram_id, u.wallet_balance, u.username, u.first_name
                FROM hosting_subscriptions hs
                JOIN hosting_plans hp ON hs.hosting_plan_id = hp.id
                JOIN users u ON hs.user_id = u.id
                WHERE hs.status IN ('active', 'pending_renewal', 'grace_period')
                  AND (
                    -- Due for renewal (past due or approaching)
                    hs.next_billing_date <= %s
                    -- Warning notifications (approaching renewal)
                    OR (hs.next_billing_date <= %s AND hs.last_warning_sent IS NULL)
                    -- Grace period expiring soon
                    OR (hs.status = 'grace_period' AND hs.grace_period_started <= %s)
                  )
                ORDER BY hs.next_billing_date ASC, hs.status ASC
            """
            
            return await execute_query(query, (now, warning_threshold, grace_cutoff))
            
        except Exception as e:
            logger.error(f"❌ Error fetching subscriptions for renewal: {e}")
            return []
    
    async def _process_renewal_batch(self, batch: List[Dict], batch_number: int) -> Dict[str, Any]:
        """Process a batch of renewals with parallel processing where safe"""
        logger.info(f"🔄 Processing renewal batch {batch_number} ({len(batch)} subscriptions)")
        
        batch_stats = {'processed': 0, 'successful': 0, 'failed': 0, 'warnings': 0}
        
        # Process each subscription in the batch
        for subscription in batch:
            try:
                result = await self.process_subscription_renewal(subscription)
                batch_stats['processed'] += 1
                
                if result['status'] == 'success':
                    batch_stats['successful'] += 1
                elif result['status'] == 'warning_sent':
                    batch_stats['warnings'] += 1
                else:
                    batch_stats['failed'] += 1
                    
                # Small delay between individual subscription processing
                await asyncio.sleep(0.5)
                
            except Exception as e:
                batch_stats['failed'] += 1
                self.stats['errors'] += 1
                logger.error(f"❌ Error processing subscription {subscription.get('id', 'unknown')}: {e}")
        
        logger.info(f"✅ Batch {batch_number} completed: {batch_stats['successful']}/{batch_stats['processed']} successful")
        return batch_stats
    
    async def process_subscription_renewal(self, subscription: Dict) -> Dict[str, Any]:
        """
        Process renewal for a single hosting subscription
        Handles the complete renewal lifecycle including payments and notifications
        """
        subscription_id = subscription['id']
        user_id = subscription['user_id']
        telegram_id = subscription['telegram_id']
        domain_name = subscription.get('domain_name', 'unknown')
        current_status = subscription['status']
        
        try:
            logger.info(f"🔄 Processing renewal for subscription {subscription_id} ({domain_name})")
            
            # Determine what action is needed
            now = datetime.now(timezone.utc)
            next_billing_date = subscription['next_billing_date']
            
            # Convert to timezone-aware datetime if needed
            if next_billing_date.tzinfo is None:
                next_billing_date = next_billing_date.replace(tzinfo=timezone.utc)
            
            renewal_action = self._determine_renewal_action(subscription, now)
            
            if renewal_action == 'warning':
                return await self._send_renewal_warning(subscription)
            elif renewal_action == 'process_renewal':
                return await self._process_subscription_payment(subscription)
            elif renewal_action == 'grace_period_warning':
                return await self._handle_grace_period_warning(subscription)
            elif renewal_action == 'suspend':
                return await self._suspend_expired_subscription(subscription)
            else:
                logger.debug(f"📅 No action needed for subscription {subscription_id}")
                return {'status': 'no_action', 'subscription_id': subscription_id}
                
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"❌ Error processing renewal for subscription {subscription_id}: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    def _determine_renewal_action(self, subscription: Dict, now: datetime) -> str:
        """Determine what renewal action is needed with comprehensive multi-period overdue handling"""
        next_billing_date = subscription['next_billing_date']
        current_status = subscription['status']
        last_warning_sent = subscription.get('last_warning_sent')
        grace_period_started = subscription.get('grace_period_started')
        billing_cycle = subscription.get('billing_cycle', 'monthly')
        
        # Convert to timezone-aware datetime if needed
        if next_billing_date.tzinfo is None:
            next_billing_date = next_billing_date.replace(tzinfo=timezone.utc)
        
        days_until_billing = (next_billing_date - now).days
        
        # Handle multi-period overdue subscriptions (more than one billing cycle behind)
        if next_billing_date < now:
            days_overdue = (now - next_billing_date).days
            
            # Check if subscription is severely overdue (multiple billing periods)
            if billing_cycle == 'monthly' and days_overdue > 60:  # More than 2 months overdue
                logger.warning(f"⚠️ Subscription {subscription['id']} severely overdue: {days_overdue} days ({days_overdue//30} months)")
            elif billing_cycle == 'yearly' and days_overdue > 730:  # More than 2 years overdue
                logger.warning(f"⚠️ Subscription {subscription['id']} severely overdue: {days_overdue} days ({days_overdue//365} years)")
            
            # For severely overdue subscriptions, prioritize renewal processing
            if current_status in ('active', 'pending_renewal'):
                return 'process_renewal'
        
        # Check if renewal warning is needed (only for active subscriptions approaching due date)
        if (days_until_billing <= self.warning_days_before and 
            days_until_billing > 0 and 
            current_status == 'active' and 
            not last_warning_sent):
            return 'warning'
        
        # Check if renewal payment is due or overdue
        if next_billing_date <= now and current_status in ('active', 'pending_renewal'):
            return 'process_renewal'
        
        # Check grace period status with enhanced validation
        if current_status == 'grace_period':
            if grace_period_started:
                if grace_period_started.tzinfo is None:
                    grace_period_started = grace_period_started.replace(tzinfo=timezone.utc)
                
                days_in_grace = (now - grace_period_started).days
                
                # Get plan-specific grace period
                grace_period_days = self.get_grace_period_days(billing_cycle)
                
                # Validate grace period hasn't exceeded maximum allowed time
                if days_in_grace >= grace_period_days:
                    logger.warning(f"😨 Subscription {subscription['id']} grace period expired: {days_in_grace}/{grace_period_days} days (billing cycle: {billing_cycle})")
                    return 'suspend'
                elif days_in_grace >= grace_period_days - 1:  # Warning 1 day before suspension
                    return 'grace_period_warning'
            else:
                # Grace period without start date - this is a data issue
                logger.error(f"❌ Subscription {subscription['id']} in grace_period status but no grace_period_started date")
                # Move to suspend to resolve the inconsistent state
                return 'suspend'
        
        return 'no_action'
    
    async def _process_subscription_payment(self, subscription: Dict) -> Dict[str, Any]:
        """Process the actual renewal payment for a subscription with atomic transactions"""
        subscription_id = subscription['id']
        user_id = subscription['user_id']
        telegram_id = subscription['telegram_id']
        billing_cycle = subscription['billing_cycle']
        domain_name = subscription.get('domain_name', 'unknown')
        
        try:
            # Calculate renewal cost
            renewal_cost = self._calculate_renewal_cost(subscription)
            if renewal_cost <= 0:
                logger.error(f"❌ Invalid renewal cost for subscription {subscription_id}: ${renewal_cost:.2f}")
                return {'status': 'error', 'reason': 'Invalid renewal cost'}
            
            # Generate idempotency key for this renewal attempt
            import hashlib
            import time
            idempotency_data = f"{subscription_id}_{subscription['next_billing_date']}_{renewal_cost}"
            idempotency_key = hashlib.sha256(idempotency_data.encode()).hexdigest()[:32]
            
            # Attempt atomic renewal with comprehensive safety checks
            renewal_result = await self._process_renewal_atomically(
                subscription_id, user_id, renewal_cost, billing_cycle, idempotency_key, domain_name
            )
            
            # Handle result and send appropriate notifications
            if renewal_result['status'] == 'success':
                # Send success notification with fallback logging
                await self._send_renewal_notification_with_fallback(
                    telegram_id, 'success', {
                        'domain_name': domain_name,
                        'amount': renewal_cost,
                        'next_billing_date': renewal_result['next_billing_date'],
                        'billing_cycle': billing_cycle
                    }
                )
                
                self.stats['successful'] += 1
                logger.info(f"✅ Atomic renewal successful for {domain_name}: ${renewal_cost:.2f} charged, next billing {renewal_result['next_billing_date'].date()}")
                
            elif renewal_result['status'] == 'payment_failed':
                # Move to grace period atomically if not already done
                if renewal_result.get('moved_to_grace_period'):
                    # Send failure notification with fallback logging
                    grace_period_days = self.get_grace_period_days(billing_cycle)
                    await self._send_renewal_notification_with_fallback(
                        telegram_id, 'payment_failed', {
                            'domain_name': domain_name,
                            'amount': renewal_cost,
                            'current_balance': renewal_result.get('current_balance', 0),
                            'grace_period_days': grace_period_days
                        }
                    )
                    
                    self.stats['failed'] += 1
                    self.stats['grace_period'] += 1
                    logger.warning(f"💸 Atomic renewal failed for {domain_name}: insufficient funds (needed ${renewal_cost:.2f})")
                else:
                    logger.error(f"❌ Failed to move subscription {subscription_id} to grace period after payment failure")
                    
            return renewal_result
                
        except Exception as e:
            logger.error(f"❌ Critical error processing renewal for subscription {subscription_id}: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    async def _process_renewal_atomically(self, subscription_id: int, user_id: int, renewal_cost: float, 
                                         billing_cycle: str, idempotency_key: str, domain_name: str) -> Dict[str, Any]:
        """
        Process renewal payment and subscription update in a single atomic transaction
        Uses row-level locking and idempotency to prevent race conditions and double-charging
        """
        from database import get_connection, return_connection
        import psycopg2
        
        conn = None
        try:
            # Perform comprehensive financial safety check with amount
            try:
                safety_check = verify_financial_operation_safety("hosting_renewal_deduction", renewal_cost)
                if not safety_check:
                    logger.error(f"🚫 Financial operation blocked for subscription {subscription_id}: safety check failed")
                    return {
                        'status': 'blocked', 
                        'subscription_id': subscription_id, 
                        'reason': 'Financial operations blocked by security system'
                    }
            except Exception as safety_error:
                # Handle case where safety check raises exception instead of returning False
                logger.error(f"🚫 Financial safety check exception for subscription {subscription_id}: {safety_error}")
                return {
                    'status': 'blocked', 
                    'subscription_id': subscription_id, 
                    'reason': f'Financial operations blocked: {str(safety_error)}'
                }
            
            # Get database connection for atomic transaction
            conn = get_connection()
            conn.autocommit = False  # Enable transaction mode
            
            with conn.cursor() as cursor:
                # Step 1: Check for duplicate processing using idempotency key
                cursor.execute(
                    "SELECT id FROM wallet_transactions WHERE description LIKE %s AND status = 'completed'",
                    (f"%renewal%{subscription_id}%{idempotency_key}%",)
                )
                existing_transaction = cursor.fetchone()
                
                if existing_transaction:
                    conn.rollback()
                    logger.warning(f"🔄 Duplicate renewal attempt detected for subscription {subscription_id} - idempotency key: {idempotency_key}")
                    return {
                        'status': 'duplicate',
                        'subscription_id': subscription_id,
                        'reason': 'Renewal already processed for this billing period'
                    }
                
                # Step 2: Lock subscription row to prevent concurrent processing
                cursor.execute(
                    "SELECT next_billing_date, status FROM hosting_subscriptions WHERE id = %s FOR UPDATE",
                    (subscription_id,)
                )
                locked_subscription = cursor.fetchone()
                
                if not locked_subscription:
                    conn.rollback()
                    logger.error(f"❌ Subscription {subscription_id} not found for atomic renewal")
                    return {
                        'status': 'error',
                        'subscription_id': subscription_id,
                        'reason': 'Subscription not found'
                    }
                
                # Step 3: Lock user wallet and check balance
                cursor.execute(
                    "SELECT wallet_balance FROM users WHERE id = %s FOR UPDATE",
                    (user_id,)
                )
                user_wallet = cursor.fetchone()
                
                if not user_wallet:
                    conn.rollback()
                    logger.error(f"❌ User {user_id} not found for atomic renewal")
                    return {
                        'status': 'error',
                        'subscription_id': subscription_id,
                        'reason': 'User not found'
                    }
                
                current_balance = float(cast(Dict[str, Any], user_wallet)['wallet_balance'] or 0.00)
                
                # Step 4: Check sufficient funds
                if current_balance < renewal_cost:
                    logger.warning(f"💸 Insufficient funds for atomic renewal: user {user_id}, subscription {subscription_id}")
                    logger.warning(f"💸 Required: ${renewal_cost:.2f}, Available: ${current_balance:.2f}")
                    
                    # Move to grace period atomically
                    cursor.execute(
                        "UPDATE hosting_subscriptions SET status = 'grace_period', grace_period_started = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (subscription_id,)
                    )
                    
                    # Record failed transaction attempt
                    cursor.execute(
                        "INSERT INTO wallet_transactions (user_id, transaction_type, amount, currency, status, description) VALUES (%s, %s, %s, %s, %s, %s)",
                        (user_id, 'debit', renewal_cost, 'USD', 'failed', f"Failed hosting renewal for {domain_name} (insufficient funds) - {idempotency_key}")
                    )
                    
                    conn.commit()
                    return {
                        'status': 'payment_failed',
                        'subscription_id': subscription_id,
                        'current_balance': current_balance,
                        'amount_needed': renewal_cost,
                        'shortfall': renewal_cost - current_balance,
                        'moved_to_grace_period': True
                    }
                
                # Step 5: Process wallet deduction atomically
                new_balance = current_balance - renewal_cost
                
                cursor.execute(
                    "UPDATE users SET wallet_balance = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (new_balance, user_id)
                )
                
                # Step 6: Record successful transaction
                cursor.execute(
                    "INSERT INTO wallet_transactions (user_id, transaction_type, amount, currency, status, description) VALUES (%s, %s, %s, %s, %s, %s)",
                    (user_id, 'debit', renewal_cost, 'USD', 'completed', f"Hosting renewal for {domain_name} - {idempotency_key}")
                )
                
                # Step 7: Update subscription with new billing date and clear warning flags
                next_billing_date = self.calculate_next_billing_date(
                    cast(Dict[str, Any], locked_subscription)['next_billing_date'], billing_cycle
                )
                
                # Validate the calculated next billing date
                if next_billing_date <= cast(Dict[str, Any], locked_subscription)['next_billing_date']:
                    logger.error(f"❌ Invalid next billing date calculation: {next_billing_date} <= {cast(Dict[str, Any], locked_subscription)['next_billing_date']}")
                    conn.rollback()
                    return {
                        'status': 'error',
                        'subscription_id': subscription_id,
                        'error': 'Invalid billing date calculation'
                    }
                
                cursor.execute(
                    "UPDATE hosting_subscriptions SET next_billing_date = %s, status = 'active', grace_period_started = NULL, last_warning_sent = NULL, last_renewed = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                    (next_billing_date, subscription_id)
                )
                
                # Commit the entire transaction
                conn.commit()
                
                logger.info(f"✅ Atomic renewal completed successfully: subscription {subscription_id}, user {user_id}")
                logger.info(f"💰 Wallet: ${current_balance:.2f} → ${new_balance:.2f} (charged ${renewal_cost:.2f})")
                logger.info(f"📅 Next billing: {next_billing_date.date()}")
                
                return {
                    'status': 'success',
                    'subscription_id': subscription_id,
                    'amount_charged': renewal_cost,
                    'previous_balance': current_balance,
                    'new_balance': new_balance,
                    'next_billing_date': next_billing_date
                }
                
        except psycopg2.Error as db_error:
            if conn:
                conn.rollback()
            logger.error(f"❌ Database error in atomic renewal for subscription {subscription_id}: {db_error}")
            return {
                'status': 'error',
                'subscription_id': subscription_id,
                'error': f'Database error: {str(db_error)}'
            }
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"❌ Critical error in atomic renewal for subscription {subscription_id}: {e}")
            return {
                'status': 'error',
                'subscription_id': subscription_id,
                'error': str(e)
            }
            
        finally:
            if conn:
                conn.autocommit = True  # Restore autocommit
                return_connection(conn)
    
    def _calculate_renewal_cost(self, subscription: Dict) -> float:
        """Calculate the renewal cost for a subscription based on billing cycle"""
        billing_cycle = subscription['billing_cycle']
        monthly_price = float(subscription.get('monthly_price', 0))
        yearly_price = float(subscription.get('yearly_price', 0))
        
        if billing_cycle == 'yearly' and yearly_price > 0:
            return yearly_price
        elif billing_cycle == 'monthly' and monthly_price > 0:
            return monthly_price
        else:
            logger.warning(f"⚠️ Unknown billing cycle or invalid pricing: {billing_cycle}, monthly=${monthly_price}, yearly=${yearly_price}")
            return monthly_price if monthly_price > 0 else 0
    
    def calculate_next_billing_date(self, current_billing_date: datetime, billing_cycle: str) -> datetime:
        """Calculate the next billing date with comprehensive edge case handling"""
        import calendar
        
        # Ensure timezone consistency from the start
        if current_billing_date.tzinfo is None:
            current_billing_date = current_billing_date.replace(tzinfo=timezone.utc)
        
        # Handle different billing cycles with robust edge case protection
        if billing_cycle == 'yearly':
            try:
                # Try direct year increment
                next_date = current_billing_date.replace(year=current_billing_date.year + 1)
            except ValueError:
                # Handle leap year edge case (Feb 29 -> Feb 28)
                if current_billing_date.month == 2 and current_billing_date.day == 29:
                    next_date = current_billing_date.replace(year=current_billing_date.year + 1, day=28)
                    logger.info(f"📅 Leap year adjustment: Feb 29 → Feb 28 for yearly billing")
                else:
                    # Fallback to safe date calculation
                    next_date = current_billing_date.replace(year=current_billing_date.year + 1, day=1) + timedelta(days=current_billing_date.day - 1)
                    
        elif billing_cycle == 'monthly':
            # Calculate next month and year
            next_month = current_billing_date.month + 1
            next_year = current_billing_date.year
            
            if next_month > 12:
                next_month = 1
                next_year += 1
            
            # Handle month-end edge cases (e.g., Jan 31 → Feb 28/29, May 31 → Jun 30)
            try:
                next_date = current_billing_date.replace(year=next_year, month=next_month)
            except ValueError:
                # Get the last valid day of the target month
                last_day = calendar.monthrange(next_year, next_month)[1]
                safe_day = min(current_billing_date.day, last_day)
                next_date = current_billing_date.replace(year=next_year, month=next_month, day=safe_day)
                
                if safe_day != current_billing_date.day:
                    logger.info(f"📅 Month-end adjustment: Day {current_billing_date.day} → Day {safe_day} for {calendar.month_name[next_month]} {next_year}")
        
        elif billing_cycle == '7days':
            # 7-day billing cycle - simple week increment
            next_date = current_billing_date + timedelta(days=7)
        elif billing_cycle == '30days':
            # 30-day billing cycle - simple month increment
            next_date = current_billing_date + timedelta(days=30)
        else:
            # Unknown billing cycle - default to 30-day increment with warning
            logger.warning(f"⚠️ Unknown billing cycle: '{billing_cycle}', using 30-day increment")
            next_date = current_billing_date + timedelta(days=30)
        
        # Ensure timezone consistency
        if next_date.tzinfo is None:
            next_date = next_date.replace(tzinfo=current_billing_date.tzinfo)
        
        # Validation: next date must be in the future
        if next_date <= current_billing_date:
            logger.error(f"❌ Invalid billing date calculation: {next_date} <= {current_billing_date}")
            # Emergency fallback: add appropriate time period
            if billing_cycle == 'yearly':
                next_date = current_billing_date + timedelta(days=365)
            elif billing_cycle == '7days':
                next_date = current_billing_date + timedelta(days=7)
            elif billing_cycle == '30days':
                next_date = current_billing_date + timedelta(days=30)
            else:  # monthly or unknown
                next_date = current_billing_date + timedelta(days=30)
            logger.warning(f"🚫 Emergency fallback: Using {next_date} as next billing date")
        
        return next_date
    
    async def _update_subscription_after_successful_renewal(self, subscription_id: int, next_billing_date: datetime) -> bool:
        """Update subscription after successful renewal"""
        try:
            await execute_update("""
                UPDATE hosting_subscriptions 
                SET next_billing_date = %s, 
                    status = 'active',
                    grace_period_started = NULL,
                    last_renewed = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (next_billing_date, subscription_id))
            
            logger.debug(f"📅 Updated subscription {subscription_id}: next billing {next_billing_date.date()}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error updating subscription after renewal: {e}")
            return False
    
    async def _move_subscription_to_grace_period(self, subscription_id: int) -> bool:
        """Move subscription to grace period after payment failure"""
        try:
            await execute_update("""
                UPDATE hosting_subscriptions 
                SET status = 'grace_period',
                    grace_period_started = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (subscription_id,))
            
            logger.info(f"⏰ Moved subscription {subscription_id} to grace period")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error moving subscription to grace period: {e}")
            return False
    
    async def _send_renewal_warning(self, subscription: Dict) -> Dict[str, Any]:
        """Send renewal warning notification to user"""
        subscription_id = subscription['id']
        telegram_id = subscription['telegram_id']
        domain_name = subscription.get('domain_name', 'unknown')
        next_billing_date = subscription['next_billing_date']
        
        try:
            # Send warning notification
            await self.send_renewal_notification(
                telegram_id, 'warning', {
                    'domain_name': domain_name,
                    'next_billing_date': next_billing_date,
                    'days_remaining': (next_billing_date - datetime.now(timezone.utc)).days,
                    'amount': self._calculate_renewal_cost(subscription)
                }
            )
            
            # Mark warning as sent
            await execute_update("""
                UPDATE hosting_subscriptions 
                SET last_warning_sent = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (subscription_id,))
            
            self.stats['warnings_sent'] += 1
            logger.info(f"⚠️ Renewal warning sent for {domain_name}")
            
            return {'status': 'warning_sent', 'subscription_id': subscription_id}
            
        except Exception as e:
            logger.error(f"❌ Error sending renewal warning: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    async def _handle_grace_period_warning(self, subscription: Dict) -> Dict[str, Any]:
        """Handle grace period warning (near suspension)"""
        subscription_id = subscription['id']
        telegram_id = subscription['telegram_id']
        domain_name = subscription.get('domain_name', 'unknown')
        grace_period_started = subscription.get('grace_period_started')
        billing_cycle = subscription.get('billing_cycle', 'monthly')
        
        try:
            if grace_period_started is None:
                logger.error(f"❌ Grace period started date is None for subscription {subscription_id}")
                return {'status': 'error', 'subscription_id': subscription_id, 'error': 'Grace period start date not available'}
            
            grace_period_days = self.get_grace_period_days(billing_cycle)
            days_remaining = grace_period_days - (datetime.now(timezone.utc) - grace_period_started).days
            
            await self.send_renewal_notification(
                telegram_id, 'grace_period_warning', {
                    'domain_name': domain_name,
                    'days_remaining': max(0, days_remaining),
                    'amount': self._calculate_renewal_cost(subscription)
                }
            )
            
            logger.warning(f"🚨 Grace period warning sent for {domain_name} ({days_remaining} days left)")
            
            return {'status': 'grace_warning_sent', 'subscription_id': subscription_id}
            
        except Exception as e:
            logger.error(f"❌ Error sending grace period warning: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    async def _suspend_expired_subscription(self, subscription: Dict) -> Dict[str, Any]:
        """Suspend subscription after grace period expires"""
        subscription_id = subscription['id']
        telegram_id = subscription['telegram_id']
        domain_name = subscription.get('domain_name', 'unknown')
        
        try:
            # Update subscription status to suspended
            await update_hosting_subscription_status(subscription_id, 'suspended')
            
            # Send suspension notification
            await self.send_renewal_notification(
                telegram_id, 'suspended', {
                    'domain_name': domain_name,
                    'amount': self._calculate_renewal_cost(subscription)
                }
            )
            
            self.stats['suspended'] += 1
            logger.warning(f"🚫 Subscription suspended: {domain_name} (grace period expired)")
            
            return {'status': 'suspended', 'subscription_id': subscription_id}
            
        except Exception as e:
            logger.error(f"❌ Error suspending subscription: {e}")
            return {'status': 'error', 'subscription_id': subscription_id, 'error': str(e)}
    
    async def _send_renewal_notification_with_fallback(self, telegram_id: int, status: str, details: Dict[str, Any]) -> bool:
        """
        Send renewal notification with comprehensive fallback logging
        Ensures critical renewal information is always logged even if notification fails
        """
        domain_name = details.get('domain_name', 'unknown')
        amount = details.get('amount', 0)
        
        # CRITICAL: Always log renewal status regardless of notification success
        log_message = f"🔄 RENEWAL {status.upper()}: Domain={domain_name}, User={telegram_id}, Amount=${amount:.2f}"
        if status == 'success':
            next_billing = details.get('next_billing_date')
            log_message += f", NextBilling={next_billing.date() if next_billing else 'unknown'}"
        elif status == 'payment_failed':
            current_balance = details.get('current_balance', 0)
            log_message += f", CurrentBalance=${current_balance:.2f}, Shortfall=${amount - current_balance:.2f}"
        
        logger.info(log_message)
        
        # Try to send notification, but don't fail if bot is unavailable
        notification_sent = await self.send_renewal_notification(telegram_id, status, details)
        
        if not notification_sent:
            # Fallback logging for failed notifications
            logger.warning(f"📱 NOTIFICATION FAILED: {status} notification for user {telegram_id} domain {domain_name}")
            logger.warning(f"📱 USER ACTION REQUIRED: User {telegram_id} may not be aware of renewal status: {status}")
        
        return notification_sent
    
    async def send_renewal_notification(self, telegram_id: int, status: str, details: Dict[str, Any]) -> bool:
        """
        Send renewal status notification to user
        Integrates with existing bot notification system
        """
        try:
            if not self._bot_application:
                logger.warning("⚠️ Bot application not set - cannot send renewal notifications")
                logger.warning(f"📱 MISSED NOTIFICATION: User {telegram_id} renewal {status} - bot unavailable")
                return False
            
            platform_name = get_platform_name()
            domain_name = details.get('domain_name', 'your hosting')
            
            # Generate appropriate message based on status
            if status == 'success':
                amount = details.get('amount', 0)
                next_billing = details.get('next_billing_date')
                billing_cycle = details.get('billing_cycle', 'monthly')
                
                message = create_success_message(
                    f"🔄 {format_bold('Hosting Renewal Successful')}\n\n"
                    f"• Domain: {format_inline_code(domain_name)}\n"
                    f"• Amount Charged: {format_bold(format_money(amount))}\n"
                    f"• Next Billing: {format_inline_code(next_billing.date().strftime('%Y-%m-%d') if next_billing else 'N/A')}\n"
                    f"• Billing Cycle: {format_inline_code(billing_cycle.title())}\n\n"
                    f"Your hosting service continues without interruption! 🚀"
                )
                
            elif status == 'warning':
                days_remaining = details.get('days_remaining', 0)
                amount = details.get('amount', 0)
                next_billing = details.get('next_billing_date')
                
                message = f"⚠️ {format_bold('Hosting Renewal Reminder')}\n\n" \
                         f"Your hosting for {format_inline_code(domain_name)} will renew in {format_bold(f'{days_remaining} days')}.\n\n" \
                         f"• Renewal Date: {format_inline_code(next_billing.date().strftime('%Y-%m-%d') if next_billing else 'N/A')}\n" \
                         f"• Amount Due: {format_bold(format_money(amount))}\n\n" \
                         f"Please ensure sufficient wallet balance to avoid service interruption.\n\n" \
                         f"💰 Check your balance: /dashboard"
                
            elif status == 'payment_failed':
                amount = details.get('amount', 0)
                current_balance = details.get('current_balance', 0)
                grace_days = details.get('grace_period_days', 7)
                shortfall = amount - current_balance
                
                message = create_error_message(
                    f"💸 {format_bold('Hosting Renewal Failed')}\n\n"
                    f"• Domain: {format_inline_code(domain_name)}\n"
                    f"• Amount Due: {format_bold(format_money(amount))}\n"
                    f"• Current Balance: {format_bold(format_money(current_balance))}\n"
                    f"• Shortfall: {format_bold(format_money(shortfall))}\n\n"
                    f"🛡️ Your hosting has been moved to a {format_bold(f'{grace_days}-day grace period')}.\n"
                    f"Please add funds to your wallet to restore full service.\n\n"
                    f"💰 Add funds: /dashboard → 💳 Add Funds"
                )
                
            elif status == 'grace_period_warning':
                days_remaining = details.get('days_remaining', 0)
                amount = details.get('amount', 0)
                
                message = f"🚨 {format_bold('URGENT: Hosting Suspension Warning')}\n\n" \
                         f"Your hosting for {format_inline_code(domain_name)} will be suspended in {format_bold(f'{days_remaining} days')} due to unpaid renewal.\n\n" \
                         f"• Amount Due: {format_bold(format_money(amount))}\n\n" \
                         f"⚡ Add funds immediately to prevent suspension!\n\n" \
                         f"💰 Add funds: /dashboard → 💳 Add Funds"
                
            elif status == 'suspended':
                amount = details.get('amount', 0)
                
                message = create_error_message(
                    f"🚫 {format_bold('Hosting Service Suspended')}\n\n"
                    f"Your hosting for {format_inline_code(domain_name)} has been suspended due to unpaid renewal.\n\n"
                    f"• Amount Due: {format_bold(format_money(amount))}\n\n"
                    f"💡 To restore service:\n"
                    f"1. Add {format_bold(format_money(amount))} to your wallet\n"
                    f"2. Contact support to reactivate\n\n"
                    f"💰 Add funds: /dashboard → 💳 Add Funds"
                )
                
            else:
                logger.warning(f"⚠️ Unknown renewal notification status: {status}")
                return False
            
            # Send the message using bot application
            await self._bot_application.bot.send_message(
                chat_id=telegram_id,
                text=message,
                parse_mode='HTML',
                disable_web_page_preview=True
            )
            
            logger.debug(f"📱 Renewal notification sent to user {telegram_id}: {status}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error sending renewal notification to {telegram_id}: {e}")
            return False
    
    def _reset_stats(self):
        """Reset processing statistics"""
        self.stats = {
            'processed': 0,
            'successful': 0,
            'failed': 0,
            'warnings_sent': 0,
            'grace_period': 0,
            'suspended': 0,
            'errors': 0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current processing statistics"""
        return self.stats.copy()
    
    async def process_manual_renewal(self, subscription_id: int, user_id: int) -> Dict[str, Any]:
        """
        Manually process renewal for a specific subscription
        Used for admin operations or user-triggered renewals
        """
        try:
            # Get subscription details
            subscription = await get_hosting_subscription_details(subscription_id, user_id)
            if not subscription:
                return {'status': 'error', 'reason': 'Subscription not found'}
            
            # Add user details for processing
            user_query = await execute_query(
                "SELECT telegram_id, wallet_balance, username, first_name FROM users WHERE id = %s",
                (user_id,)
            )
            if user_query:
                subscription.update(user_query[0])
            
            logger.info(f"🔧 Manual renewal requested for subscription {subscription_id}")
            
            # Process the renewal
            result = await self.process_subscription_renewal(subscription)
            
            # Log manual renewal attempt
            if result['status'] == 'success':
                logger.info(f"✅ Manual renewal successful for subscription {subscription_id}")
            else:
                logger.warning(f"⚠️ Manual renewal failed for subscription {subscription_id}: {result.get('reason', 'unknown')}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Error in manual renewal for subscription {subscription_id}: {e}")
            return {'status': 'error', 'reason': str(e)}

# Create global instance
renewal_processor = HostingRenewalProcessor()

# Convenience functions for external usage
async def process_all_hosting_renewals() -> Dict[str, Any]:
    """Process all hosting renewals - main entry point for scheduler"""
    return await renewal_processor.process_all_renewals()

async def process_manual_hosting_renewal(subscription_id: int, user_id: int) -> Dict[str, Any]:
    """Process manual renewal for specific subscription"""
    return await renewal_processor.process_manual_renewal(subscription_id, user_id)

def set_renewal_bot_application(bot_application):
    """Set bot application reference for notifications"""
    renewal_processor.set_bot_application(bot_application)

def get_renewal_processor_stats() -> Dict[str, Any]:
    """Get current renewal processor statistics"""
    return renewal_processor.get_stats()