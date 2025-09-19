"""
Hosting Account Status Monitoring System
Provides real-time monitoring and health checks for hosting accounts using APScheduler
"""

import logging
import asyncio
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from database import execute_query, execute_update, get_user_hosting_subscriptions
from services.cpanel import CPanelService
from health_monitor import get_health_monitor

logger = logging.getLogger(__name__)

class HostingMonitor:
    """Production hosting account monitoring and status synchronization"""
    
    def __init__(self):
        self.cpanel = CPanelService()
        self.last_full_scan = time.time()  # FIX: Initialize to current time instead of 0
        self.monitoring_enabled = True
        self.scan_interval = 300  # 5 minutes between full scans
        self.quick_check_interval = 60  # 1 minute between quick checks
        self.error_count = 0
        self.max_errors = 10  # Disable monitoring after too many errors
        
    async def monitor_hosting_status(self) -> Dict[str, Any]:
        """Main monitoring function - checks all active hosting accounts"""
        if not self.monitoring_enabled:
            logger.debug("🔇 Hosting monitoring is disabled")
            return {"status": "disabled", "accounts_checked": 0}
        
        try:
            logger.info("🔍 Starting hosting accounts status check...")
            
            # Get all active hosting subscriptions
            active_subscriptions = await self._get_active_hosting_subscriptions()
            
            if not active_subscriptions:
                logger.info("ℹ️ No active hosting subscriptions found")
                return {"status": "success", "accounts_checked": 0}
            
            logger.info(f"📊 Found {len(active_subscriptions)} active hosting accounts to monitor")
            
            # Monitor each account
            results = {
                "total_accounts": len(active_subscriptions),
                "success_count": 0,
                "error_count": 0,
                "status_changes": 0,
                "accounts_checked": 0
            }
            
            for subscription in active_subscriptions:
                try:
                    check_result = await self._check_account_status(subscription)
                    results["accounts_checked"] += 1
                    
                    if check_result["success"]:
                        results["success_count"] += 1
                        if check_result.get("status_changed"):
                            results["status_changes"] += 1
                    else:
                        results["error_count"] += 1
                        
                    # Small delay between checks to avoid overwhelming the API
                    await asyncio.sleep(1)
                    
                except Exception as account_error:
                    logger.error(f"❌ Error checking account {subscription.get('id', 'unknown')}: {account_error}")
                    results["error_count"] += 1
            
            # Update monitoring statistics
            self.last_full_scan = time.time()
            self.error_count = 0  # Reset error count on successful scan
            
            # Log summary
            logger.info(f"✅ Hosting monitoring completed: {results['success_count']}/{results['total_accounts']} accounts checked successfully")
            if results["status_changes"] > 0:
                logger.info(f"🔄 {results['status_changes']} hosting account status changes detected")
            
            return {"status": "success", **results}
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"❌ Hosting monitoring error: {e}")
            
            # Disable monitoring if too many errors
            if self.error_count >= self.max_errors:
                self.monitoring_enabled = False
                logger.error(f"🚫 Hosting monitoring disabled after {self.max_errors} consecutive errors")
                get_health_monitor().update_error_count(f"Hosting monitoring disabled: {e}")
            
            return {"status": "error", "error": str(e), "accounts_checked": 0}
    
    async def _get_active_hosting_subscriptions(self) -> List[Dict]:
        """Get all active hosting subscriptions that need monitoring"""
        try:
            query = """
                SELECT hs.id, hs.user_id, hs.domain_name, hs.status, hs.updated_at,
                       ca.cpanel_username, ca.status as cpanel_status
                FROM hosting_subscriptions hs
                LEFT JOIN cpanel_accounts ca ON hs.id = ca.subscription_id
                WHERE hs.status IN ('active', 'suspended', 'pending')
                  AND ca.cpanel_username IS NOT NULL
                ORDER BY hs.updated_at ASC
            """
            
            return await execute_query(query)
            
        except Exception as e:
            logger.error(f"❌ Error fetching hosting subscriptions for monitoring: {e}")
            return []
    
    async def _check_account_status(self, subscription: Dict) -> Dict[str, Any]:
        """Check status of a single hosting account"""
        subscription_id = subscription['id']
        cpanel_username = subscription['cpanel_username']
        current_status = subscription['status']
        domain_name = subscription.get('domain_name', 'unknown')
        
        try:
            # Get live status from cPanel
            live_status_result = await self.cpanel.check_account_status(cpanel_username)
            
            if not live_status_result:
                logger.warning(f"⚠️ Could not get live status for {domain_name} (username: {cpanel_username})")
                return {"success": False, "error": "No status response from cPanel"}
            
            live_status = live_status_result.get('status', 'unknown')
            
            # Compare with database status
            status_changed = False
            if live_status != current_status and live_status != 'unknown':
                logger.info(f"🔄 Status change detected for {domain_name}: {current_status} → {live_status}")
                
                # Update database status
                await self._update_subscription_status(subscription_id, live_status)
                status_changed = True
                
                # Update health monitor
                get_health_monitor().log_info(f"Hosting status sync: {domain_name} {current_status}→{live_status}")
            
            logger.debug(f"✅ Checked {domain_name}: {live_status} (was: {current_status})")
            
            return {
                "success": True,
                "subscription_id": subscription_id,
                "domain": domain_name,
                "old_status": current_status,
                "new_status": live_status,
                "status_changed": status_changed,
                "details": live_status_result.get('details', {})
            }
            
        except Exception as e:
            logger.error(f"❌ Error checking status for {domain_name}: {e}")
            return {"success": False, "error": str(e)}
    
    async def _update_subscription_status(self, subscription_id: int, new_status: str) -> bool:
        """Update hosting subscription status in database"""
        try:
            await execute_update(
                "UPDATE hosting_subscriptions SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                (new_status, subscription_id)
            )
            
            # Also update cPanel account status if exists
            await execute_update(
                "UPDATE cpanel_accounts SET status = %s, updated_at = CURRENT_TIMESTAMP WHERE subscription_id = %s",
                (new_status, subscription_id)
            )
            
            logger.info(f"✅ Updated subscription {subscription_id} status to: {new_status}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error updating subscription {subscription_id} status: {e}")
            return False
    
    async def quick_health_check(self) -> Dict[str, Any]:
        """Quick health check for hosting monitoring system"""
        try:
            # Check if monitoring is enabled
            if not self.monitoring_enabled:
                return {"status": "disabled", "reason": "Too many errors"}
            
            # Check last scan time with validation
            current_time = time.time()
            
            # FIX: Validate timestamp and handle edge cases
            if self.last_full_scan <= 0 or self.last_full_scan > current_time:
                # Invalid timestamp - reset to current time and return healthy status
                self.last_full_scan = current_time
                logger.warning("⚠️ Invalid last_full_scan timestamp detected - resetting to current time")
                return {
                    "status": "healthy",
                    "health": "good",
                    "last_scan_minutes_ago": 0.0,
                    "error_count": self.error_count,
                    "monitoring_enabled": self.monitoring_enabled,
                    "note": "Timestamp reset due to invalid value"
                }
            
            time_since_scan = current_time - self.last_full_scan
            scan_age_minutes = time_since_scan / 60
            
            # Check if scan is overdue
            if scan_age_minutes > 10:  # More than 10 minutes
                status = "overdue"
                health = "warning"
            elif scan_age_minutes > 20:  # More than 20 minutes
                status = "stale"
                health = "critical"
            else:
                status = "healthy"
                health = "good"
            
            return {
                "status": status,
                "health": health,
                "last_scan_minutes_ago": round(scan_age_minutes, 1),
                "error_count": self.error_count,
                "monitoring_enabled": self.monitoring_enabled
            }
            
        except Exception as e:
            logger.error(f"❌ Hosting monitor health check error: {e}")
            return {"status": "error", "error": str(e)}
    
    def enable_monitoring(self):
        """Enable hosting monitoring"""
        self.monitoring_enabled = True
        self.error_count = 0
        logger.info("✅ Hosting monitoring enabled")
    
    def disable_monitoring(self):
        """Disable hosting monitoring"""
        self.monitoring_enabled = False
        logger.warning("🔇 Hosting monitoring disabled")
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        return {
            "enabled": self.monitoring_enabled,
            "last_scan_timestamp": self.last_full_scan,
            "error_count": self.error_count,
            "max_errors": self.max_errors,
            "scan_interval": self.scan_interval,
            "quick_check_interval": self.quick_check_interval
        }

# Global hosting monitor instance
_hosting_monitor = None

def get_hosting_monitor() -> HostingMonitor:
    """Get or create global hosting monitor instance"""
    global _hosting_monitor
    if _hosting_monitor is None:
        _hosting_monitor = HostingMonitor()
        logger.info("✅ Hosting monitor instance created")
    return _hosting_monitor

async def run_hosting_status_check():
    """Scheduled function to run hosting status checks"""
    monitor = get_hosting_monitor()
    return await monitor.monitor_hosting_status()

async def run_quick_hosting_check():
    """Scheduled function for quick hosting health checks"""
    monitor = get_hosting_monitor()
    return await monitor.quick_health_check()

def get_hosting_monitoring_stats() -> Dict[str, Any]:
    """Get hosting monitoring statistics for admin/debug purposes"""
    monitor = get_hosting_monitor()
    return monitor.get_monitoring_stats()

def enable_hosting_monitoring():
    """Enable hosting monitoring"""
    monitor = get_hosting_monitor()
    monitor.enable_monitoring()

def disable_hosting_monitoring():
    """Disable hosting monitoring"""
    monitor = get_hosting_monitor()
    monitor.disable_monitoring()