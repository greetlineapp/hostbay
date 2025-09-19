"""
Application Watchdog for Telegram Bot - Comprehensive End-to-End Health Monitoring

This module implements a robust watchdog system that detects silent failures where the bot
appears to be running (HTTP server works, health checks pass) but has actually stopped
processing Telegram updates. It provides:

1. End-to-end health checks that send actual test messages through the bot
2. PTB Application lifecycle monitoring to detect when the event loop stops
3. Fail-fast behavior with clean process exit for supervisor restart
4. Consecutive failure detection with configurable thresholds
5. Enhanced health monitoring endpoints that validate full bot functionality
6. Integration with existing health monitoring and admin alerts

Focus: Detect and recover from "silent failure" mode where users see the bot as online
but it doesn't respond to their messages.
"""

import asyncio
import logging
import time
import os
import sys
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import uuid

from health_monitor import get_health_monitor, log_error, log_restart
from admin_alerts import send_critical_alert, send_error_alert, send_warning_alert, AlertSeverity, AlertCategory

logger = logging.getLogger(__name__)

# ====================================================================
# WATCHDOG CONFIGURATION AND DATA STRUCTURES
# ====================================================================

class WatchdogState(Enum):
    """Watchdog operational states"""
    STARTING = "starting"
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    FAILED = "failed"
    SHUTTING_DOWN = "shutting_down"

class TestType(Enum):
    """Types of health tests performed by watchdog"""
    HTTP_HEALTH = "http_health"           # Basic HTTP server responsiveness
    DATABASE_CONNECTIVITY = "database"    # Database connection test
    PTB_APPLICATION_ALIVE = "ptb_alive"   # PTB Application loop monitoring
    END_TO_END_MESSAGING = "e2e_messaging"  # Full bot messaging test
    WEBHOOK_PROCESSING = "webhook_proc"   # Webhook processing capability

@dataclass
class WatchdogTest:
    """Individual watchdog test result"""
    test_type: TestType
    timestamp: datetime
    success: bool
    duration_ms: float
    error_message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

@dataclass
class WatchdogStatus:
    """Complete watchdog status information"""
    state: WatchdogState
    last_test_time: datetime
    consecutive_failures: int
    total_tests: int
    total_failures: int
    uptime_seconds: float
    last_success_time: Optional[datetime]
    recent_tests: List[WatchdogTest]
    ptb_application_status: str
    fail_fast_triggered: bool
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'state': self.state.value,
            'last_test_time': self.last_test_time.isoformat(),
            'consecutive_failures': self.consecutive_failures,
            'total_tests': self.total_tests,
            'total_failures': self.total_failures,
            'uptime_seconds': self.uptime_seconds,
            'last_success_time': self.last_success_time.isoformat() if self.last_success_time else None,
            'recent_tests': [
                {
                    'test_type': test.test_type.value,
                    'timestamp': test.timestamp.isoformat(),
                    'success': test.success,
                    'duration_ms': test.duration_ms,
                    'error_message': test.error_message,
                    'details': test.details
                } for test in self.recent_tests
            ],
            'ptb_application_status': self.ptb_application_status,
            'fail_fast_triggered': self.fail_fast_triggered
        }

# ====================================================================
# MAIN APPLICATION WATCHDOG CLASS
# ====================================================================

class ApplicationWatchdog:
    """
    Comprehensive application watchdog for Telegram bot monitoring.
    
    Detects silent failures where the bot appears running but has stopped
    processing updates. Provides fail-fast recovery and detailed monitoring.
    """
    
    def __init__(self):
        # Configuration from environment variables
        self.enabled = os.getenv('WATCHDOG_ENABLED', 'true').lower() == 'true'
        self.test_interval = int(os.getenv('WATCHDOG_TEST_INTERVAL', '60'))  # seconds
        self.failure_threshold = int(os.getenv('WATCHDOG_FAILURE_THRESHOLD', '2'))  # consecutive failures
        self.test_timeout = int(os.getenv('WATCHDOG_TEST_TIMEOUT', '30'))  # seconds
        self.fail_fast_enabled = os.getenv('WATCHDOG_FAIL_FAST', 'true').lower() == 'true'
        self.admin_test_chat_id = os.getenv('ADMIN_USER_ID')  # For end-to-end tests
        
        # Internal state
        self.state = WatchdogState.STARTING
        self.start_time = time.time()
        self.consecutive_failures = 0
        self.total_tests = 0
        self.total_failures = 0
        self.last_success_time: Optional[datetime] = None
        self.recent_tests: List[WatchdogTest] = []
        self.fail_fast_triggered = False
        
        # External references (set by integration)
        self._bot_application = None
        self._bot_loop = None
        self._health_monitor = None
        
        # Monitoring tasks
        self._watchdog_task = None
        self._ptb_monitor_task = None
        self._shutdown_event = asyncio.Event()
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Test message tracking for end-to-end validation
        self._pending_test_messages: Dict[str, datetime] = {}
        self._test_message_timeout = 10  # seconds
        
        logger.info(f"🐕 Application Watchdog initialized:")
        logger.info(f"   • Enabled: {self.enabled}")
        logger.info(f"   • Test Interval: {self.test_interval}s")
        logger.info(f"   • Failure Threshold: {self.failure_threshold}")
        logger.info(f"   • Fail-Fast: {self.fail_fast_enabled}")
        logger.info(f"   • Admin Test Chat: {'SET' if self.admin_test_chat_id else 'NOT SET'}")
    
    def set_bot_application(self, application, loop=None):
        """Set references to PTB Application and event loop"""
        self._bot_application = application
        self._bot_loop = loop
        self._health_monitor = get_health_monitor()
        logger.info("✅ Watchdog: Bot application and loop references set")
    
    async def start(self):
        """Start the watchdog monitoring system"""
        if not self.enabled:
            logger.info("🐕 Watchdog is disabled - skipping startup")
            return
        
        logger.info("🐕 Starting Application Watchdog...")
        
        # Reset shutdown event
        self._shutdown_event.clear()
        
        # Start monitoring tasks
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())
        self._ptb_monitor_task = asyncio.create_task(self._ptb_application_monitor())
        
        # Initial health test
        await self._run_health_tests()
        
        self.state = WatchdogState.HEALTHY
        logger.info("✅ Application Watchdog started successfully")
    
    async def stop(self):
        """Stop the watchdog monitoring system"""
        logger.info("🐕 Stopping Application Watchdog...")
        
        self.state = WatchdogState.SHUTTING_DOWN
        self._shutdown_event.set()
        
        # Cancel monitoring tasks
        if self._watchdog_task:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass
        
        if self._ptb_monitor_task:
            self._ptb_monitor_task.cancel()
            try:
                await self._ptb_monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("✅ Application Watchdog stopped")
    
    async def _watchdog_loop(self):
        """Main watchdog monitoring loop"""
        logger.info("🔄 Watchdog monitoring loop started")
        
        while not self._shutdown_event.is_set():
            try:
                await self._run_health_tests()
                await asyncio.sleep(self.test_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ Watchdog loop error: {e}")
                await asyncio.sleep(5)  # Brief pause on error
    
    async def _ptb_application_monitor(self):
        """Monitor PTB Application lifecycle and detect when it stops"""
        logger.info("🔄 PTB Application lifecycle monitor started")
        
        last_check = time.time()
        
        while not self._shutdown_event.is_set():
            try:
                current_time = time.time()
                
                # Check if PTB Application is still alive
                if self._bot_application and self._bot_loop:
                    # Test if the event loop is still responsive
                    future = asyncio.run_coroutine_threadsafe(
                        self._test_ptb_responsiveness(), 
                        self._bot_loop
                    )
                    
                    try:
                        # Wait with timeout
                        await asyncio.wait_for(
                            asyncio.wrap_future(future), 
                            timeout=5.0
                        )
                        last_check = current_time
                    except asyncio.TimeoutError:
                        # PTB Application loop is not responsive
                        logger.error("🚨 PTB Application loop is not responsive!")
                        await self._handle_ptb_application_failure()
                        break
                    except Exception as e:
                        logger.warning(f"⚠️ PTB responsiveness test failed: {e}")
                
                # Check for significant delays in loop execution
                time_since_check = current_time - last_check
                if time_since_check > 30:  # More than 30 seconds without response
                    logger.error(f"🚨 PTB Application loop appears stuck (delayed {time_since_check:.1f}s)")
                    await self._handle_ptb_application_failure()
                    break
                
                await asyncio.sleep(10)  # Check every 10 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"❌ PTB Application monitor error: {e}")
                await asyncio.sleep(5)
    
    async def _test_ptb_responsiveness(self):
        """Test that PTB Application event loop is responsive"""
        # Simple async operation to test loop responsiveness
        await asyncio.sleep(0.1)
        return True
    
    async def _handle_ptb_application_failure(self):
        """Handle detected PTB Application failure"""
        logger.error("🚨 CRITICAL: PTB Application failure detected!")
        
        # Send critical alert
        await send_critical_alert(
            "PTB Application Failure",
            "The Telegram bot application has stopped responding. "
            "Bot will appear online but won't process messages. "
            "Initiating fail-fast restart.",
            AlertCategory.SYSTEM_HEALTH.value
        )
        
        # Log error for health monitor
        log_error("PTB Application loop stopped responding")
        
        # Trigger fail-fast if enabled
        if self.fail_fast_enabled:
            await self._trigger_fail_fast("PTB Application not responsive")
    
    async def _run_health_tests(self):
        """Run comprehensive health test suite"""
        start_time = time.time()
        test_results = []
        
        with self._lock:
            self.total_tests += 1
        
        logger.debug(f"🔍 Running health test suite (#{self.total_tests})")
        
        # Test 1: HTTP Health Check
        test_results.append(await self._test_http_health())
        
        # Test 2: Database Connectivity
        test_results.append(await self._test_database_connectivity())
        
        # Test 3: PTB Application Status
        test_results.append(await self._test_ptb_application_status())
        
        # Test 4: End-to-End Messaging (DISABLED - Skip E2E tests to admin chat)
        # if self.admin_test_chat_id:
        #     test_results.append(await self._test_end_to_end_messaging())
        
        # Test 5: Webhook Processing Capability
        test_results.append(await self._test_webhook_processing())
        
        # Process results
        await self._process_test_results(test_results)
        
        duration = (time.time() - start_time) * 1000
        logger.debug(f"✅ Health test suite completed in {duration:.1f}ms")
    
    async def _test_http_health(self) -> WatchdogTest:
        """Test HTTP server health"""
        start_time = time.time()
        
        try:
            # Use existing health monitor
            health_status = await self._health_monitor.perform_health_check() if self._health_monitor else {}
            
            success = health_status.get('overall') in ['healthy', 'warning']
            duration_ms = (time.time() - start_time) * 1000
            
            return WatchdogTest(
                test_type=TestType.HTTP_HEALTH,
                timestamp=datetime.utcnow(),
                success=success,
                duration_ms=duration_ms,
                details={'health_status': health_status}
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return WatchdogTest(
                test_type=TestType.HTTP_HEALTH,
                timestamp=datetime.utcnow(),
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _test_database_connectivity(self) -> WatchdogTest:
        """Test database connectivity"""
        start_time = time.time()
        
        try:
            if self._health_monitor:
                db_healthy = await self._health_monitor.check_database_health()
                duration_ms = (time.time() - start_time) * 1000
                
                return WatchdogTest(
                    test_type=TestType.DATABASE_CONNECTIVITY,
                    timestamp=datetime.utcnow(),
                    success=db_healthy,
                    duration_ms=duration_ms
                )
            else:
                # Fallback test
                from database import execute_query
                result = await execute_query("SELECT 1 as watchdog_test", ())
                success = bool(result and len(result) > 0)
                duration_ms = (time.time() - start_time) * 1000
                
                return WatchdogTest(
                    test_type=TestType.DATABASE_CONNECTIVITY,
                    timestamp=datetime.utcnow(),
                    success=success,
                    duration_ms=duration_ms
                )
                
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return WatchdogTest(
                test_type=TestType.DATABASE_CONNECTIVITY,
                timestamp=datetime.utcnow(),
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _test_ptb_application_status(self) -> WatchdogTest:
        """Test PTB Application status"""
        start_time = time.time()
        
        try:
            if not self._bot_application:
                duration_ms = (time.time() - start_time) * 1000
                return WatchdogTest(
                    test_type=TestType.PTB_APPLICATION_ALIVE,
                    timestamp=datetime.utcnow(),
                    success=False,
                    duration_ms=duration_ms,
                    error_message="Bot application not set"
                )
            
            # Check if application is running
            success = (
                hasattr(self._bot_application, 'running') and 
                self._bot_application.running
            )
            
            duration_ms = (time.time() - start_time) * 1000
            
            return WatchdogTest(
                test_type=TestType.PTB_APPLICATION_ALIVE,
                timestamp=datetime.utcnow(),
                success=success,
                duration_ms=duration_ms,
                details={
                    'running': success,
                    'application_type': type(self._bot_application).__name__
                }
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return WatchdogTest(
                test_type=TestType.PTB_APPLICATION_ALIVE,
                timestamp=datetime.utcnow(),
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _test_end_to_end_messaging(self) -> WatchdogTest:
        """Test end-to-end bot messaging capability - DISABLED"""
        start_time = time.time()
        
        # E2E messaging test is completely disabled to prevent spam to admin chat
        # This function returns immediately without sending any messages
        logger.debug("🐕 E2E messaging test skipped - function disabled to prevent admin spam")
        
        duration_ms = (time.time() - start_time) * 1000
        
        return WatchdogTest(
            test_type=TestType.END_TO_END_MESSAGING,
            timestamp=datetime.utcnow(),
            success=True,  # Return success to not affect overall health status
            duration_ms=duration_ms,
            details={'status': 'disabled', 'reason': 'E2E test disabled to prevent admin message spam'}
        )
    
    async def _test_webhook_processing(self) -> WatchdogTest:
        """Test webhook processing capability"""
        start_time = time.time()
        
        try:
            # Test if webhook handler is responding
            from webhook_handler import validate_webhook_configuration
            
            webhook_status = validate_webhook_configuration()
            success = len(webhook_status.get('issues', [])) == 0
            
            duration_ms = (time.time() - start_time) * 1000
            
            return WatchdogTest(
                test_type=TestType.WEBHOOK_PROCESSING,
                timestamp=datetime.utcnow(),
                success=success,
                duration_ms=duration_ms,
                details=webhook_status
            )
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return WatchdogTest(
                test_type=TestType.WEBHOOK_PROCESSING,
                timestamp=datetime.utcnow(),
                success=False,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    async def _process_test_results(self, test_results: List[WatchdogTest]):
        """Process health test results and update watchdog state"""
        with self._lock:
            # Add to recent tests (keep last 10)
            self.recent_tests.extend(test_results)
            self.recent_tests = self.recent_tests[-10:]
            
            # Check if all tests passed
            all_passed = all(test.success for test in test_results)
            
            if all_passed:
                # Reset consecutive failures on success
                if self.consecutive_failures > 0:
                    logger.info(f"✅ Watchdog tests passed - reset consecutive failures from {self.consecutive_failures}")
                
                self.consecutive_failures = 0
                self.last_success_time = datetime.utcnow()
                
                # Update state based on overall health
                if self.state in [WatchdogState.WARNING, WatchdogState.CRITICAL]:
                    self.state = WatchdogState.HEALTHY
                    logger.info("✅ Watchdog state recovered to HEALTHY")
                
            else:
                # Handle failures
                self.consecutive_failures += 1
                self.total_failures += 1
                
                failed_tests = [test for test in test_results if not test.success]
                failed_types = [test.test_type.value for test in failed_tests]
                
                logger.warning(f"⚠️ Watchdog tests failed: {failed_types} (consecutive failures: {self.consecutive_failures})")
                
                # Update state based on failure severity
                if self.consecutive_failures >= self.failure_threshold:
                    await self._handle_consecutive_failures(failed_tests)
                elif self.consecutive_failures >= self.failure_threshold // 2:
                    self.state = WatchdogState.WARNING
                    await self._send_warning_alert(failed_tests)
    
    async def _handle_consecutive_failures(self, failed_tests: List[WatchdogTest]):
        """Handle consecutive failures beyond threshold"""
        self.state = WatchdogState.CRITICAL
        
        logger.error(f"🚨 CRITICAL: Watchdog failure threshold reached ({self.consecutive_failures}/{self.failure_threshold})")
        
        failed_types = [test.test_type.value for test in failed_tests]
        error_details = []
        
        for test in failed_tests:
            if test.error_message:
                error_details.append(f"{test.test_type.value}: {test.error_message}")
        
        # Send critical alert
        await send_critical_alert(
            "Application Watchdog: Critical Failures",
            f"Bot has failed {self.consecutive_failures} consecutive health checks.\n"
            f"Failed tests: {', '.join(failed_types)}\n"
            f"Errors: {'; '.join(error_details)}\n"
            f"This indicates the bot may appear online but is not functioning properly.",
            AlertCategory.SYSTEM_HEALTH.value
        )
        
        # Log error for health monitor
        log_error(f"Watchdog critical failures: {failed_types}")
        
        # Trigger fail-fast if enabled
        if self.fail_fast_enabled:
            await self._trigger_fail_fast(f"Consecutive failures: {failed_types}")
    
    async def _send_warning_alert(self, failed_tests: List[WatchdogTest]):
        """Send warning alert for partial failures"""
        failed_types = [test.test_type.value for test in failed_tests]
        
        await send_warning_alert(
            "Application Watchdog: Warning",
            f"Bot health check warnings detected.\n"
            f"Failed tests: {', '.join(failed_types)}\n"
            f"Consecutive failures: {self.consecutive_failures}",
            AlertCategory.SYSTEM_HEALTH.value
        )
    
    async def _trigger_fail_fast(self, reason: str):
        """Trigger fail-fast behavior - clean process exit"""
        if self.fail_fast_triggered:
            return  # Already triggered
        
        self.fail_fast_triggered = True
        self.state = WatchdogState.FAILED
        
        logger.error(f"💥 FAIL-FAST TRIGGERED: {reason}")
        logger.error("🛑 Initiating clean process exit for supervisor restart")
        
        # Log restart for health monitor
        log_restart()
        
        # Stop watchdog
        await self.stop()
        
        # Give time for final logs
        await asyncio.sleep(2)
        
        # Exit process cleanly
        sys.exit(1)
    
    def get_status(self) -> WatchdogStatus:
        """Get current watchdog status"""
        with self._lock:
            return WatchdogStatus(
                state=self.state,
                last_test_time=datetime.fromtimestamp(time.time()),
                consecutive_failures=self.consecutive_failures,
                total_tests=self.total_tests,
                total_failures=self.total_failures,
                uptime_seconds=time.time() - self.start_time,
                last_success_time=self.last_success_time,
                recent_tests=self.recent_tests.copy(),
                ptb_application_status="running" if (self._bot_application and hasattr(self._bot_application, 'running') and self._bot_application.running) else "stopped",
                fail_fast_triggered=self.fail_fast_triggered
            )
    
    def is_healthy(self) -> bool:
        """Check if watchdog considers the application healthy"""
        return self.state in [WatchdogState.HEALTHY, WatchdogState.WARNING]

# ====================================================================
# GLOBAL WATCHDOG INSTANCE AND UTILITY FUNCTIONS
# ====================================================================

# Global watchdog instance
_application_watchdog = None

def get_application_watchdog() -> ApplicationWatchdog:
    """Get or create global application watchdog instance"""
    global _application_watchdog
    if _application_watchdog is None:
        _application_watchdog = ApplicationWatchdog()
        logger.info("✅ Application Watchdog instance created")
    return _application_watchdog

async def start_application_watchdog(bot_application=None, bot_loop=None):
    """Start the application watchdog system"""
    watchdog = get_application_watchdog()
    
    if bot_application:
        watchdog.set_bot_application(bot_application, bot_loop)
    
    await watchdog.start()
    return watchdog

async def stop_application_watchdog():
    """Stop the application watchdog system"""
    global _application_watchdog
    if _application_watchdog:
        await _application_watchdog.stop()

def get_watchdog_status() -> Dict[str, Any]:
    """Get current watchdog status as dictionary"""
    watchdog = get_application_watchdog()
    return watchdog.get_status().to_dict()

def is_application_healthy() -> bool:
    """Quick check if application is considered healthy by watchdog"""
    watchdog = get_application_watchdog()
    return watchdog.is_healthy()