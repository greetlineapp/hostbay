"""
Health Monitoring and System Status for Production Telegram Bot
Provides health checks, system monitoring, and graceful shutdown handling
"""

import os
import time
import asyncio
import logging
import threading
import psutil
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from database import execute_query, get_connection_pool
from brand_config import get_platform_name

logger = logging.getLogger(__name__)

class HealthMonitor:
    """Production health monitoring and system status tracking"""
    
    def __init__(self):
        self.start_time = time.time()
        self.last_health_check = 0
        self.health_status = {
            'overall': 'healthy',
            'database': 'unknown',
            'telegram_api': 'unknown',
            'webhook_server': 'unknown',
            'memory_usage': 0,
            'uptime_seconds': 0,
            'error_count_1h': 0,
            'last_error': None,
            'restart_count': 0
        }
        self.error_log = []
        self.shutdown_requested = False
        self._lock = threading.Lock()
    
    def update_error_count(self, error_message: str):
        """Track errors for health monitoring"""
        with self._lock:
            current_time = time.time()
            
            # Add new error
            self.error_log.append({
                'timestamp': current_time,
                'message': str(error_message)[:200]  # Truncate long messages
            })
            
            # Remove errors older than 1 hour
            one_hour_ago = current_time - 3600
            self.error_log = [err for err in self.error_log if err['timestamp'] > one_hour_ago]
            
            # Update health status
            self.health_status['error_count_1h'] = len(self.error_log)
            self.health_status['last_error'] = {
                'message': str(error_message)[:100],
                'timestamp': datetime.fromtimestamp(current_time).isoformat()
            }
            
            # Update overall health status based on error frequency
            if len(self.error_log) > 50:  # More than 50 errors in 1 hour
                self.health_status['overall'] = 'critical'
            elif len(self.error_log) > 20:  # More than 20 errors in 1 hour
                self.health_status['overall'] = 'degraded'
            elif len(self.error_log) > 5:   # More than 5 errors in 1 hour
                self.health_status['overall'] = 'warning'
            else:
                self.health_status['overall'] = 'healthy'
    
    def update_restart_count(self):
        """Track bot restarts"""
        with self._lock:
            self.health_status['restart_count'] += 1
    
    def log_info(self, message: str):
        """Log informational message for health tracking"""
        logger.info(message)
        # Could be extended to track positive events for health metrics
    
    async def check_database_health(self) -> bool:
        """Check database connectivity and performance"""
        try:
            start_time = time.time()
            
            # Simple connectivity test
            result = await execute_query("SELECT 1 as health_check", ())
            
            response_time = time.time() - start_time
            
            if result and len(result) > 0:
                if response_time < 1.0:  # Less than 1 second
                    self.health_status['database'] = 'healthy'
                elif response_time < 5.0:  # Less than 5 seconds
                    self.health_status['database'] = 'slow'
                else:
                    self.health_status['database'] = 'degraded'
                return True
            else:
                self.health_status['database'] = 'failed'
                return False
                
        except Exception as e:
            logger.warning(f"Database health check failed: {e}")
            self.health_status['database'] = 'failed'
            return False
    
    def check_system_resources(self):
        """Check system memory and CPU usage"""
        try:
            # Memory usage
            memory_info = psutil.virtual_memory()
            self.health_status['memory_usage'] = memory_info.percent
            
            # Process-specific memory
            process = psutil.Process()
            process_memory = process.memory_info().rss / 1024 / 1024  # MB
            self.health_status['process_memory_mb'] = round(process_memory, 1)
            
            # Uptime
            self.health_status['uptime_seconds'] = int(time.time() - self.start_time)
            
            # CPU usage (if available)
            try:
                cpu_percent = psutil.cpu_percent(interval=0.1)
                self.health_status['cpu_usage'] = cpu_percent
            except:
                pass  # CPU usage not critical for health
                
        except Exception as e:
            logger.warning(f"System resource check failed: {e}")
    
    async def perform_health_check(self) -> Dict[str, Any]:
        """Comprehensive health check"""
        current_time = time.time()
        
        # Don't check too frequently
        if current_time - self.last_health_check < 30:  # 30 second minimum interval
            return self.health_status
        
        self.last_health_check = current_time
        
        logger.info("🔍 Performing comprehensive health check...")
        
        # Check database health
        database_healthy = await self.check_database_health()
        
        # Check system resources
        self.check_system_resources()
        
        # Update overall status
        if not database_healthy:
            if self.health_status['overall'] == 'healthy':
                self.health_status['overall'] = 'degraded'
        
        # Memory warning
        if self.health_status['memory_usage'] > 90:
            self.health_status['overall'] = 'warning'
            logger.warning(f"⚠️ High memory usage: {self.health_status['memory_usage']:.1f}%")
        
        # Add timestamp
        self.health_status['last_check'] = datetime.fromtimestamp(current_time).isoformat()
        self.health_status['platform'] = get_platform_name()
        
        # Log health status periodically
        if self.health_status['uptime_seconds'] % 300 == 0:  # Every 5 minutes
            logger.info(f"💓 Health Status: {self.health_status['overall']} | "
                       f"Uptime: {self.health_status['uptime_seconds']}s | "
                       f"Memory: {self.health_status['memory_usage']:.1f}% | "
                       f"Errors (1h): {self.health_status['error_count_1h']}")
        
        return self.health_status
    
    def get_health_summary(self) -> str:
        """Get human-readable health summary"""
        status = self.health_status
        uptime_str = str(timedelta(seconds=status['uptime_seconds']))
        
        summary = f"""
🤖 {get_platform_name()} Bot Health Status

📊 Overall Status: {status['overall'].upper()}
⏱️ Uptime: {uptime_str}
💾 Memory Usage: {status['memory_usage']:.1f}%
🗄️ Database: {status['database']}
🔄 Restarts: {status['restart_count']}
⚠️ Errors (1h): {status['error_count_1h']}

Last Check: {status.get('last_check', 'Never')}
        """.strip()
        
        if status.get('last_error'):
            summary += f"\n\n🚨 Last Error: {status['last_error']['message']}"
        
        return summary
    
    def request_shutdown(self):
        """Request graceful shutdown"""
        self.shutdown_requested = True
        logger.info("🛑 Graceful shutdown requested")
    
    def is_shutdown_requested(self) -> bool:
        """Check if shutdown was requested"""
        return self.shutdown_requested

# Global health monitor instance
_health_monitor = None

def get_health_monitor() -> HealthMonitor:
    """Get or create global health monitor instance"""
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = HealthMonitor()
        logger.info("✅ Health monitor initialized")
    return _health_monitor

def log_error(error_message: str):
    """Convenience function to log errors to health monitor"""
    monitor = get_health_monitor()
    monitor.update_error_count(error_message)

def log_restart():
    """Convenience function to log bot restarts"""
    monitor = get_health_monitor()
    monitor.update_restart_count()

async def get_health_status() -> Dict[str, Any]:
    """Get current health status"""
    monitor = get_health_monitor()
    return await monitor.perform_health_check()

def get_health_summary() -> str:
    """Get human-readable health summary"""
    monitor = get_health_monitor()
    return monitor.get_health_summary()

def request_shutdown():
    """Request graceful shutdown"""
    monitor = get_health_monitor()
    monitor.request_shutdown()

def is_shutdown_requested() -> bool:
    """Check if shutdown was requested"""
    monitor = get_health_monitor()
    return monitor.is_shutdown_requested()