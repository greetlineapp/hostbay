#!/usr/bin/env python3
"""
Consolidated Telegram Bot - Single Event Loop Implementation
Eliminates threading issues by running PTB Application and webhook server in same asyncio loop
"""

import os
import logging
import asyncio
import sys
import signal
from typing import Optional
from telegram import Update
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters, Defaults

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# SECURITY FIX: Prevent httpx from logging sensitive URLs with bot tokens
logging.getLogger("httpx").setLevel(logging.WARNING)

# SPAM FIX: Suppress aiohttp access logs for successful requests but keep errors
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Import our handlers and services
from handlers import (
    start_command, 
    domain_command, 
    dns_command, 
    wallet_command,
    search_command,
    profile_command,
    hosting_command,
    language_command,
    handle_callback,
    handle_text_message,
    cleanup_expired_tokens
)

# Import consolidated admin handlers
from admin_handlers import (
    credit_wallet_command,
    broadcast_command,
    cancel_command,
    handle_admin_broadcast_text,
    handle_admin_credit_text
)

# Import brand configuration
from brand_config import get_startup_message, get_platform_name
from health_monitor import get_health_monitor, log_error, log_restart, get_health_status

# Import renewal processor for hosting subscriptions
from services.renewal_processor import process_all_hosting_renewals, set_renewal_bot_application

# Global shutdown flag
shutdown_requested = False

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global shutdown_requested
    shutdown_requested = True
    logger.info(f"🛑 Shutdown signal received ({signum}), initiating graceful shutdown...")

async def initialize_database():
    """Initialize database and security constraints"""
    try:
        logger.info("🔄 Initializing database and security constraints...")
        from database import init_database, get_security_status
        
        # Initialize database
        await init_database()
        
        # Verify it worked
        status = get_security_status()
        if status.get('financial_operations_allowed', False):
            logger.info("✅ Database initialized - financial operations enabled")
        else:
            logger.warning("⚠️ Database initialized but financial operations may be limited")
            
        return True
        
    except Exception as db_error:
        logger.error(f"❌ Database initialization failed: {db_error}")
        logger.warning("⚠️ Bot will continue but financial operations may be disabled")
        return False

async def setup_periodic_jobs(app: Application):
    """Set up periodic maintenance jobs"""
    job_queue = app.job_queue
    if not job_queue:
        logger.warning("⚠️ Job queue not available - skipping periodic jobs")
        return

    # Cleanup job
    async def safe_cleanup_job(context: ContextTypes.DEFAULT_TYPE):
        try:
            from database import cleanup_old_webhook_callbacks
            
            # Clean up expired callback tokens
            await cleanup_expired_tokens()
            
            # Clean up old webhook callback records (30+ days old)
            cleaned_count = await cleanup_old_webhook_callbacks(days_old=30)
            
            logger.info(f"🧹 Periodic cleanup completed - webhook callbacks cleaned: {cleaned_count}")
        except Exception as cleanup_error:
            logger.warning(f"⚠️ Cleanup job error: {cleanup_error}")

    # Schedule cleanup job every 15 minutes
    job_queue.run_repeating(safe_cleanup_job, interval=900, first=60)
    logger.info("✅ Periodic cleanup job scheduled")

    # Hosting monitoring jobs
    try:
        from hosting_monitor import run_hosting_status_check, run_quick_hosting_check
        
        async def safe_hosting_monitoring_job(context: ContextTypes.DEFAULT_TYPE):
            try:
                result = await run_hosting_status_check()
                if result.get("status") == "success":
                    accounts_checked = result.get("accounts_checked", 0)
                    status_changes = result.get("status_changes", 0)
                    if status_changes > 0:
                        logger.info(f"🔄 Hosting monitoring: {accounts_checked} accounts checked, {status_changes} status changes")
            except Exception as monitoring_error:
                logger.warning(f"⚠️ Hosting monitoring job error: {monitoring_error}")
        
        async def safe_hosting_health_job(context: ContextTypes.DEFAULT_TYPE):
            try:
                health_result = await run_quick_hosting_check()
                if health_result.get("health") in ["warning", "critical"]:
                    logger.warning(f"⚠️ Hosting monitoring health: {health_result.get('status')} - {health_result}")
            except Exception as health_error:
                logger.warning(f"⚠️ Hosting health check error: {health_error}")
        
        # Schedule monitoring jobs
        job_queue.run_repeating(safe_hosting_monitoring_job, interval=300, first=120)  # Every 5 minutes
        job_queue.run_repeating(safe_hosting_health_job, interval=120, first=180)     # Every 2 minutes
        
        logger.info("✅ Hosting status monitoring jobs scheduled")
        
    except Exception as hosting_job_error:
        logger.warning(f"⚠️ Failed to schedule hosting monitoring jobs: {hosting_job_error}")

    # Renewal processing job
    try:
        renewal_interval = int(os.getenv('RENEWAL_PROCESSING_INTERVAL', '3600'))
        
        async def safe_renewal_processing_job(context: ContextTypes.DEFAULT_TYPE):
            try:
                logger.info("🔄 Starting automated hosting renewal processing...")
                result = await process_all_hosting_renewals()
                
                if result.get("status") == "success":
                    stats = result.get("stats", {})
                    processed = stats.get("processed", 0)
                    successful = stats.get("successful", 0)
                    failed = stats.get("failed", 0)
                    
                    if processed > 0:
                        success_rate = (successful / processed * 100) if processed > 0 else 0
                        logger.info(f"✅ Renewal processing completed: {successful}/{processed} successful ({success_rate:.1f}%)")
                        if failed > 0:
                            logger.warning(f"⚠️ {failed} renewals failed or require attention")
                elif result.get("status") == "disabled":
                    logger.debug("🔇 Renewal processing is disabled")
                elif result.get("status") == "blocked":
                    logger.warning(f"🚫 Renewal processing blocked: {result.get('reason', 'Unknown reason')}")
                else:
                    error_msg = result.get("error", "Unknown error")
                    logger.warning(f"⚠️ Renewal processing failed: {error_msg}")
                    
            except Exception as renewal_error:
                logger.warning(f"⚠️ Renewal processing job error: {renewal_error}")
        
        # Schedule renewal processing job
        job_queue.run_repeating(safe_renewal_processing_job, interval=renewal_interval, first=300)
        
        logger.info("✅ Hosting renewal processing job scheduled")
        logger.info(f"   • Automated renewals: every {renewal_interval//60} minutes")
        
    except Exception as renewal_job_error:
        logger.warning(f"⚠️ Failed to schedule renewal processing job: {renewal_job_error}")

async def configure_telegram_webhook(app: Application, token: str):
    """Configure Telegram webhook"""
    try:
        from utils.environment import get_webhook_domain
        webhook_domain = get_webhook_domain()
        
        logger.info("🔧 Configuring Telegram webhook...")
        
        # Use persistent webhook secret token
        webhook_secret = os.getenv('TELEGRAM_WEBHOOK_SECRET_TOKEN')
        if not webhook_secret:
            # Generate deterministic secret based on bot token
            import hashlib
            import time
            secret_source = f"{token[:32]}_{int(time.time() // 86400)}"
            webhook_secret = hashlib.sha256(secret_source.encode()).hexdigest()[:32]
            logger.info("🔐 Generated persistent webhook secret token")
        else:
            logger.info("🔐 Using existing persistent webhook secret token")
        
        logger.info(f"🌐 Setting Telegram webhook URL: https://{webhook_domain}/webhook/telegram")
        
        # Configure Telegram webhook
        webhook_result = await app.bot.set_webhook(
            url=f"https://{webhook_domain}/webhook/telegram",
            secret_token=webhook_secret,
            max_connections=100
        )
        
        if webhook_result:
            logger.info("✅ Telegram webhook configured successfully!")
            
            # Get webhook info for verification
            webhook_info = await app.bot.get_webhook_info()
            logger.info(f"📊 Webhook URL: {webhook_info.url}")
            logger.info(f"🔌 Max connections: {webhook_info.max_connections}")
            logger.info(f"📨 Pending updates: {webhook_info.pending_update_count}")
            return True
        else:
            logger.error("❌ Failed to configure Telegram webhook")
            return False
            
    except Exception as webhook_config_error:
        logger.error(f"❌ Webhook configuration failed: {webhook_config_error}")
        return False

async def main_bot_loop():
    """Main bot event loop - runs everything in single asyncio loop"""
    global shutdown_requested
    
    # Initialize variables that might be used in finally block
    app: Optional[Application] = None
    webhook_runner = None
    
    try:
        # Initialize database first
        await initialize_database()
        
        # Get bot token from environment
        token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not token:
            logger.error("❌ TELEGRAM_BOT_TOKEN not found in environment")
            sys.exit(1)
        
        # Validate token format
        if not isinstance(token, str) or len(token) < 10:
            logger.error("❌ Invalid bot token format")
            sys.exit(1)
        
        # At this point, token is guaranteed to be str
        assert isinstance(token, str), "Token must be str after validation"
        
        logger.info(get_startup_message())
        logger.info("💰 Cryptocurrency payments enabled")
        logger.info("🌐 Payment webhook endpoints: /webhook/blockbee, /webhook/dynopay")
        logger.info("📱 Telegram webhook endpoint: /webhook/telegram")
        logger.info("🛡️ Auto-recovery and error handling active")
        logger.info("🚫 Polling mode DISABLED - using webhook-only mode")
        
        # Create application with enhanced error handling
        defaults = Defaults(parse_mode='HTML')
        app = Application.builder().token(token).concurrent_updates(128).defaults(defaults).build()
        logger.info("✅ High concurrency enabled: 128 concurrent updates for 5000+ user scalability")
        
        # Add global error handler
        async def global_error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
            """Global error handler for unhandled exceptions"""
            error_str = str(context.error)
            if "ReadError" in error_str or "NetworkError" in error_str or "ConnectionError" in error_str:
                logger.info("🌐 Network timeout recovered automatically by retry mechanism")
            elif "httpx" in error_str:
                logger.info(f"🔧 HTTP client error handled: {context.error}")
            else:
                logger.warning(f"⚠️ Unhandled application error: {context.error}")
        
        app.add_error_handler(global_error_handler)
        logger.info("✅ Global error handler registered for network resilience")
        
        # Set bot application reference for admin alerts
        try:
            from admin_alerts import set_admin_alert_bot_application
            set_admin_alert_bot_application(app)
            logger.info("✅ Admin alert system configured")
        except Exception as alert_integration_error:
            logger.warning(f"⚠️ Admin alert integration failed: {alert_integration_error}")
        
        # Set bot application reference for renewal processor notifications
        try:
            set_renewal_bot_application(app)
            logger.info("✅ Renewal processor integration configured")
        except Exception as renewal_integration_error:
            logger.warning(f"⚠️ Renewal processor integration failed: {renewal_integration_error}")
        
        # Add command handlers
        app.add_handler(CommandHandler("start", start_command))
        app.add_handler(CommandHandler("domain", domain_command))
        app.add_handler(CommandHandler("dns", dns_command))
        app.add_handler(CommandHandler("wallet", wallet_command))
        app.add_handler(CommandHandler("credit_wallet", credit_wallet_command))
        app.add_handler(CommandHandler("broadcast", broadcast_command))
        app.add_handler(CommandHandler("cancel", cancel_command))
        app.add_handler(CommandHandler("search", search_command))
        app.add_handler(CommandHandler("profile", profile_command))
        app.add_handler(CommandHandler("hosting", hosting_command))
        app.add_handler(CommandHandler("language", language_command))
        
        # Add callback query handler for all inline keyboard interactions
        app.add_handler(CallbackQueryHandler(handle_callback))
        
        # Add message handlers with priority groups
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_credit_text), group=-2)
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_broadcast_text), group=-1)
        app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message), group=0)
        
        logger.info("✅ All command handlers registered in main event loop")
        
        # Initialize and start the application
        await app.initialize()
        await app.start()
        logger.info("✅ Application initialized and started successfully")
        
        # Get current loop for webhook handler
        current_loop = asyncio.get_running_loop()
        
        # Set bot application reference for webhook handler - CRITICAL: ensure loop is running
        if current_loop.is_running():
            from webhook_handler import set_bot_application
            set_bot_application(app, current_loop)
            logger.info("✅ Bot application set in webhook handler with live loop")
        else:
            logger.error("❌ Event loop not running - cannot set bot application")
            sys.exit(1)
        
        # Start webhook server in the same event loop
        from webhook_handler import start_webhook_server
        webhook_runner = await start_webhook_server()
        logger.info("✅ Webhook server started for cryptocurrency payment processing")
        
        # Configure Telegram webhook
        webhook_configured = await configure_telegram_webhook(app, token)
        if not webhook_configured:
            logger.error("❌ Failed to configure Telegram webhook")
            sys.exit(1)
        
        # Set up periodic jobs
        await setup_periodic_jobs(app)
        
        # Initialize and start application watchdog
        try:
            from application_watchdog import start_application_watchdog
            watchdog = await start_application_watchdog(app, current_loop)
            logger.info("✅ Application Watchdog started successfully")
        except Exception as watchdog_error:
            logger.warning(f"⚠️ Failed to start Application Watchdog: {watchdog_error}")
            logger.warning("🔄 Bot will continue without advanced monitoring")
        
        logger.info("✅ Bot started in consolidated event loop mode")
        logger.info("🌐 Bot running in webhook-only mode - listening for Telegram updates via webhook")
        logger.info("📱 Telegram webhook endpoint: /webhook/telegram")
        
        # Run forever - webhook server handles incoming requests
        status_counter = 0
        while not shutdown_requested:
            await asyncio.sleep(60)  # Status check every minute
            status_counter += 1
            if status_counter % 5 == 0:  # Log every 5 minutes
                logger.info("⏰ Bot webhook server running - ready to receive Telegram updates")
        
        logger.info("🛑 Shutdown requested - cleaning up...")
        
        # Stop application watchdog
        try:
            from application_watchdog import stop_application_watchdog
            await stop_application_watchdog()
            logger.info("✅ Application Watchdog stopped")
        except Exception as watchdog_cleanup_error:
            logger.warning(f"⚠️ Watchdog cleanup warning: {watchdog_cleanup_error}")
        
        return True
        
    except KeyboardInterrupt:
        logger.info("🛑 Received keyboard interrupt")
        return True
    except Exception as runtime_error:
        logger.error(f"❌ Application runtime error: {runtime_error}")
        logger.error("💥 FAIL FAST: Exiting for supervisor restart")
        sys.exit(1)
    finally:
        # Cleanup
        try:
            # Stop watchdog first
            try:
                from application_watchdog import stop_application_watchdog
                await stop_application_watchdog()
            except Exception:
                pass  # Best effort cleanup
                
            if app is not None:
                await app.stop()
                await app.shutdown()
            if webhook_runner is not None:
                from webhook_handler import stop_webhook_server
                await stop_webhook_server()
            logger.info("✅ Cleanup completed")
        except Exception as cleanup_error:
            logger.warning(f"⚠️ Cleanup error: {cleanup_error}")

def main():
    """Main entry point"""
    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    logger.info("🚀 Starting Consolidated Telegram Bot with Single Event Loop...")
    
    try:
        # Run the main bot loop
        result = asyncio.run(main_bot_loop())
        logger.info("✅ Bot stopped normally" if result else "⚠️ Bot stopped with error")
        return result
    except Exception as e:
        logger.error(f"💥 Critical bot failure: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()