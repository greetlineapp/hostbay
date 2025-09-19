#!/usr/bin/env python3
"""
Telegram Bot - Enhanced with Cryptocurrency Payment Integration
Pure telegram bot for domain registration, DNS management, and crypto payments
"""

import os
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters, Defaults

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# SECURITY FIX: Prevent httpx from logging sensitive URLs with bot tokens
logging.getLogger("httpx").setLevel(logging.WARNING)

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

# Import webhook handler for payment processing
from webhook_handler import run_webhook_server

# Import brand configuration
from brand_config import get_startup_message, get_platform_name
from health_monitor import get_health_monitor, log_error, log_restart, get_health_status

# Import renewal processor for hosting subscriptions
from services.renewal_processor import process_all_hosting_renewals, set_renewal_bot_application, get_renewal_processor_stats

def main():
    """Start the bot with enhanced payment integration and auto-recovery"""
    # CRITICAL FIX: Force database initialization and security verification BEFORE anything else
    logger.info("🔧 CRITICAL FIX: Forcing database initialization and security verification...")
    try:
        import asyncio
        from database import init_database, get_security_status
        
        # Force run database initialization
        asyncio.run(init_database())
        
        # Verify it worked
        status = get_security_status()
        if status.get('financial_operations_allowed', False):
            logger.info("✅ CRITICAL FIX SUCCESS: Financial operations enabled - crypto payments working!")
        else:
            logger.error("❌ CRITICAL FIX FAILED: Financial operations still blocked")
            
    except Exception as critical_error:
        logger.error(f"❌ CRITICAL FIX ERROR: {critical_error}")
        logger.warning("⚠️ Crypto payments may not work properly")
    
    return start_bot_with_recovery()

def start_bot_with_recovery(max_restart_attempts: int = 10, base_restart_delay: float = 5.0):
    """Start bot with comprehensive error handling and auto-restart capability"""
    import time
    import traceback
    from telegram.error import NetworkError, TelegramError
    
    restart_count = 0
    last_restart_time = 0
    
    while restart_count < max_restart_attempts:
        current_time = time.time()
        
        # Reset restart count if enough time has passed since last restart
        if current_time - last_restart_time > 300:  # 5 minutes
            restart_count = 0
            logger.info("✅ Restart counter reset - bot has been stable")
        
        try:
            logger.info(f"🚀 Starting bot (attempt {restart_count + 1}/{max_restart_attempts})")
            
            # CRITICAL: Initialize database and verify security constraints FIRST
            try:
                logger.info("🔄 Initializing database and security constraints...")
                import asyncio
                from database import init_database
                asyncio.run(init_database())
                logger.info("✅ Database and security initialization completed successfully")
            except Exception as db_error:
                logger.error(f"❌ Database initialization failed: {db_error}")
                logger.warning("⚠️ Bot will continue but financial operations may be disabled")
            
            # Get bot token from environment with validation
            token = os.getenv('TELEGRAM_BOT_TOKEN')
            if not token:
                logger.error("❌ TELEGRAM_BOT_TOKEN not found in environment")
                if restart_count == 0:
                    logger.error("🆘 Critical: Cannot start bot without token")
                    return False
                else:
                    logger.info("⏰ Retrying token validation...")
                    time.sleep(base_restart_delay)
                    restart_count += 1
                    continue
            
            # Validate token format
            if not isinstance(token, str) or len(token) < 10:
                logger.error("❌ Invalid bot token format")
                return False
            
            # NOTE: Webhook server will be started AFTER app initialization to prevent race conditions
            
            # Create application with clean dependencies and enhanced error handling
            # PHASE 2: High Concurrency for 5000+ Users
            defaults = Defaults(parse_mode='HTML')
            app = Application.builder().token(token).concurrent_updates(128).defaults(defaults).build()
            logger.info("✅ High concurrency enabled: 128 concurrent updates for 5000+ user scalability")
            
            # Add global error handler for unhandled network exceptions
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
            
            # CRITICAL FIX: Skip premature webhook setup - it will be done properly with loop in background thread
            # This prevents _bot_loop being set to None which breaks message delivery
            logger.info("🔄 Webhook integration will be configured in background thread with proper event loop")
            
            # Set bot application reference for admin alerts
            try:
                from admin_alerts import set_admin_alert_bot_application
                set_admin_alert_bot_application(app)
                logger.info("✅ Admin alert system configured")
            except Exception as alert_integration_error:
                logger.warning(f"⚠️ Admin alert integration failed: {alert_integration_error}")
                logger.info("🔄 Bot will continue without admin alerts")
            
            # Set bot application reference for renewal processor notifications
            try:
                set_renewal_bot_application(app)
                logger.info("✅ Renewal processor integration configured")
            except Exception as renewal_integration_error:
                logger.warning(f"⚠️ Renewal processor integration failed: {renewal_integration_error}")
                logger.info("🔄 Bot will continue without renewal processor integration")
            
            # WEBHOOK MODE FIX: Skip main thread handler registration in webhook mode
            # Handlers are registered in background thread (line 432) for webhook processing
            webhook_mode = True  # This bot runs exclusively in webhook mode
            if not webhook_mode:
                # Add command handlers with error wrapping (POLLING MODE ONLY)
                try:
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
                    
                    # Add HIGHEST priority admin credit text handler (group -2)
                    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_credit_text), group=-2)
                    
                    # Add high-priority admin broadcast text handler (group -1)  
                    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_broadcast_text), group=-1)
                    
                    # Add unified message handler for all text input flows (group 0)
                    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message), group=0)
                    
                    logger.info("✅ All command handlers registered successfully (polling mode)")
                except Exception as handler_error:
                    logger.error(f"❌ Failed to register handlers: {handler_error}")
                    restart_count += 1
                    continue
            else:
                logger.info("✅ Skipping main thread handler registration (webhook mode - handlers in background thread)")
            
            # Schedule periodic cleanup with error handling
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
                    # Don't crash the bot for cleanup failures
            
            # Add cleanup job to run every 15 minutes
            job_queue = app.job_queue
            if job_queue:
                try:
                    job_queue.run_repeating(safe_cleanup_job, interval=900, first=60)
                    logger.info("✅ Periodic cleanup job scheduled")
                except Exception as job_error:
                    logger.warning(f"⚠️ Failed to schedule cleanup job: {job_error}")
                
                # Add hosting status monitoring jobs
                try:
                    from hosting_monitor import run_hosting_status_check, run_quick_hosting_check
                    
                    # Schedule full hosting status check every 5 minutes
                    async def safe_hosting_monitoring_job(context: ContextTypes.DEFAULT_TYPE):
                        try:
                            result = await run_hosting_status_check()
                            if result.get("status") == "success":
                                accounts_checked = result.get("accounts_checked", 0)
                                status_changes = result.get("status_changes", 0)
                                if status_changes > 0:
                                    logger.info(f"🔄 Hosting monitoring: {accounts_checked} accounts checked, {status_changes} status changes")
                                else:
                                    logger.debug(f"✅ Hosting monitoring: {accounts_checked} accounts checked, all stable")
                            else:
                                logger.warning(f"⚠️ Hosting monitoring failed: {result.get('error', 'Unknown error')}")
                        except Exception as monitoring_error:
                            logger.warning(f"⚠️ Hosting monitoring job error: {monitoring_error}")
                    
                    # Schedule quick health check every 2 minutes
                    async def safe_hosting_health_job(context: ContextTypes.DEFAULT_TYPE):
                        try:
                            health_result = await run_quick_hosting_check()
                            if health_result.get("health") in ["warning", "critical"]:
                                logger.warning(f"⚠️ Hosting monitoring health: {health_result.get('status')} - {health_result}")
                        except Exception as health_error:
                            logger.warning(f"⚠️ Hosting health check error: {health_error}")
                    
                    # Schedule the monitoring jobs
                    job_queue.run_repeating(safe_hosting_monitoring_job, interval=300, first=120)  # Every 5 minutes, start after 2 minutes
                    job_queue.run_repeating(safe_hosting_health_job, interval=120, first=180)     # Every 2 minutes, start after 3 minutes
                    
                    logger.info("✅ Hosting status monitoring jobs scheduled")
                    logger.info("   • Full status check: every 5 minutes")
                    logger.info("   • Quick health check: every 2 minutes")
                    
                except Exception as hosting_job_error:
                    logger.warning(f"⚠️ Failed to schedule hosting monitoring jobs: {hosting_job_error}")
                    logger.info("🔄 Bot will continue without hosting status monitoring")
                
                # Add hosting renewal processing job
                try:
                    # Get renewal processing interval from environment (default: 1 hour = 3600 seconds)
                    renewal_interval = int(os.getenv('RENEWAL_PROCESSING_INTERVAL', '3600'))
                    
                    # Schedule automated hosting renewal processing
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
                                else:
                                    logger.debug("✅ Renewal processing completed: No subscriptions required processing")
                            elif result.get("status") == "disabled":
                                logger.debug("🔇 Renewal processing is disabled")
                            elif result.get("status") == "blocked":
                                logger.warning(f"🚫 Renewal processing blocked: {result.get('reason', 'Unknown reason')}")
                            else:
                                error_msg = result.get("error", "Unknown error")
                                logger.warning(f"⚠️ Renewal processing failed: {error_msg}")
                                
                        except Exception as renewal_error:
                            logger.warning(f"⚠️ Renewal processing job error: {renewal_error}")
                            # Don't crash the bot for renewal processing failures
                    
                    # Schedule renewal processing job with configurable interval
                    job_queue.run_repeating(safe_renewal_processing_job, interval=renewal_interval, first=300)  # Start after 5 minutes
                    
                    logger.info("✅ Hosting renewal processing job scheduled")
                    logger.info(f"   • Automated renewals: every {renewal_interval//60} minutes")
                    logger.info(f"   • First run: 5 minutes after startup")
                    
                except Exception as renewal_job_error:
                    logger.warning(f"⚠️ Failed to schedule renewal processing job: {renewal_job_error}")
                    logger.info("🔄 Bot will continue without automated renewal processing")
            
            # Start the bot with enhanced error handling
            logger.info(get_startup_message())
            logger.info("💰 Cryptocurrency payments enabled")
            logger.info("🌐 Payment webhook endpoints: /webhook/blockbee, /webhook/dynopay")
            logger.info("📱 Telegram webhook endpoint: /webhook/telegram")
            logger.info("🛡️ Auto-recovery and error handling active")
            logger.info("🚫 Polling mode DISABLED - using webhook-only mode")
            
            # NOTE: Telegram webhook configuration is now handled inline in the application thread
            
            # STEP 3: Create persistent Application thread for webhook processing
            logger.info("🔧 Starting persistent Application thread for webhook processing...")
                
            def run_bot_application():
                """Build and run bot application on persistent event loop"""
                import asyncio
                
                # Validate token inside function scope to fix LSP error
                if not token or not isinstance(token, str):
                    logger.error("❌ Invalid token in application thread")
                    return False
                    
                # Create dedicated event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                app = None  # Initialize app variable
                try:
                    # Build the Application inside this thread to avoid loop mismatch
                    from telegram.ext import Application, ApplicationBuilder, CallbackQueryHandler, CommandHandler, ConversationHandler, MessageHandler, filters
                    from telegram.error import TelegramError
                    from handlers import (
                        start_command, domain_command, dns_command, wallet_command, 
                        search_command, profile_command, hosting_command, handle_callback,
                        handle_text_message
                    )
                    from admin_handlers import (
                        credit_wallet_command, broadcast_command, cancel_command,
                        handle_admin_broadcast_text, handle_admin_credit_text
                    )
                    import logging
                    
                    # Build Application with all configuration (token is validated above)
                    app = (
                        ApplicationBuilder()
                        .token(token)  # token is guaranteed to be str here
                        .concurrent_updates(128)  # Handle high concurrency for 5000+ users
                        .defaults(defaults)
                        .build()
                    )
                    
                    logger.info("✅ Application built successfully in background thread")
                    
                    # Add all command handlers (matching main thread setup)
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
                    
                    # Add HIGHEST priority admin credit text handler (group -2)
                    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_credit_text), group=-2)
                    
                    # Add high-priority admin broadcast text handler (group -1)  
                    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_admin_broadcast_text), group=-1)
                    
                    # Add unified message handler for all text input flows (group 0)
                    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message), group=0)
                    
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
                    
                    # Note: Periodic cleanup job will be scheduled in future version
                    
                    logger.info("✅ All handlers and jobs configured successfully")
                    
                    # Initialize and start the application
                    loop.run_until_complete(app.initialize())
                    loop.run_until_complete(app.start())
                    logger.info("✅ Application initialized and started successfully")
                    
                    # CRITICAL: Pass the running app and loop to webhook handler BEFORE starting webhook server
                    from webhook_handler import set_bot_application
                    set_bot_application(app, loop)
                    
                    # NOW start webhook server after app is fully initialized (prevents race condition)
                    webhook_thread = None
                    try:
                        from webhook_handler import run_webhook_server
                        webhook_thread = run_webhook_server()
                        if webhook_thread:
                            logger.info("✅ Webhook server started for cryptocurrency payment processing")
                        else:
                            logger.warning("⚠️ Webhook server failed to start - payments may not work properly")
                    except Exception as webhook_error:
                        logger.warning(f"⚠️ Webhook server startup error: {webhook_error}")
                        logger.info("🔄 Bot will continue without webhook payments")
                    
                    
                    # CRITICAL FIX: Configure Telegram webhook with persistent secret
                    logger.info("🔧 Configuring Telegram webhook after Application is ready...")
                    try:
                        # Use persistent webhook secret token (never rotate at runtime)
                        webhook_secret_token = os.getenv('TELEGRAM_WEBHOOK_SECRET_TOKEN')
                        
                        if not webhook_secret_token:
                            # Generate secret only if it doesn't exist
                            import secrets
                            webhook_secret_token = secrets.token_urlsafe(32)
                            logger.info("🔐 Generated new webhook secret token (first time setup)")
                            logger.warning("⚠️ Set TELEGRAM_WEBHOOK_SECRET_TOKEN in environment to persist across restarts")
                        else:
                            logger.info("🔐 Using existing persistent webhook secret token")
                        
                        # Set environment variable for webhook verification
                        os.environ['TELEGRAM_WEBHOOK_SECRET_TOKEN'] = webhook_secret_token
                        
                        # Get webhook URL using environment detection
                        from utils.environment import get_webhook_url
                        webhook_url = get_webhook_url('telegram')
                        logger.info(f"🌐 Setting Telegram webhook URL: {webhook_url}")
                        
                        # Configure webhook with Telegram
                        loop.run_until_complete(app.bot.set_webhook(
                            url=webhook_url,
                            secret_token=webhook_secret_token,
                            allowed_updates=Update.ALL_TYPES,
                            drop_pending_updates=False,
                            max_connections=100
                        ))
                        
                        # Verify webhook was configured
                        webhook_info = loop.run_until_complete(app.bot.get_webhook_info())
                        if webhook_info.url == webhook_url:
                            logger.info("✅ Telegram webhook configured successfully!")
                            logger.info(f"📊 Webhook URL: {webhook_info.url}")
                            logger.info(f"🔌 Max connections: {webhook_info.max_connections}")
                            logger.info(f"📨 Pending updates: {webhook_info.pending_update_count}")
                        else:
                            logger.error(f"❌ Webhook verification failed. Expected: {webhook_url}, Got: {webhook_info.url}")
                            return False
                            
                    except Exception as webhook_error:
                        logger.error(f"❌ Telegram webhook configuration error: {webhook_error}")
                        import traceback
                        logger.error(f"🔍 Webhook error traceback: {traceback.format_exc()}")
                        return False
                    
                    # Keep the loop running to process webhook updates
                    loop.run_forever()
                    
                except Exception as app_error:
                    logger.error(f"❌ Application thread error: {app_error}")
                    import traceback
                    logger.error(f"❌ Traceback: {traceback.format_exc()}")
                finally:
                    try:
                        if app is not None:
                            loop.run_until_complete(app.stop())
                            loop.run_until_complete(app.shutdown())
                    except:
                        pass
                    loop.close()
                    logger.info("🔄 Application thread stopped")
            
            # Start the application thread
            import threading
            app_thread = threading.Thread(target=run_bot_application, daemon=True, name="BotApplication")
            app_thread.start()
            
            # Wait a moment for initialization
            import time
            time.sleep(3)
            logger.info("✅ Persistent Application thread started for webhook mode")
            
            # Keep the bot running in webhook mode (no polling)
            logger.info("🌐 Bot running in webhook-only mode - listening for Telegram updates via webhook")
            logger.info("📱 Telegram webhook endpoint: /webhook/telegram")
            
            # Keep the main thread alive to maintain the webhook server
            try:
                while True:
                    time.sleep(60)
                    logger.info("⏰ Bot webhook server running - ready to receive Telegram updates")
                    
            except KeyboardInterrupt:
                logger.info("🛑 Bot stopped by user (Ctrl+C)")
                return True
                
            except NetworkError as network_error:
                logger.warning(f"🌐 Network error occurred: {network_error}")
                log_error(f"Network error: {network_error}")
                
                if "Read timed out" in str(network_error) or "Connection reset" in str(network_error):
                    logger.info("🔄 Temporary network issue - will auto-restart")
                    restart_count += 1
                    last_restart_time = current_time
                    log_restart()
                    delay = min(base_restart_delay * (2 ** min(restart_count - 1, 5)), 60)
                    logger.info(f"⏰ Auto-restart in {delay:.1f} seconds...")
                    time.sleep(delay)
                    continue
                else:
                    logger.error(f"❌ Serious network error: {network_error}")
                    restart_count += 1
                    last_restart_time = current_time
                    log_restart()
                    delay = min(base_restart_delay * (2 ** min(restart_count - 1, 3)), 30)
                    time.sleep(delay)
                    continue
                    
            except TelegramError as telegram_error:
                logger.error(f"🤖 Telegram API error: {telegram_error}")
                log_error(f"Telegram API error: {telegram_error}")
                
                if "Unauthorized" in str(telegram_error):
                    logger.error("🆘 Bot token is invalid - cannot recover automatically")
                    return False
                elif "Flood control exceeded" in str(telegram_error):
                    logger.warning("🚦 Rate limited - waiting before restart")
                    time.sleep(60)  # Wait 1 minute for rate limit
                
                restart_count += 1
                last_restart_time = current_time
                log_restart()
                delay = min(base_restart_delay * (2 ** min(restart_count - 1, 4)), 45)
                logger.info(f"⏰ Auto-restart in {delay:.1f} seconds...")
                time.sleep(delay)
                continue
                
            except Exception as unexpected_error:
                logger.error(f"💥 Unexpected bot error: {unexpected_error}")
                logger.error(f"🔍 Error traceback:\n{traceback.format_exc()}")
                
                restart_count += 1
                last_restart_time = current_time
                delay = min(base_restart_delay * (2 ** min(restart_count - 1, 3)), 30)
                logger.info(f"⏰ Auto-restart in {delay:.1f} seconds...")
                time.sleep(delay)
                continue
                
        except Exception as startup_error:
            logger.error(f"💥 Bot startup error: {startup_error}")
            logger.error(f"🔍 Startup error traceback:\n{traceback.format_exc()}")
            
            restart_count += 1
            last_restart_time = current_time
            delay = min(base_restart_delay * (2 ** min(restart_count - 1, 3)), 30)
            logger.info(f"⏰ Startup retry in {delay:.1f} seconds...")
            time.sleep(delay)
            continue
            
        finally:
            # Clean shutdown - close HTTP clients with error handling
            logger.info("🧹 Cleaning up resources...")
            try:
                import asyncio
                from services.cloudflare import CloudflareService
                try:
                    asyncio.run(CloudflareService.close_client())
                    logger.info("✅ HTTP client closed cleanly")
                except Exception as cleanup_error:
                    logger.warning(f"⚠️ HTTP client cleanup warning: {cleanup_error}")
            except Exception as final_cleanup_error:
                logger.warning(f"⚠️ Final cleanup error: {final_cleanup_error}")
    
    # Maximum restart attempts exceeded
    logger.error(f"💥 Maximum restart attempts ({max_restart_attempts}) exceeded")
    logger.error("🆘 Bot requires manual intervention - check configuration and dependencies")
    return False

def safe_mode_main():
    """Ultra-safe mode with minimal functionality for emergency operation"""
    try:
        logger.info("🆘 Starting bot in safe mode - minimal functionality only")
        
        token = os.getenv('TELEGRAM_BOT_TOKEN')
        if not token:
            logger.error("❌ No bot token available for safe mode")
            return
        
        # Create minimal application
        defaults = Defaults(parse_mode='HTML')
        app = Application.builder().token(token).defaults(defaults).build()
        
        # Add only essential handlers
        async def safe_start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
            try:
                if update.message:
                    await update.message.reply_text("🆘 Bot is running in safe mode. Some features may be limited.")
            except:
                pass
        
        app.add_handler(CommandHandler("start", safe_start_command))
        
        logger.info("🆘 Safe mode handlers registered")
        
        # Run with minimal settings
        app.run_polling(
            allowed_updates=[Update.MESSAGE],
            poll_interval=5.0,  # Slower polling
            timeout=60,
            bootstrap_retries=3
        )
        
    except Exception as safe_mode_error:
        logger.error(f"💥 Safe mode failed: {safe_mode_error}")
        return

if __name__ == '__main__':
    main()