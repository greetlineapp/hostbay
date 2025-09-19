"""
Consolidated Admin Handlers for Telegram Bot
Contains ALL admin functionality: commands, callbacks, text handlers, and broadcast features
"""

import os
import logging
import time
import asyncio
from typing import Optional
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode
from telegram.ext import ContextTypes, ApplicationHandlerStop
from database import (
    execute_query, get_or_create_user, credit_user_wallet,
    get_user_wallet_balance, execute_update
)
from pricing_utils import format_money
from brand_config import get_platform_name
from message_utils import create_error_message, format_bold, format_inline_code, escape_html
from webhook_handler import get_bot_application
from localization import t, resolve_user_language, t_html

logger = logging.getLogger(__name__)

# ========== ADMIN LANGUAGE CONTEXT HELPER ==========

async def get_admin_language(user_id: int, user_lang_code: Optional[str] = None) -> str:
    """
    Resolve admin language preference for admin interface.
    Admin commands should use admin's preferred language.
    
    Args:
        user_id: Admin user's Telegram ID
        user_lang_code: Admin user's Telegram language code
        
    Returns:
        Language code for admin interface
    """
    try:
        return await resolve_user_language(user_id, user_lang_code)
    except Exception as e:
        logger.warning(f"Failed to resolve admin language for {user_id}: {e}")
        return 'en'  # Fallback to English for admin interface

async def get_user_notification_language(user_id: int) -> str:
    """
    Resolve language for notifications sent to users (not admin interface).
    User notifications should always be in the user's preferred language.
    
    Args:
        user_id: Target user's Telegram ID
        
    Returns:
        Language code for user notification
    """
    try:
        return await resolve_user_language(user_id)
    except Exception as e:
        logger.warning(f"Failed to resolve user notification language for {user_id}: {e}")
        return 'en'  # Fallback to English

# ========== ADMIN COMMAND HANDLERS ==========

async def credit_wallet_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to credit wallet balance with enhanced security validation"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in credit wallet command")
        return
    
    # SECURITY: Multi-layer admin validation
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to use /credit_wallet command")
        
        # Get admin language for security response
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        await message.reply_text(
            t('admin.access.denied', admin_lang) + "\n\n" + 
            t('admin.access.restricted', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return
    
    # Parse command arguments
    args = context.args or []
    if len(args) != 2:
        # Get admin language for usage message
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        await message.reply_text(
            t('admin.commands.credit_wallet.usage', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return
    
    try:
        if not args or len(args) < 2:
            return
        target_user_id = int(args[0])
        amount = float(args[1])
        
        # Enhanced validation
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        if amount <= 0:
            await message.reply_text(
                t('admin.commands.credit_wallet.invalid_amount', admin_lang),
                parse_mode=ParseMode.HTML
            )
            return
        
        if amount > 10000:  # Safety limit
            await message.reply_text(
                t('admin.commands.credit_wallet.amount_too_large', admin_lang),
                parse_mode=ParseMode.HTML
            )
            return
        
        # Check if target user exists
        target_users = await execute_query(
            "SELECT * FROM users WHERE telegram_id = %s",
            (target_user_id,)
        )
        
        if not target_users:
            await message.reply_text(
                t('admin.commands.credit_wallet.user_not_found', admin_lang, user_id=target_user_id),
                parse_mode=ParseMode.HTML
            )
            return
        
        target_user = target_users[0]
        user_internal_id = target_user['id']
        
        # Execute wallet credit
        description = f"Admin credit by {user.username or user.first_name} (ID: {user.id})"
        
        # Use unified credit function with admin defaults
        success = await credit_user_wallet(
            user_id=user_internal_id,
            amount_usd=amount,
            provider="admin",
            txid=f"admin_{int(time.time())}_{user.id}",
            order_id=f"admin_credit_{int(time.time())}"
        )
        
        if success:
            # Get updated balance
            new_balance = await get_user_wallet_balance(target_user_id)
            
            display_name = target_user.get('first_name', 'Unknown')
            if target_user.get('last_name'):
                display_name += f" {target_user['last_name']}"
            
            transaction_id = int(time.time())
            
            await message.reply_text(
                t('admin.commands.credit_wallet.credit_successful', admin_lang, 
                  display_name=escape_html(display_name),
                  username=escape_html(target_user.get('username', 'no_username')),
                  amount=f"{amount:.2f}",
                  new_balance=f"{new_balance:.2f}",
                  transaction_id=transaction_id,
                  admin_name=escape_html(user.username or user.first_name)),
                parse_mode=ParseMode.HTML
            )
            
            # Send notification to credited user (in user's language)
            try:
                app = get_bot_application()
                if app:
                    user_lang = await get_user_notification_language(target_user_id)
                    user_notification = t('admin.notifications.user_credit', user_lang,
                                        amount=format_money(amount, 'USD', include_currency=True),
                                        new_balance=format_money(new_balance, 'USD', include_currency=True))
                    
                    await app.bot.send_message(
                        chat_id=target_user_id,
                        text=user_notification,
                        parse_mode=ParseMode.HTML
                    )
                    logger.info(f"✅ Notification sent to user {target_user_id} about ${amount} credit")
            except Exception as notification_error:
                logger.error(f"❌ Failed to send credit notification: {notification_error}")
            
            logger.info(f"💳 ADMIN: User {user.id} credited ${amount:.2f} to user {target_user_id}")
            
        else:
            await message.reply_text(
                t('admin.commands.credit_wallet.credit_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )
            logger.error(f"🚫 ADMIN ERROR: Failed to credit ${amount:.2f} to user {target_user_id} by admin {user.id}")
            
    except ValueError:
        admin_lang = await get_admin_language(user.id, user.language_code)
        await message.reply_text(
            t('admin.commands.credit_wallet.invalid_input', admin_lang),
            parse_mode=ParseMode.HTML
        )
    except Exception as e:
        logger.error(f"🚫 ADMIN ERROR: Exception in credit_wallet_command by admin {user.id}: {e}")
        admin_lang = await get_admin_language(user.id, user.language_code)
        await message.reply_text(
            t('admin.commands.credit_wallet.system_error', admin_lang),
            parse_mode=ParseMode.HTML
        )

async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin command to broadcast message to all users with batching and retry logic"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in broadcast command")
        return
    
    # SECURITY: Multi-layer admin validation
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to use /broadcast command")
        
        # Get admin language for security response
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        await message.reply_text(
            t('admin.access.denied', admin_lang) + "\n\n" + 
            t('admin.access.restricted', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return
    
    # Get admin language for all responses
    admin_lang = await get_admin_language(user.id, user.language_code)
    
    # Get broadcast message from command arguments
    if not context.args:
        await message.reply_text(
            t('admin.commands.broadcast.usage', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return
    
    broadcast_message = " ".join(context.args)
    
    if len(broadcast_message.strip()) == 0:
        await message.reply_text(
            t('admin.commands.broadcast.empty_message', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return
    
    try:
        # Send broadcast using shared helper
        result = await send_broadcast(broadcast_message, update, context, admin_lang)
        
        if not result['success']:
            await message.reply_text(result['message'])
        
    except Exception as e:
        logger.error(f"🚫 ADMIN ERROR: Exception in broadcast_command by admin {user.id}: {e}")
        await message.reply_text(
            t('admin.commands.broadcast.failed', admin_lang),
            parse_mode=ParseMode.HTML
        )

async def send_broadcast(broadcast_message: str, update: Update, context: ContextTypes.DEFAULT_TYPE, admin_lang: str = 'en'):
    """
    Shared broadcast helper function with batching and retry logic.
    Used by both /broadcast command and button interface.
    """
    user = update.effective_user
    message = update.effective_message or (update.callback_query.message if update.callback_query else None)
    
    try:
        # Get all users who have accepted terms
        users = await execute_query(
            "SELECT telegram_id, first_name FROM users WHERE terms_accepted = true ORDER BY id",
            ()
        )
        
        if not users:
            return {
                'success': False,
                'message': t('admin.commands.broadcast.no_recipients', admin_lang)
            }
        
        total_users = len(users)
        
        # Show initial status
        message_preview = escape_html(broadcast_message[:100]) + ('...' if len(broadcast_message) > 100 else '')
        
        if not message:
            return {'success': False, 'message': 'No message available for broadcast status'}
            
        status_message = None
        # Type-safe message reply for broadcast status - properly handle MaybeInaccessibleMessage
        # Only use messages that are actual Message objects, not MaybeInaccessibleMessage
        from telegram import Message
        if message and isinstance(message, Message):
            status_message = await message.reply_text(
                t('admin.broadcast.title', admin_lang) + "\n\n" +
                f"<b>Message:</b> {message_preview}\n" +
                f"<b>Recipients:</b> {total_users} users\n" +
                f"<b>Status:</b> " + t('admin.broadcast.status_starting', admin_lang),
                parse_mode=ParseMode.HTML
            )
        
        # Broadcast with batching and retry logic
        batch_size = 30  # Telegram rate limit friendly
        total_sent = 0
        total_failed = 0
        
        for i in range(0, total_users, batch_size):
            batch = users[i:i + batch_size]
            batch_sent = 0
            batch_failed = 0
            
            for target_user in batch:
                target_user_id = target_user['telegram_id']
                target_name = target_user.get('first_name', 'User')
                
                # Retry logic for each user
                max_retries = 3
                sent = False
                
                for attempt in range(max_retries):
                    try:
                        app = get_bot_application()
                        if app:
                            # Get user's language for broadcast notification
                            user_lang = await get_user_notification_language(target_user_id)
                            broadcast_header = t('admin.broadcast.broadcast_message_header', user_lang)
                            
                            await app.bot.send_message(
                                chat_id=target_user_id,
                                text=f"{broadcast_header}\n\n{escape_html(broadcast_message)}",
                                parse_mode=ParseMode.HTML
                            )
                            batch_sent += 1
                            sent = True
                            break
                    except Exception as send_error:
                        if attempt == max_retries - 1:  # Last attempt failed
                            logger.warning(f"Failed to send broadcast to {target_name} ({target_user_id}): {send_error}")
                            batch_failed += 1
                        else:
                            await asyncio.sleep(0.5)  # Brief pause before retry
                
                if sent:
                    logger.debug(f"📢 Broadcast sent to {target_name} ({target_user_id})")
            
            total_sent += batch_sent
            total_failed += batch_failed
            
            # Update progress
            progress = ((i + len(batch)) / total_users) * 100
            message_preview = escape_html(broadcast_message[:100]) + ('...' if len(broadcast_message) > 100 else '')
            
            if status_message:
                await status_message.edit_text(
                    t('admin.broadcast.progress', admin_lang,
                      message_preview=message_preview,
                      sent=total_sent + total_failed,
                      total=total_users,
                      percentage=f"{progress:.1f}",
                      failed=total_failed),
                    parse_mode=ParseMode.HTML
                )
            
            # Rate limiting delay between batches
            if i + batch_size < total_users:
                await asyncio.sleep(1)  # 1 second delay between batches
        
        # Final results
        success_rate = (total_sent / total_users) * 100 if total_users > 0 else 0
        message_preview = escape_html(broadcast_message[:100]) + ('...' if len(broadcast_message) > 100 else '')
        
        final_message = t('admin.broadcast.complete', admin_lang,
                         message_preview=message_preview,
                         total=total_users,
                         sent=total_sent,
                         failed=total_failed,
                         success_rate=f"{success_rate:.1f}")
        
        if status_message:
            await status_message.edit_text(final_message, parse_mode=ParseMode.HTML)
        
        if user:
            logger.info(f"📢 ADMIN BROADCAST: {user.username or user.first_name} sent to {total_sent}/{total_users} users")
        
        return {
            'success': True,
            'total_users': total_users,
            'total_sent': total_sent,
            'total_failed': total_failed,
            'success_rate': success_rate
        }
        
    except Exception as e:
        logger.error(f"❌ Broadcast error: {e}")
        return {
            'success': False,
            'message': t('admin.commands.broadcast.failed', admin_lang) + f"\n\nError: {str(e)[:100]}"
        }

async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /cancel command to exit broadcast mode"""
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message:
        logger.error("Missing user or message in cancel command")
        return
    
    try:
        # Get admin language
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        # Clear any admin states
        states_cleared = []
        
        if context.user_data and 'awaiting_broadcast' in context.user_data:
            del context.user_data['awaiting_broadcast']
            states_cleared.append(t('admin.status.broadcast_mode', admin_lang))
        
        if context.user_data and 'admin_credit_state' in context.user_data:
            del context.user_data['admin_credit_state']
            states_cleared.append(t('admin.status.credit_wallet_mode', admin_lang))
        
        if states_cleared:
            await message.reply_text(
                t('admin.cancel.success', admin_lang, operations=', '.join(states_cleared)),
                parse_mode=ParseMode.HTML
            )
            logger.info(f"ADMIN: User {user.id} cancelled {', '.join(states_cleared)}")
        else:
            await message.reply_text(
                t('admin.cancel.no_operations', admin_lang),
                parse_mode=ParseMode.HTML
            )
        
    except Exception as e:
        logger.error(f"Error in cancel_command: {e}")
        admin_lang = await get_admin_language(user.id, user.language_code)
        await message.reply_text(
            t('admin.cancel.error', admin_lang),
            parse_mode=ParseMode.HTML
        )

# ========== ADMIN CALLBACK HANDLERS ==========

async def handle_admin_broadcast(query, context):
    """Handle admin broadcast button press"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_admin_broadcast")
        return
    
    # Security check
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        admin_lang = await get_admin_language(user.id, user.language_code)
        await query.edit_message_text(
            t('admin.access.denied', admin_lang),
            parse_mode=ParseMode.HTML
        )
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to access broadcast interface")
        return
    
    try:
        await query.answer()
        
        # Set broadcast mode flag
        context.user_data['awaiting_broadcast'] = True
        
        # Get admin language and show broadcast interface
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        message = t('admin.broadcast.ready', admin_lang,
                   bold_text="Admin Broadcast Ready",
                   bold_text_ready="Broadcast mode activated!",
                   bold_text_steps="Next Steps:",
                   bold_text_type="Type your broadcast message",
                   bold_text_specs="Specs:",
                   bold_text_status="Status:")

        keyboard = [
            [InlineKeyboardButton(t('admin.buttons.cancel_broadcast', admin_lang), callback_data="cancel_broadcast")],
            [InlineKeyboardButton(t('admin.buttons.back_to_dashboard', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=message,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        logger.info(f"📢 ADMIN: User {user.id} accessed broadcast interface")
        
    except Exception as e:
        logger.error(f"Error in handle_admin_broadcast: {e}")
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        await query.edit_message_text(
            t('admin.errors.broadcast_interface_failed', admin_lang),
            parse_mode=ParseMode.HTML
        )

async def handle_cancel_broadcast(query, context):
    """Handle cancel broadcast button press"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_cancel_broadcast")
        return
    
    # Security check
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        admin_lang = await get_admin_language(user.id, user.language_code)
        await query.edit_message_text(
            t('admin.access.denied', admin_lang),
            parse_mode=ParseMode.HTML
        )
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to cancel broadcast")
        return
    
    try:
        await query.answer()
        
        # Get admin language and clear broadcast flag
        admin_lang = await get_admin_language(user.id, user.language_code)
        
        if 'awaiting_broadcast' in context.user_data:
            del context.user_data['awaiting_broadcast']
        
        # Show cancellation message
        message = t('admin.broadcast.cancelled', admin_lang, bold_text="Broadcast Cancelled")

        keyboard = [
            [InlineKeyboardButton(t('admin.buttons.back_to_dashboard', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=message,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        logger.info(f"📢 ADMIN: User {user.id} cancelled broadcast mode")
        
    except Exception as e:
        logger.error(f"Error in handle_cancel_broadcast: {e}")
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        await query.edit_message_text(
            t('admin.errors.broadcast_cancel_failed', admin_lang),
            parse_mode=ParseMode.HTML
        )

# ========== ADMIN TEXT MESSAGE HANDLERS ==========

async def handle_admin_broadcast_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    High-priority text handler for admin broadcast messages.
    Only processes messages when admin is in broadcast mode.
    """
    user = update.effective_user
    message = update.effective_message
    
    if not user or not message or not message.text:
        return False  # Let other handlers process this
    
    # Check if user is admin
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        return False  # Not admin - let other handlers process
    
    # Check if awaiting broadcast
    if not context.user_data or not context.user_data.get('awaiting_broadcast'):
        return False  # Not in broadcast mode - let other handlers process
    
    try:
        broadcast_message = message.text.strip()
        
        if len(broadcast_message) == 0:
            admin_lang = await get_admin_language(user.id, user.language_code)
            await message.reply_text(
                t('admin.commands.broadcast.empty_message', admin_lang),
                parse_mode=ParseMode.HTML
            )
            return True
        
        # Clear broadcast flag immediately
        del context.user_data['awaiting_broadcast']
        
        # Get admin language and send broadcast using shared helper
        admin_lang = await get_admin_language(user.id, user.language_code)
        result = await send_broadcast(broadcast_message, update, context, admin_lang)
        
        logger.info(f"📢 ADMIN TEXT: User {user.id} sent broadcast via text input: '{broadcast_message[:50]}{'...' if len(broadcast_message) > 50 else ''}'")
        return True  # Message handled
        
    except Exception as e:
        logger.error(f"Error in handle_admin_broadcast_text: {e}")
        # Clear broadcast flag on error
        if context.user_data and 'awaiting_broadcast' in context.user_data:
            del context.user_data['awaiting_broadcast']
        
        admin_lang = await get_admin_language(user.id, user.language_code)
        await message.reply_text(
            t('admin.errors.broadcast_text_failed', admin_lang),
            parse_mode=ParseMode.HTML
        )
        return True  # Message handled

async def handle_admin_credit_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """
    High-priority text handler for admin credit wallet workflow.
    Only processes messages when admin is in credit mode.
    """
    user = update.effective_user
    message = update.effective_message
    
    logger.info(f"🔍 CREDIT HANDLER: Called for user {user.id if user else 'None'}")
    
    if not user or not message or not message.text:
        logger.info(f"🔍 CREDIT HANDLER: Missing data - user: {user is not None}, message: {message is not None}, text: {message.text if message else 'None'}")
        return False  # Let other handlers process this
    
    # Check if user is admin
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        logger.info(f"🔍 CREDIT HANDLER: Not admin - user {user.id} vs admin {admin_user_id}")
        return False  # Not admin - let other handlers process
    
    logger.info(f"🔍 CREDIT HANDLER: Admin confirmed - checking credit state")
    
    # Check admin credit state with proper null safety
    if not context.user_data:
        logger.info(f"🔍 CREDIT HANDLER: No user_data context")
        return False  # Not in credit mode - let other handlers process
        
    credit_state = context.user_data.get('admin_credit_state')
    logger.info(f"🔍 CREDIT HANDLER: Credit state: {credit_state}")
    
    if not credit_state:
        logger.info(f"🔍 CREDIT HANDLER: No credit state - user_data keys: {list(context.user_data.keys())}")
        return False  # Not in credit mode - let other handlers process
    
    try:
        step = credit_state.get('step')
        if not message or not message.text:
            logger.info(f"🔍 CREDIT HANDLER: No message text")
            return False
            
        user_input = message.text.strip()
        logger.info(f"🔍 CREDIT HANDLER: Processing step '{step}' with input: '{user_input[:20]}...'")
        
        if step == 'awaiting_user_search':
            # Handle user search input
            logger.info(f"🔍 CREDIT HANDLER: Starting user search")
            await handle_admin_credit_user_search_text(update, context, user_input)
            logger.info(f"🔍 CREDIT HANDLER: User search completed successfully")
            raise ApplicationHandlerStop  # Stop other handlers from processing this message
        elif step == 'awaiting_amount':
            # Handle amount input
            target_user_id = credit_state.get('target_user_id')
            if target_user_id:
                logger.info(f"🔍 CREDIT HANDLER: Starting amount processing")
                await handle_admin_credit_amount_text(update, context, target_user_id, user_input)
                logger.info(f"🔍 CREDIT HANDLER: Amount processing completed successfully")
            raise ApplicationHandlerStop  # Stop other handlers from processing this message
        
        return False  # Unknown state - let other handlers process
        
    except ApplicationHandlerStop:
        # Allow control-flow exceptions to propagate
        raise
    except asyncio.CancelledError:
        # Allow asyncio cancellation to propagate  
        raise
    except Exception as e:
        logger.exception("Error in handle_admin_credit_text (%s): %s", e.__class__.__name__, str(e))
        # Clear credit state on error with null safety
        if context.user_data and 'admin_credit_state' in context.user_data:
            del context.user_data['admin_credit_state']
        
        if user and message:
            admin_lang = await get_admin_language(user.id, user.language_code)
            await message.reply_text(
                t('admin.errors.processing_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )
        return True  # Handler processed the error

async def handle_admin_credit_user_search_text(update: Update, context: ContextTypes.DEFAULT_TYPE, user_input: str):
    """Handle admin search for user to credit via text input"""
    # Initialize variables at function scope to prevent unbound issues
    message = update.effective_message
    effective_user = update.effective_user
    
    try:
        message = update.effective_message
        
        # Parse user input - could be user ID or @username
        target_user = None
        
        if user_input.startswith('@'):
            # Username search
            username = user_input[1:]  # Remove @
            users = await execute_query(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            )
            if users:
                target_user = users[0]
        elif user_input.isdigit():
            # User ID search
            telegram_id = int(user_input)
            users = await execute_query(
                "SELECT * FROM users WHERE telegram_id = %s",
                (telegram_id,)
            )
            if users:
                target_user = users[0]
        
        if not target_user:
            # No user found
            effective_user = update.effective_user
            if effective_user and message:
                admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
                await message.reply_text(
                t('admin.credit.user_not_found_detailed', admin_lang, user_input=user_input),
                parse_mode=ParseMode.HTML
            )
            return
        
        # User found - show user details and ask for amount
        effective_user = update.effective_user
        if not effective_user:
            return
        admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
        current_balance = float(target_user['wallet_balance'] or 0)
        balance_display = format_money(current_balance, 'USD', include_currency=True)
        
        display_name = target_user.get('first_name', 'Unknown')
        if target_user.get('last_name'):
            display_name += f" {target_user['last_name']}"
        
        username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
        
        # Type-safe message reply for user found confirmation
        if message and hasattr(message, 'reply_text'):
            await message.reply_text(
                t('admin.credit.user_found', admin_lang,
                  display_name=escape_html(display_name),
                  username_display=escape_html(username_display),
                  user_id=target_user['telegram_id'],
                  balance=balance_display),
                parse_mode=ParseMode.HTML
            )
        
        # Update state for next step
        if not context.user_data:
            context.user_data = {}
        context.user_data['admin_credit_state'] = {
            'step': 'awaiting_amount',
            'target_user_id': target_user['telegram_id']
        }
        
    except Exception as e:
        logger.error(f"Error handling admin user search text: {e}")
        # Type-safe error handling with null checks - variables initialized at function scope
        if effective_user and message and hasattr(message, 'reply_text'):
            admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
            await message.reply_text(
                t('admin.errors.search_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )

async def handle_admin_credit_amount_text(update: Update, context: ContextTypes.DEFAULT_TYPE, target_user_id: int, amount_str: str):
    """Handle admin entering credit amount via text input"""
    # Initialize variables at function scope to prevent unbound issues
    message = update.effective_message
    effective_user = update.effective_user
    
    try:
        
        # Validate amount
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            if amount > 10000:  # Safety limit
                raise ValueError("Amount too large (max $10,000)")
        except ValueError as e:
            # Type-safe error handling for invalid amount
            effective_user = update.effective_user
            if effective_user and message and hasattr(message, 'reply_text'):
                admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
                await message.reply_text(
                    t('admin.credit.invalid_amount_detailed', admin_lang, amount=amount_str),
                    parse_mode=ParseMode.HTML
                )
            return
        
        # Clear credit state
        if context.user_data and 'admin_credit_state' in context.user_data:
            del context.user_data['admin_credit_state']
        
        # Execute credit directly (since this is text input, we skip confirmation)
        await execute_admin_credit_direct(update, context, target_user_id, amount)
        
    except Exception as e:
        logger.error(f"Error handling admin credit amount text: {e}")
        # Type-safe error handling for amount processing - variables initialized at function scope
        if effective_user and message and hasattr(message, 'reply_text'):
            admin_lang = await get_admin_language(effective_user.id, effective_user.language_code)
            await message.reply_text(
                t('admin.errors.amount_processing_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )

async def execute_admin_credit_direct(update: Update, context: ContextTypes.DEFAULT_TYPE, target_user_id: int, amount: float):
    """Execute admin credit transaction directly (used by text input flow)"""
    # Initialize variables at function scope to prevent unbound issues
    user = update.effective_user
    message = update.effective_message
    
    try:
        
        # Get admin language and show processing message
        if not user:
            return
        admin_lang = await get_admin_language(user.id, user.language_code)
        if not message:
            return
        processing_message = await message.reply_text(
            t('admin.credit.processing', admin_lang),
            parse_mode=ParseMode.HTML
        )
        
        # Get target user details
        users = await execute_query(
            "SELECT * FROM users WHERE telegram_id = %s",
            (target_user_id,)
        )
        
        if not users:
            await processing_message.edit_text(
                t('admin.commands.credit_wallet.user_not_found', admin_lang, user_id=target_user_id),
                parse_mode=ParseMode.HTML
            )
            return
        
        target_user = users[0]
        user_internal_id = target_user['id']
        
        # Execute the credit
        description = f"Admin credit by {user.username or user.first_name} (ID: {user.id})"
        
        # Use unified credit function with admin defaults
        success = await credit_user_wallet(
            user_id=user_internal_id,
            amount_usd=amount,
            provider="admin",
            txid=f"admin_{int(time.time())}_{user.id}",
            order_id=f"admin_credit_{int(time.time())}"
        )
        
        if success:
            # Get updated balance
            new_balance = await get_user_wallet_balance(target_user_id)
            
            display_name = target_user.get('first_name', 'Unknown')
            if target_user.get('last_name'):
                display_name += f" {target_user['last_name']}"
            
            username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
            
            transaction_id = int(time.time())
            await processing_message.edit_text(
                t('admin.credit.transaction_successful', admin_lang,
                  display_name=escape_html(display_name),
                  username_display=escape_html(username_display),
                  amount=format_money(amount, 'USD', include_currency=True),
                  new_balance=format_money(new_balance, 'USD', include_currency=True),
                  transaction_id=transaction_id,
                  admin_name=escape_html(user.username or user.first_name)),
                parse_mode=ParseMode.HTML
            )
            
            # Send notification to the user who received the credit
            try:
                app = get_bot_application()
                if app:
                    user_lang = await get_user_notification_language(target_user_id)
                    user_notification = t('admin.notifications.user_credit', user_lang,
                                        amount=format_money(amount, 'USD', include_currency=True),
                                        new_balance=format_money(new_balance, 'USD', include_currency=True))
                    
                    await app.bot.send_message(
                        chat_id=target_user_id,
                        text=user_notification,
                        parse_mode=ParseMode.HTML
                    )
                    logger.info(f"✅ Notification sent to user {target_user_id} about ${amount} credit")
                else:
                    logger.warning(f"⚠️ Could not send notification - bot application not available")
                    
            except Exception as notification_error:
                logger.error(f"❌ Failed to send credit notification to user {target_user_id}: {notification_error}")
                # Don't fail the credit transaction if notification fails
            
            logger.info(f"💳 ADMIN: User {user.id} credited ${amount} to user {target_user_id}")
            
        else:
            await processing_message.edit_text(
                t('admin.credit.transaction_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )
        
    except Exception as e:
        logger.error(f"Error executing admin credit direct: {e}")
        # Type-safe error handling for credit execution - variables initialized at function scope
        if user and message and hasattr(message, 'reply_text'):
            admin_lang = await get_admin_language(user.id, user.language_code)
            await message.reply_text(
                t('admin.errors.execution_failed', admin_lang),
                parse_mode=ParseMode.HTML
            )

async def handle_admin_credit_wallet(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle admin credit wallet command with easy UX"""
    query = getattr(update, 'callback_query', None)
    
    if query:
        # Coming from callback button - set state and show search interface
        # Type-safe user_data access
        if context.user_data is None:
            context.user_data = {}
        context.user_data['admin_credit_state'] = {
            'step': 'awaiting_user_search'
        }
        await show_admin_credit_search(query, context)
    else:
        # Coming from direct command - type-safe message access
        logger.info("Admin credit wallet handler called")
        if update.message and hasattr(update.message, 'reply_text'):
            await update.message.reply_text("Admin credit wallet functionality not yet implemented")

async def show_admin_credit_search(query, context=None):
    """Show interface for admin to search for user to credit"""
    try:
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        
        keyboard = [
            [InlineKeyboardButton(t('admin.buttons.cancel', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=t('admin.credit.search_prompt', admin_lang),
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
    except Exception as e:
        logger.error(f"Error showing admin credit search: {e}")
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        await query.edit_message_text(
            t('admin.errors.broadcast_interface_failed', admin_lang),
            parse_mode=ParseMode.HTML
        )

async def handle_admin_credit_user_search(query, user_input: str):
    """Handle admin search for user to credit"""
    try:
        # Parse user input - could be user ID or @username
        target_user = None
        
        if user_input.startswith('@'):
            # Username search
            username = user_input[1:]  # Remove @
            users = await execute_query(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            )
            if users:
                target_user = users[0]
        elif user_input.isdigit():
            # User ID search
            telegram_id = int(user_input)
            users = await execute_query(
                "SELECT * FROM users WHERE telegram_id = %s",
                (telegram_id,)
            )
            if users:
                target_user = users[0]
        
        if not target_user:
            # No user found
            message = f"""
❌ <b>User Not Found</b>

Could not find user: {user_input}

Please check:
• User ID is correct (e.g., 1234567890)
• Username is correct (e.g., @johndoe)
• User has used the bot before

Try again with a different identifier:
"""
            
            # Get admin language for localized buttons - type-safe user access
            admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code) if query.from_user else 'en'
            
            keyboard = [
                [InlineKeyboardButton(t('buttons.try_again', admin_lang), callback_data="admin_credit_wallet")],
                [InlineKeyboardButton(t('buttons.cancel', admin_lang), callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await query.edit_message_text(
                text=message,
                reply_markup=reply_markup,
                parse_mode=ParseMode.HTML
            )
            return
        
        # User found - show user details and ask for amount
        current_balance = float(target_user['wallet_balance'] or 0)
        balance_display = format_money(current_balance, 'USD', include_currency=True)
        
        display_name = target_user.get('first_name', 'Unknown')
        if target_user.get('last_name'):
            display_name += f" {target_user['last_name']}"
        
        username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
        
        message = f"""
✅ <b>User Found</b>\n\n<b>Name:</b> {escape_html(display_name)}\n<b>Username:</b> {escape_html(username_display)}\n<b>User ID:</b> <code>{target_user['telegram_id']}</code>\n<b>Current Balance:</b> {balance_display}\n\nEnter the <b>amount in USD</b> to credit to this user's wallet:

Examples: 25.00, 100, 50.50
"""
        
        # Get admin language for localized buttons - type-safe user access
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code) if query.from_user else 'en'
        
        keyboard = [
            [InlineKeyboardButton(t('buttons.cancel', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=message,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
        # Store user info for next step (we'll need a better state management approach)
        # For now, we'll store it in a way that can be retrieved
        
    except Exception as e:
        logger.error(f"Error handling admin user search: {e}")
        await query.edit_message_text("❌ Error searching for user. Please try again.")

async def handle_admin_credit_amount(query, target_user_id: int, amount_str: str):
    """Handle admin entering credit amount"""
    try:
        # Validate amount
        try:
            amount = float(amount_str)
            if amount <= 0:
                raise ValueError("Amount must be positive")
            if amount > 10000:  # Safety limit
                raise ValueError("Amount too large (max $10,000)")
        except ValueError as e:
            message = f"""
❌ <b>Invalid Amount</b>

{amount_str} is not a valid amount.

Please enter a valid amount in USD:
• Must be a positive number
• Maximum $10,000.00
• Examples: 25.00, 100, 50.50
"""
            
            keyboard = [
                [InlineKeyboardButton("❌ Cancel", callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await query.edit_message_text(
                text=message,
                reply_markup=reply_markup,
                parse_mode=ParseMode.HTML
            )
            return
        
        # Get user details for confirmation
        users = await execute_query(
            "SELECT * FROM users WHERE telegram_id = %s",
            (target_user_id,)
        )
        
        if not users:
            await query.edit_message_text("❌ Error: User not found. Please start over.")
            return
        
        target_user = users[0]
        current_balance = float(target_user['wallet_balance'] or 0)
        new_balance = current_balance + amount
        
        display_name = target_user.get('first_name', 'Unknown')
        if target_user.get('last_name'):
            display_name += f" {target_user['last_name']}"
        
        username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
        
        message = f"""
⚠️ <b>Confirm Credit Transaction</b>\n\n<b>User:</b> {escape_html(display_name)} ({escape_html(username_display)})\n<b>User ID:</b> <code>{target_user_id}</code>\n\n<b>Current Balance:</b> {format_money(current_balance, 'USD', include_currency=True)}\n<b>Credit Amount:</b> {format_money(amount, 'USD', include_currency=True)}\n<b>New Balance:</b> {format_money(new_balance, 'USD', include_currency=True)}\n\n⚠️ <b>This action cannot be undone!</b>

Are you sure you want to credit this amount?
"""
        
        # Get admin language for localized buttons
        admin_lang = await get_admin_language(query.from_user.id, query.from_user.language_code)
        
        keyboard = [
            [InlineKeyboardButton(t('admin.buttons.confirm_credit', admin_lang), callback_data=f"admin_execute_credit:{target_user_id}:{amount}")],
            [InlineKeyboardButton(t('buttons.cancel', admin_lang), callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=message,
            reply_markup=reply_markup,
            parse_mode=ParseMode.HTML
        )
        
    except Exception as e:
        logger.error(f"Error handling admin credit amount: {e}")
        await query.edit_message_text("❌ Error processing credit amount. Please try again.")

async def execute_admin_credit(query, target_user_id: int, amount: float):
    """Execute the admin credit transaction"""
    try:
        admin_user = query.from_user
        
        # Show processing message
        await query.edit_message_text("⏳ Processing credit transaction...")
        
        # Get target user details
        users = await execute_query(
            "SELECT * FROM users WHERE telegram_id = %s",
            (target_user_id,)
        )
        
        if not users:
            await query.edit_message_text("❌ Error: User not found.")
            return
        
        target_user = users[0]
        user_internal_id = target_user['id']
        
        # Execute the credit
        description = f"Admin credit by {admin_user.username or admin_user.first_name} (ID: {admin_user.id})"
        
        # Use unified credit function with admin defaults
        success = await credit_user_wallet(
            user_id=user_internal_id,
            amount_usd=amount,
            provider="admin",
            txid=f"admin_{int(time.time())}_{admin_user.id}",
            order_id=f"admin_credit_{int(time.time())}"
        )
        
        if success:
            # Get updated balance
            new_balance = await get_user_wallet_balance(target_user_id)
            
            display_name = target_user.get('first_name', 'Unknown')
            if target_user.get('last_name'):
                display_name += f" {target_user['last_name']}"
            
            username_display = f"@{target_user['username']}" if target_user.get('username') else "No username"
            
            message = f"""
✅ <b>Credit Transaction Successful</b>

<b>User:</b> {escape_html(display_name)} ({escape_html(username_display)})
<b>Amount Credited:</b> {format_money(amount, 'USD', include_currency=True)}
<b>New Balance:</b> {format_money(new_balance, 'USD', include_currency=True)}

Transaction completed successfully! 
The user's wallet has been credited.

<b>Transaction ID:</b> <code>{int(time.time())}</code>
<b>Admin:</b> {escape_html(admin_user.username or admin_user.first_name)}
"""
            
            # Get admin language for localized buttons
            admin_lang = await get_admin_language(admin_user.id, admin_user.language_code)
            
            keyboard = [
                [InlineKeyboardButton(t('admin.buttons.credit_another_user', admin_lang), callback_data="admin_credit_wallet")],
                [InlineKeyboardButton(t('admin.buttons.back_to_dashboard', admin_lang), callback_data="main_menu")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await query.edit_message_text(
                text=message,
                reply_markup=reply_markup,
                parse_mode=ParseMode.HTML
            )
            
            # Send notification to the user who received the credit
            try:
                app = get_bot_application()
                if app:
                    user_notification = f"""
🎉 <b>Wallet Credit: {format_money(amount, 'USD', include_currency=True)}</b>

New Balance: {format_money(new_balance, 'USD', include_currency=True)}
"""
                    
                    await app.bot.send_message(
                        chat_id=target_user_id,
                        text=user_notification,
                        parse_mode=ParseMode.HTML
                    )
                    logger.info(f"✅ Notification sent to user {target_user_id} about ${amount} credit")
                else:
                    logger.warning(f"⚠️ Could not send notification - bot application not available")
                    
            except Exception as notification_error:
                logger.error(f"❌ Failed to send credit notification to user {target_user_id}: {notification_error}")
                # Don't fail the credit transaction if notification fails
            
            logger.info(f"💳 ADMIN: User {admin_user.id} credited ${amount} to user {target_user_id}")
            
        else:
            await query.edit_message_text(
                "❌ <b>Credit Failed</b>\n\nTransaction could not be completed. Please try again or contact support."
            )
        
    except Exception as e:
        logger.error(f"Error executing admin credit: {e}")
        await query.edit_message_text("❌ Error processing credit transaction. Please try again.")

