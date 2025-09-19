"""
Admin interface handlers for broadcast and wallet credit functionality
"""

import os
import logging
from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from message_utils import create_error_message, format_bold, format_inline_code, escape_html

logger = logging.getLogger(__name__)

async def handle_admin_broadcast(query, context):
    """Handle admin broadcast button press"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_admin_broadcast")
        return
    
    # Security check
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        await query.edit_message_text(create_error_message("Access Denied"))
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to access broadcast interface")
        return
    
    try:
        await query.answer()
        
        # Set broadcast mode flag
        context.user_data['awaiting_broadcast'] = True
        
        # Show broadcast interface with updated instructions
        message = f"""📢 {format_bold("Admin Broadcast Ready")}

✅ {format_bold("Broadcast mode activated!")}

{format_bold("Next Steps:")}
1. {format_bold("Type your broadcast message")} as your next message
2. Or use /broadcast &lt;message&gt; command
3. Send /cancel to cancel broadcast mode

{format_bold("Specs:")}
• Batch size: 30 users
• Delay: 1 second between batches  
• Max retries: 3 attempts
• Only sends to users who accepted terms

{format_bold("Status:")} 🟢 Waiting for your broadcast message..."""

        keyboard = [
            [InlineKeyboardButton("🚫 Cancel Broadcast", callback_data="cancel_broadcast")],
            [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=message,
            reply_markup=reply_markup
        )
        
        logger.info(f"📢 ADMIN: User {user.id} accessed broadcast interface")
        
    except Exception as e:
        logger.error(f"Error in handle_admin_broadcast: {e}")
        await query.edit_message_text(create_error_message("Error", "Could not load broadcast interface."))

async def handle_admin_credit_wallet(query, context):
    """Handle admin credit wallet button press"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_admin_credit_wallet")
        return
    
    # Security check  
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        await query.edit_message_text(create_error_message("Access Denied"))
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to access credit wallet interface")
        return
    
    try:
        await query.answer()
        
        # Show credit wallet interface
        message = f"""💳 {format_bold("Admin Credit Wallet Interface")}

{format_bold("Usage Instructions:")}
Use the command below to credit user wallets directly.

{format_bold("Command:")}
{format_inline_code("/credit_wallet <user_id> <amount>")}

{format_bold("Example:")}
{format_inline_code("/credit_wallet 123456789 50.00")}

{format_bold("Limits:")}
• Maximum: $10,000 per operation
• Amount must be positive
• User ID must be valid Telegram user ID

{format_bold("Security:")}
• All operations are logged
• Only admin can use this feature
• Transaction history is tracked"""

        keyboard = [
            [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=message,
            reply_markup=reply_markup
        )
        
        logger.info(f"💳 ADMIN: User {user.id} accessed credit wallet interface")
        
    except Exception as e:
        logger.error(f"Error in handle_admin_credit_wallet: {e}")
        await query.edit_message_text(create_error_message("Error", "Could not load credit wallet interface."))

async def handle_cancel_broadcast(query, context):
    """Handle cancel broadcast button press"""
    user = query.from_user
    
    if not user:
        logger.error("Missing user in handle_cancel_broadcast")
        return
    
    # Security check
    admin_user_id = os.getenv('ADMIN_USER_ID')
    if not admin_user_id or not admin_user_id.isdigit() or user.id != int(admin_user_id):
        await query.edit_message_text(create_error_message("Access Denied"))
        logger.error(f"🚫 SECURITY: Non-admin user {user.id} attempted to cancel broadcast")
        return
    
    try:
        await query.answer()
        
        # Clear broadcast flag
        if 'awaiting_broadcast' in context.user_data:
            del context.user_data['awaiting_broadcast']
        
        # Show cancellation message
        message = f"""🚫 {format_bold("Broadcast Cancelled")}

Broadcast mode has been deactivated.

You can start a new broadcast anytime from the admin panel."""

        keyboard = [
            [InlineKeyboardButton("⬅️ Back to Dashboard", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            text=message,
            reply_markup=reply_markup
        )
        
        logger.info(f"📢 ADMIN: User {user.id} cancelled broadcast mode")
        
    except Exception as e:
        logger.error(f"Error in handle_cancel_broadcast: {e}")
        await query.edit_message_text(create_error_message("Error", "Could not cancel broadcast."))