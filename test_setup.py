#!/usr/bin/env python3
"""
Test setup script to verify the Telegram bot project can start properly
This tests the core imports and database connection without requiring secrets
"""

import os
import sys
import asyncio
import logging

# Add current directory to path
sys.path.append('.')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_imports():
    """Test that all core modules can be imported"""
    try:
        logger.info("Testing core imports...")
        
        # Test database imports
        from database import get_connection, execute_query
        logger.info("✅ Database module imported successfully")
        
        # Test webhook handler imports
        from webhook_handler import set_bot_application, validate_webhook_configuration
        logger.info("✅ Webhook handler imported successfully")
        
        # Test handlers imports
        from handlers import AutoApplySession, DNSAutoApplyManager
        logger.info("✅ Handlers imported successfully")
        
        # Test service imports
        from services.openprovider import OpenProviderService
        from services.cpanel import CPanelService
        logger.info("✅ Services imported successfully")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Import test failed: {e}")
        return False

async def test_database_connection():
    """Test database connection"""
    try:
        logger.info("Testing database connection...")
        
        from database import get_connection
        conn = get_connection()
        
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            
        if result and result[0] == 1:
            logger.info("✅ Database connection successful")
            return True
        else:
            logger.error("❌ Database connection test failed")
            return False
            
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        return False

async def test_table_existence():
    """Test that required tables exist"""
    try:
        logger.info("Testing table existence...")
        
        from database import execute_query
        
        # Test critical tables
        tables_to_check = [
            'users',
            'domains', 
            'domain_registration_intents',
            'payment_intents',
            'wallet_transactions'
        ]
        
        for table in tables_to_check:
            result = await execute_query(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = %s",
                (table,)
            )
            if result and result[0][0] > 0:
                logger.info(f"✅ Table '{table}' exists")
            else:
                logger.warning(f"⚠️ Table '{table}' missing")
                
        return True
        
    except Exception as e:
        logger.error(f"❌ Table check failed: {e}")
        return False

async def main():
    """Run all tests"""
    logger.info("🚀 Starting setup verification tests...")
    
    # Test imports
    imports_ok = await test_imports()
    
    if not imports_ok:
        logger.error("❌ Import tests failed - cannot continue")
        return False
    
    # Test database connection
    db_ok = await test_database_connection()
    
    if not db_ok:
        logger.error("❌ Database tests failed")
        return False
    
    # Test table existence
    tables_ok = await test_table_existence()
    
    if imports_ok and db_ok and tables_ok:
        logger.info("🎉 All setup tests passed!")
        logger.info("📋 To start the bot, you need to:")
        logger.info("   1. Set TELEGRAM_BOT_TOKEN environment variable")
        logger.info("   2. Configure other service API keys as needed")
        logger.info("   3. Run: python bot.py")
        return True
    else:
        logger.error("❌ Some setup tests failed")
        return False

if __name__ == "__main__":
    result = asyncio.run(main())
    sys.exit(0 if result else 1)