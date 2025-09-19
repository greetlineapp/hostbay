# Telegram Bot Project

## Overview
This is a comprehensive Telegram bot for domain registration, hosting services, and cryptocurrency payments. The bot integrates with multiple external services including Cloudflare, OpenProvider, cPanel/WHM, and cryptocurrency payment providers.

## Recent Changes
- **2025-09-19**: Initial setup in Replit environment
  - Installed Python 3.11 and all required dependencies
  - Created pyproject.toml for project configuration
  - Currently setting up PostgreSQL database

## Project Architecture
- **Bot Framework**: python-telegram-bot with webhook integration
- **Database**: PostgreSQL with custom connection pooling
- **Web Server**: aiohttp for webhook handling on port 5000
- **External Services**: 
  - Cloudflare (DNS management)
  - OpenProvider (domain registration)
  - cPanel/WHM (hosting management)
  - DynoPay/BlockBee (cryptocurrency payments)

## Required Environment Variables
- `DATABASE_URL`: PostgreSQL connection string
- `TELEGRAM_BOT_TOKEN`: Bot API token from @BotFather
- `CRYPTO_PAYMENT_PROVIDER`: 'dynopay' or 'blockbee'
- `DYNOPAY_API_KEY`, `DYNOPAY_WALLET_TOKEN`: DynoPay credentials
- `BLOCKBEE_API_KEY`: BlockBee API key
- `WHM_HOST`, `WHM_USERNAME`, `WHM_API_TOKEN`: cPanel/WHM credentials
- `ADMIN_USER_ID`: Telegram ID of the admin user

## Dependencies
The project uses uv for dependency management with a comprehensive set of packages including:
- python-telegram-bot, aiohttp, psycopg2-binary, httpx, dnspython, and many others

## Development Notes
- The application runs as a webhook server on port 5000
- Uses sophisticated connection pooling for PostgreSQL with Neon compatibility
- Includes comprehensive error handling and monitoring systems