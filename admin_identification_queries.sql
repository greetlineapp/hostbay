-- Admin Identification Queries for HostBay Telegram Bot
-- These queries demonstrate how to use the comprehensive views for admin purposes

-- ====================
-- 1. PARAMETERIZED USER RESOLVER
-- ====================

-- Find user by telegram_id, username, or user_id
-- This is the primary admin resolver query
-- Usage: Replace $1 with the search value (telegram_id, username, or user_id)

-- By Telegram ID (most common admin lookup)
SELECT * FROM v_user_overview 
WHERE telegram_id = $1;
-- Example: WHERE telegram_id = 1027722772

-- By Username (when provided)  
SELECT * FROM v_user_overview 
WHERE username ILIKE $1;
-- Example: WHERE username ILIKE 'john_doe'

-- By User ID (internal lookups)
SELECT * FROM v_user_overview 
WHERE id = $1;
-- Example: WHERE id = 123

-- Combined universal resolver (searches all fields)
SELECT * FROM v_user_overview 
WHERE id = $1 
   OR telegram_id = $1 
   OR username ILIKE $1
ORDER BY last_activity_at DESC;

-- ====================
-- 2. COMPREHENSIVE USER LOOKUP WITH ALL DATA
-- ====================

-- Get complete user profile with all associated data in JSON format
-- This provides everything an admin needs to know about a user
SELECT 
    id,
    telegram_id,
    username,
    first_name,
    last_name,
    wallet_balance,
    terms_accepted,
    preferred_language,
    created_at,
    updated_at,
    domains_json,
    hosting_subscriptions_json,
    domain_orders_json,
    payment_orders_json,
    wallet_transactions_json,
    wallet_deposits_json
FROM v_user_profile_detail 
WHERE telegram_id = $1;
-- Example: WHERE telegram_id = 1027722772

-- ====================
-- 3. DASHBOARD PAGINATION QUERIES
-- ====================

-- Main admin dashboard - all users with summary counts
-- Supports pagination and sorting
SELECT 
    id,
    telegram_id,
    username,
    COALESCE(first_name, '') || ' ' || COALESCE(last_name, '') as full_name,
    wallet_balance,
    total_domains,
    active_domains,
    total_hosting_subscriptions,
    active_hosting_subscriptions,
    open_domain_orders,
    open_payment_orders,
    last_activity_at,
    terms_accepted
FROM v_user_overview 
ORDER BY last_activity_at DESC 
LIMIT $1 OFFSET $2;
-- Example: LIMIT 25 OFFSET 0 (first page, 25 users)
-- Example: LIMIT 25 OFFSET 25 (second page, 25 users)

-- Dashboard with search filtering
SELECT * FROM v_user_overview 
WHERE (
    username ILIKE '%' || $1 || '%' 
    OR first_name ILIKE '%' || $1 || '%' 
    OR last_name ILIKE '%' || $1 || '%'
    OR telegram_id::text ILIKE '%' || $1 || '%'
)
ORDER BY last_activity_at DESC 
LIMIT $2 OFFSET $3;
-- Example: $1 = 'john', $2 = 25, $3 = 0

-- ====================
-- 4. FINANCIAL AUDIT QUERIES
-- ====================

-- Find users with wallet discrepancies  
SELECT 
    user_id,
    telegram_id,
    username,
    full_name,
    recorded_balance,
    calculated_balance,
    discrepancy,
    reconciliation_status
FROM v_user_wallet_reconciliation
WHERE reconciliation_status != 'BALANCED'
ORDER BY ABS(discrepancy) DESC;

-- High-value wallet users
SELECT * FROM v_user_overview 
WHERE wallet_balance > 100.00
ORDER BY wallet_balance DESC;

-- Users with recent payment activity
SELECT 
    intent_id,
    user_id,
    intent_type,
    amount,
    currency,
    status,
    provider_order_id,
    txid,
    created_at
FROM v_payment_intents 
WHERE created_at >= NOW() - INTERVAL '7 days'
ORDER BY created_at DESC;

-- ====================
-- 5. OPERATIONAL QUERIES
-- ====================

-- Recently active users (last 24 hours)
SELECT * FROM v_user_overview 
WHERE last_activity_at >= NOW() - INTERVAL '1 day'
ORDER BY last_activity_at DESC;

-- Users with failed orders/payments
SELECT 
    u.id,
    u.telegram_id,
    u.username,
    u.wallet_balance,
    pi.intent_type,
    pi.amount,
    pi.status,
    pi.created_at
FROM v_user_overview u
JOIN v_payment_intents pi ON u.id = pi.user_id
WHERE pi.status IN ('failed', 'error', 'cancelled')
ORDER BY pi.created_at DESC;

-- Users with pending domain orders
SELECT * FROM v_user_overview 
WHERE open_domain_orders > 0
ORDER BY open_domain_orders DESC, last_activity_at DESC;

-- ====================
-- 6. SUPPORT QUERIES
-- ====================

-- Find user context for support tickets
-- When a user contacts support, use this to get full context
WITH user_context AS (
    SELECT * FROM v_user_profile_detail WHERE telegram_id = $1
),
recent_payments AS (
    SELECT * FROM v_payment_intents 
    WHERE user_id = (SELECT id FROM user_context)
    AND created_at >= NOW() - INTERVAL '30 days'
    ORDER BY created_at DESC
    LIMIT 10
)
SELECT 
    uc.*,
    (SELECT json_agg(rp.*) FROM recent_payments rp) as recent_payments_json
FROM user_context uc;

-- User activity timeline
SELECT 
    intent_type as activity_type,
    intent_id as activity_id,
    status,
    amount,
    created_at
FROM v_payment_intents 
WHERE user_id = $1
ORDER BY created_at DESC
LIMIT 20;

-- ====================
-- 7. REPORTING QUERIES
-- ====================

-- Daily active users
SELECT 
    DATE(last_activity_at) as date,
    COUNT(*) as active_users
FROM v_user_overview 
WHERE last_activity_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE(last_activity_at)
ORDER BY date DESC;

-- Revenue summary by intent type
SELECT 
    intent_type,
    COUNT(*) as count,
    SUM(amount) as total_amount,
    AVG(amount) as avg_amount
FROM v_payment_intents 
WHERE status IN ('completed', 'confirmed')
AND created_at >= NOW() - INTERVAL '30 days'
GROUP BY intent_type
ORDER BY total_amount DESC;

-- ====================
-- 8. PERFORMANCE MONITORING
-- ====================

-- Check view performance (these should be fast with indexes)
EXPLAIN ANALYZE SELECT * FROM v_user_overview WHERE telegram_id = 1027722772;
EXPLAIN ANALYZE SELECT * FROM v_user_profile_detail WHERE telegram_id = 1027722772;  
EXPLAIN ANALYZE SELECT * FROM v_payment_intents WHERE user_id = 1 ORDER BY created_at DESC LIMIT 10;

-- ====================
-- 9. DATA INTEGRITY CHECKS
-- ====================

-- Users without telegram_id (should be none)
SELECT COUNT(*) as users_without_telegram_id 
FROM users 
WHERE telegram_id IS NULL;

-- Orphaned records check
SELECT 
    'domains' as table_name,
    COUNT(*) as orphaned_count
FROM domains d 
LEFT JOIN users u ON d.user_id = u.id 
WHERE u.id IS NULL

UNION ALL

SELECT 
    'hosting_subscriptions' as table_name,
    COUNT(*) as orphaned_count
FROM hosting_subscriptions hs 
LEFT JOIN users u ON hs.user_id = u.id 
WHERE u.id IS NULL

UNION ALL

SELECT 
    'wallet_transactions' as table_name,
    COUNT(*) as orphaned_count
FROM wallet_transactions wt 
LEFT JOIN users u ON wt.user_id = u.id 
WHERE u.id IS NULL;

-- ====================
-- SAMPLE USAGE EXAMPLES
-- ====================

-- Example 1: Admin searches for user "john" on support
-- SELECT * FROM v_user_overview WHERE username ILIKE '%john%' OR first_name ILIKE '%john%' OR last_name ILIKE '%john%';

-- Example 2: Get complete profile for telegram user 1027722772  
-- SELECT * FROM v_user_profile_detail WHERE telegram_id = 1027722772;

-- Example 3: Check wallet discrepancies
-- SELECT * FROM v_user_wallet_reconciliation WHERE reconciliation_status != 'BALANCED';

-- Example 4: Recent payment activity for investigation
-- SELECT * FROM v_payment_intents WHERE created_at >= NOW() - INTERVAL '1 day' ORDER BY created_at DESC;

-- Example 5: Dashboard pagination (page 1, 25 users per page)
-- SELECT * FROM v_user_overview ORDER BY last_activity_at DESC LIMIT 25 OFFSET 0;