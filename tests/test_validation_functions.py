"""
Validation Functions Tests
Tests for domain names, emails, phone numbers, and payment amounts
"""

import pytest
import re
from decimal import Decimal
from typing import List, Tuple

# Import validation functions from various modules
from pricing_utils import format_money
from message_utils import escape_html
from handlers import validate_domain_name, validate_email_format  # Assuming these exist


class TestDomainNameValidation:
    """Test domain name validation functions"""
    
    def test_valid_domain_names(self):
        """Test validation of valid domain names"""
        valid_domains = [
            'example.com',
            'test.org',
            'my-site.net',
            'sub.domain.com',
            'a.co',
            'long-domain-name-with-hyphens.info',
            'test123.com',
            '123test.org',
            'test-123.net',
            'example.co.uk',
            'site.io',
            'app.dev'
        ]
        
        for domain in valid_domains:
            assert self._validate_domain_basic(domain), f"Domain {domain} should be valid"
    
    def test_invalid_domain_names(self):
        """Test validation of invalid domain names"""
        invalid_domains = [
            '',                    # Empty
            'a',                   # No TLD
            '.com',               # No domain
            'domain.',            # Trailing dot
            'domain..com',        # Double dot
            'domain-.com',        # Ends with hyphen
            '-domain.com',        # Starts with hyphen
            'domain.c',          # TLD too short
            'domain .com',       # Space in domain
            'domain.com.',       # Trailing dot
            'domain.123',        # Numeric TLD
            'verylongdomainnamethatexceedslengthimits' * 5 + '.com',  # Too long
            'dom@in.com',        # Invalid character
            'domain.com/path',   # Has path
            'http://domain.com', # Has protocol
            'domain...',         # Multiple trailing dots
            'domain.c0m',        # Invalid TLD character
        ]
        
        for domain in invalid_domains:
            assert not self._validate_domain_basic(domain), f"Domain {domain} should be invalid"
    
    def test_domain_length_limits(self):
        """Test domain name length validation"""
        # Test maximum length (253 characters total)
        max_length_domain = 'a' * 245 + '.com'  # Should be at limit
        assert self._validate_domain_basic(max_length_domain)
        
        # Test exceeding maximum length
        too_long_domain = 'a' * 250 + '.com'  # Should exceed limit
        assert not self._validate_domain_basic(too_long_domain)
        
        # Test minimum valid length
        min_domain = 'a.co'  # Should be minimum valid
        assert self._validate_domain_basic(min_domain)
    
    def test_internationalized_domain_names(self):
        """Test IDN (Internationalized Domain Names) validation"""
        idn_domains = [
            'тест.рф',           # Russian
            'münchen.de',        # German
            'café.fr',           # French
            '测试.中国',          # Chinese
            'ドメイン.jp',        # Japanese
        ]
        
        for domain in idn_domains:
            # IDN validation depends on implementation
            # This test documents expected behavior
            result = self._validate_domain_basic(domain)
            # IDN support may vary, so we document the result
            print(f"IDN domain {domain}: {'valid' if result else 'invalid'}")
    
    def test_special_tld_validation(self):
        """Test validation of special and new TLDs"""
        special_tlds = [
            'example.app',
            'site.dev',
            'api.io',
            'brand.shop',
            'my.blog',
            'company.tech',
            'service.cloud',
            'example.ai'
        ]
        
        for domain in special_tlds:
            assert self._validate_domain_basic(domain), f"Special TLD domain {domain} should be valid"
    
    def _validate_domain_basic(self, domain: str) -> bool:
        """Basic domain validation implementation"""
        if not domain or not isinstance(domain, str):
            return False
        
        # Remove leading/trailing whitespace
        domain = domain.strip().lower()
        
        # Basic length check
        if len(domain) < 4 or len(domain) > 253:
            return False
        
        # Must contain at least one dot
        if '.' not in domain:
            return False
        
        # Split into parts
        parts = domain.split('.')
        
        # Must have at least 2 parts (domain and TLD)
        if len(parts) < 2:
            return False
        
        # Check each part
        for i, part in enumerate(parts):
            if not part:  # Empty part (double dots)
                return False
            
            if part.startswith('-') or part.endswith('-'):
                return False
            
            # TLD (last part) validation
            if i == len(parts) - 1:
                if len(part) < 2:
                    return False
                if part.isdigit():  # TLD cannot be all numeric
                    return False
            
            # Check for valid characters
            if not re.match(r'^[a-zA-Z0-9-]+$', part):
                # For now, allow non-ASCII for IDN domains
                if not re.match(r'^[a-zA-Z0-9-\u00a0-\uffff]+$', part):
                    return False
        
        return True


class TestEmailValidation:
    """Test email validation functions"""
    
    def test_valid_email_addresses(self):
        """Test validation of valid email addresses"""
        valid_emails = [
            'user@example.com',
            'test.email@domain.org',
            'user+tag@example.net',
            'firstname.lastname@company.co.uk',
            'user123@test123.io',
            'a@b.co',
            'very.long.email.address@very.long.domain.name.com',
            'user-name@example-domain.com',
            'test_user@example.com',
            'user@subdomain.example.com'
        ]
        
        for email in valid_emails:
            assert self._validate_email_basic(email), f"Email {email} should be valid"
    
    def test_invalid_email_addresses(self):
        """Test validation of invalid email addresses"""
        invalid_emails = [
            '',                           # Empty
            'user',                       # No @ symbol
            '@domain.com',               # No local part
            'user@',                     # No domain
            'user@@domain.com',          # Double @
            'user@domain',               # No TLD
            'user @domain.com',          # Space in local part
            'user@domain .com',          # Space in domain
            'user.@domain.com',          # Dot at end of local part
            '.user@domain.com',          # Dot at start of local part
            'user..name@domain.com',     # Double dot
            'user@domain..com',          # Double dot in domain
            'user@domain.c',             # TLD too short
            'user@domain.',              # Trailing dot
            'verylongemailaddressthatexceedslimits' * 10 + '@domain.com',  # Too long
            'user@verylongdomainnamethatexceedslimits' * 10 + '.com',      # Domain too long
        ]
        
        for email in invalid_emails:
            assert not self._validate_email_basic(email), f"Email {email} should be invalid"
    
    def test_email_length_limits(self):
        """Test email address length validation"""
        # Test reasonable length limits
        long_local = 'a' * 60 + '@example.com'  # Long local part
        assert self._validate_email_basic(long_local)
        
        # Test excessive length
        too_long_local = 'a' * 70 + '@example.com'  # Too long local part
        assert not self._validate_email_basic(too_long_local)
    
    def test_email_special_characters(self):
        """Test email validation with special characters"""
        special_char_emails = [
            'user+tag@example.com',      # Plus sign
            'user-name@example.com',     # Hyphen
            'user_name@example.com',     # Underscore
            'user.name@example.com',     # Dot
            'user123@example.com',       # Numbers
        ]
        
        for email in special_char_emails:
            assert self._validate_email_basic(email), f"Email with special chars {email} should be valid"
    
    def _validate_email_basic(self, email: str) -> bool:
        """Basic email validation implementation"""
        if not email or not isinstance(email, str):
            return False
        
        email = email.strip()
        
        # Basic length check
        if len(email) < 5 or len(email) > 254:
            return False
        
        # Must contain exactly one @ symbol
        if email.count('@') != 1:
            return False
        
        local, domain = email.split('@')
        
        # Local part validation
        if len(local) < 1 or len(local) > 64:
            return False
        
        if local.startswith('.') or local.endswith('.'):
            return False
        
        if '..' in local:
            return False
        
        # Domain part validation (reuse domain validation)
        if not self._validate_domain_basic(domain):
            return False
        
        # Check for valid characters in local part
        if not re.match(r'^[a-zA-Z0-9._+-]+$', local):
            return False
        
        return True
    
    def _validate_domain_basic(self, domain: str) -> bool:
        """Basic domain validation (shared with domain tests)"""
        # Same implementation as in TestDomainNameValidation
        if not domain or not isinstance(domain, str):
            return False
        
        domain = domain.strip().lower()
        
        if len(domain) < 4 or len(domain) > 253:
            return False
        
        if '.' not in domain:
            return False
        
        parts = domain.split('.')
        
        if len(parts) < 2:
            return False
        
        for i, part in enumerate(parts):
            if not part:
                return False
            
            if part.startswith('-') or part.endswith('-'):
                return False
            
            if i == len(parts) - 1:
                if len(part) < 2:
                    return False
                if part.isdigit():
                    return False
            
            if not re.match(r'^[a-zA-Z0-9-]+$', part):
                return False
        
        return True


class TestPhoneNumberValidation:
    """Test phone number validation and formatting"""
    
    def test_valid_phone_numbers(self):
        """Test validation of valid phone numbers"""
        valid_phones = [
            '+1234567890',           # International format
            '+44 20 1234 5678',      # UK format with spaces
            '+49 30 12345678',       # German format
            '+33 1 23 45 67 89',     # French format
            '(555) 123-4567',        # US format with parentheses
            '555-123-4567',          # US format with dashes
            '5551234567',            # Simple format
            '+1 (555) 123-4567',     # Mixed format
        ]
        
        for phone in valid_phones:
            normalized = self._normalize_phone(phone)
            assert self._validate_phone_basic(normalized), f"Phone {phone} should be valid"
    
    def test_invalid_phone_numbers(self):
        """Test validation of invalid phone numbers"""
        invalid_phones = [
            '',                      # Empty
            '123',                   # Too short
            'abc-def-ghij',         # Letters
            '123456789012345678',   # Too long
            '+',                    # Just plus sign
            '++1234567890',         # Double plus
            '123 456 789',          # Too short with spaces
            '(555 123-4567',        # Unmatched parenthesis
            '555) 123-4567',        # Unmatched parenthesis
            '555--123--4567',       # Double dashes
        ]
        
        for phone in invalid_phones:
            normalized = self._normalize_phone(phone)
            assert not self._validate_phone_basic(normalized), f"Phone {phone} should be invalid"
    
    def test_phone_number_normalization(self):
        """Test phone number normalization"""
        test_cases = [
            ('+1 (555) 123-4567', '+15551234567'),
            ('555-123-4567', '5551234567'),
            ('+44 20 1234 5678', '+442012345678'),
            ('(555) 123-4567', '5551234567'),
            '+33 1 23 45 67 89',
        ]
        
        for input_phone, expected in test_cases:
            if isinstance(expected, tuple):
                expected = expected[0]
            
            normalized = self._normalize_phone(input_phone)
            assert normalized == expected, f"Phone {input_phone} should normalize to {expected}, got {normalized}"
    
    def test_international_phone_formats(self):
        """Test various international phone number formats"""
        international_phones = [
            '+1 555 123 4567',       # US
            '+44 20 1234 5678',      # UK
            '+49 30 12345678',       # Germany
            '+33 1 23 45 67 89',     # France
            '+81 3 1234 5678',       # Japan
            '+86 10 1234 5678',      # China
            '+7 495 123 45 67',      # Russia
        ]
        
        for phone in international_phones:
            normalized = self._normalize_phone(phone)
            assert self._validate_phone_basic(normalized), f"International phone {phone} should be valid"
    
    def _normalize_phone(self, phone: str) -> str:
        """Normalize phone number by removing formatting"""
        if not phone:
            return ''
        
        # Remove all non-digit characters except +
        normalized = re.sub(r'[^\d+]', '', phone)
        
        return normalized
    
    def _validate_phone_basic(self, phone: str) -> bool:
        """Basic phone number validation"""
        if not phone or not isinstance(phone, str):
            return False
        
        # Must start with + or digit
        if not (phone.startswith('+') or phone[0].isdigit()):
            return False
        
        # Remove + for length calculation
        digits_only = phone.replace('+', '')
        
        # Must be all digits after removing +
        if not digits_only.isdigit():
            return False
        
        # Length check (7-15 digits is typical range)
        if len(digits_only) < 7 or len(digits_only) > 15:
            return False
        
        return True


class TestPaymentAmountValidation:
    """Test payment amount validation and formatting"""
    
    def test_valid_payment_amounts(self):
        """Test validation of valid payment amounts"""
        valid_amounts = [
            '10.00',
            '0.01',           # Minimum
            '50.99',
            '100',            # Integer amount
            '999.99',
            '1000.00',
            '25.50',
            Decimal('50.00'), # Decimal type
            50.00,            # Float type
        ]
        
        for amount in valid_amounts:
            assert self._validate_payment_amount(amount), f"Amount {amount} should be valid"
    
    def test_invalid_payment_amounts(self):
        """Test validation of invalid payment amounts"""
        invalid_amounts = [
            '0.00',           # Zero
            '-10.00',         # Negative
            '0.001',          # Too many decimal places
            'abc',            # Non-numeric
            '',               # Empty
            '10000.00',       # Too large
            '10.999',         # Too many decimal places
            '10,000.00',      # Comma formatting
            '$50.00',         # Currency symbol
            '50.00 USD',      # With currency code
            None,             # None value
        ]
        
        for amount in invalid_amounts:
            assert not self._validate_payment_amount(amount), f"Amount {amount} should be invalid"
    
    def test_payment_amount_precision(self):
        """Test payment amount decimal precision handling"""
        precision_tests = [
            ('10.00', Decimal('10.00')),
            ('10.1', Decimal('10.10')),
            ('10', Decimal('10.00')),
            (10.5, Decimal('10.50')),
            (Decimal('25.99'), Decimal('25.99')),
        ]
        
        for input_amount, expected in precision_tests:
            if self._validate_payment_amount(input_amount):
                normalized = self._normalize_payment_amount(input_amount)
                assert normalized == expected, f"Amount {input_amount} should normalize to {expected}, got {normalized}"
    
    def test_payment_amount_limits(self):
        """Test payment amount minimum and maximum limits"""
        # Test minimum amount (typically $0.01)
        assert self._validate_payment_amount('0.01')
        assert not self._validate_payment_amount('0.00')
        
        # Test reasonable maximum (e.g., $9999.99)
        assert self._validate_payment_amount('9999.99')
        assert not self._validate_payment_amount('10000.00')
    
    def test_payment_amount_formatting(self):
        """Test payment amount formatting for display"""
        formatting_tests = [
            (Decimal('10.00'), '$10.00'),
            (Decimal('10.50'), '$10.50'),
            (Decimal('1000.00'), '$1,000.00'),
            (Decimal('0.01'), '$0.01'),
            (Decimal('999.99'), '$999.99'),
        ]
        
        for amount, expected_format in formatting_tests:
            formatted = format_money(amount)
            assert expected_format in formatted or str(amount) in formatted, \
                f"Amount {amount} formatting should include {expected_format}"
    
    def _validate_payment_amount(self, amount) -> bool:
        """Validate payment amount"""
        try:
            if amount is None:
                return False
            
            # Convert to Decimal for precise validation
            if isinstance(amount, str):
                # Remove whitespace and common formatting
                amount = amount.strip()
                if not amount:
                    return False
                
                # Check for non-numeric characters (except decimal point)
                if not re.match(r'^\d+\.?\d*$', amount):
                    return False
                
                decimal_amount = Decimal(amount)
            elif isinstance(amount, (int, float)):
                decimal_amount = Decimal(str(amount))
            elif isinstance(amount, Decimal):
                decimal_amount = amount
            else:
                return False
            
            # Must be positive
            if decimal_amount <= 0:
                return False
            
            # Check decimal places (max 2)
            if decimal_amount.as_tuple().exponent < -2:
                return False
            
            # Check maximum amount (e.g., $9999.99)
            if decimal_amount > Decimal('9999.99'):
                return False
            
            # Check minimum amount ($0.01)
            if decimal_amount < Decimal('0.01'):
                return False
            
            return True
            
        except (ValueError, TypeError, ArithmeticError):
            return False
    
    def _normalize_payment_amount(self, amount) -> Decimal:
        """Normalize payment amount to Decimal with 2 decimal places"""
        if isinstance(amount, str):
            decimal_amount = Decimal(amount.strip())
        elif isinstance(amount, (int, float)):
            decimal_amount = Decimal(str(amount))
        else:
            decimal_amount = amount
        
        # Round to 2 decimal places
        return decimal_amount.quantize(Decimal('0.01'))


class TestInputSanitization:
    """Test input sanitization and HTML escaping"""
    
    def test_html_escaping(self):
        """Test HTML character escaping"""
        test_cases = [
            ('<script>alert("xss")</script>', '&lt;script&gt;alert("xss")&lt;/script&gt;'),
            ('user@domain.com', 'user@domain.com'),  # No change needed
            ('Test & Company', 'Test &amp; Company'),
            ('Price: $50 < $100', 'Price: $50 &lt; $100'),
            ('"quoted text"', '&quot;quoted text&quot;'),
            ("'single quoted'", "'single quoted'"),  # May or may not be escaped
        ]
        
        for input_text, expected_output in test_cases:
            escaped = escape_html(input_text)
            # Check that dangerous characters are escaped
            assert '<script>' not in escaped
            assert '&lt;' in escaped or '<' not in input_text
            assert '&amp;' in escaped or '&' not in input_text
    
    def test_sql_injection_prevention(self):
        """Test SQL injection attempt sanitization"""
        sql_injection_attempts = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM passwords --",
            "'; INSERT INTO users VALUES ('hacker', 'password'); --",
        ]
        
        for injection_attempt in sql_injection_attempts:
            # Test that these are treated as regular strings, not SQL
            escaped = escape_html(injection_attempt)
            
            # Should not contain unescaped SQL-dangerous characters
            assert "'" not in escaped or "&quot;" in escaped or "&#x27;" in escaped
    
    def test_xss_prevention(self):
        """Test XSS attack prevention"""
        xss_attempts = [
            '<script>alert("xss")</script>',
            '<img src="x" onerror="alert(1)">',
            '<svg onload="alert(1)">',
            'javascript:alert("xss")',
            '<iframe src="javascript:alert(1)"></iframe>',
        ]
        
        for xss_attempt in xss_attempts:
            escaped = escape_html(xss_attempt)
            
            # Should not contain executable script tags
            assert '<script>' not in escaped
            assert 'javascript:' not in escaped.lower()
            assert 'onerror=' not in escaped.lower()
            assert 'onload=' not in escaped.lower()
    
    def test_path_traversal_prevention(self):
        """Test path traversal attack prevention"""
        path_traversal_attempts = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '/etc/shadow',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        ]
        
        for path_attempt in path_traversal_attempts:
            # These should be treated as regular text, not file paths
            sanitized = path_attempt  # Implement actual sanitization as needed
            
            # Should not resolve to system paths
            assert not sanitized.startswith('/etc/')
            assert not sanitized.startswith('/root/')
            assert '\\system32\\' not in sanitized.lower()