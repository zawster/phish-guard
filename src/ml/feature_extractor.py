"""URL Feature Extractor for phishing detection ML model."""
import re
import math
from dataclasses import dataclass, asdict
from typing import List, Optional, Set
from urllib.parse import urlparse, parse_qs, unquote
import tldextract


@dataclass
class URLFeatures:
    """All features extracted from a URL for ML classification."""

    # Length-based features
    url_length: int = 0
    domain_length: int = 0
    path_length: int = 0
    query_length: int = 0
    subdomain_length: int = 0

    # Count-based features
    num_dots: int = 0
    num_hyphens: int = 0
    num_underscores: int = 0
    num_slashes: int = 0
    num_question_marks: int = 0
    num_equal_signs: int = 0
    num_at_symbols: int = 0
    num_ampersands: int = 0
    num_exclamation: int = 0
    num_tilde: int = 0
    num_percent: int = 0
    num_hash: int = 0

    # Digit-based features
    num_digits: int = 0
    num_digits_in_domain: int = 0
    digit_ratio: float = 0.0

    # Letter-based features
    num_letters: int = 0
    letter_ratio: float = 0.0

    # Special patterns
    has_ip_address: bool = False
    has_port: bool = False
    uses_https: bool = False
    has_double_slash_in_path: bool = False
    has_at_symbol: bool = False
    has_hex_chars: bool = False

    # Domain features
    num_subdomains: int = 0
    tld_length: int = 0
    is_common_tld: bool = False
    is_suspicious_tld: bool = False
    domain_has_digits: bool = False
    domain_has_hyphen: bool = False

    # Path features
    path_depth: int = 0
    has_suspicious_path: bool = False
    has_file_extension: bool = False
    has_suspicious_extension: bool = False

    # Query features
    num_query_params: int = 0
    has_suspicious_params: bool = False
    query_value_length_avg: float = 0.0

    # Brand/keyword detection
    has_brand_in_subdomain: bool = False
    has_brand_in_path: bool = False
    brand_mismatch: bool = False

    # Entropy and randomness
    domain_entropy: float = 0.0
    path_entropy: float = 0.0
    url_entropy: float = 0.0

    # Suspicious patterns
    contains_shortened_url: bool = False
    has_punycode: bool = False
    consecutive_chars_max: int = 0
    special_char_ratio: float = 0.0

    # Additional suspicious indicators
    has_login_keyword: bool = False
    has_secure_keyword: bool = False
    has_account_keyword: bool = False
    has_update_keyword: bool = False
    has_verify_keyword: bool = False
    domain_token_count: int = 0
    path_token_count: int = 0
    avg_token_length: float = 0.0
    longest_token_length: int = 0

    def to_dict(self) -> dict:
        """Convert features to dictionary."""
        return asdict(self)


class FeatureExtractor:
    """Extracts features from URLs for phishing detection."""

    COMMON_TLDS: Set[str] = {
        'com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'info', 'biz', 'us', 'uk', 'ca',
        'ai', 'app', 'dev', 'tech', 'cloud', 'me', 'tv', 'fm', 'gg', 'so'
    }

    SUSPICIOUS_TLDS: Set[str] = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link',
        'icu', 'buzz', 'sbs', 'cfd', 'loan', 'download', 'racing', 'win',
        'party', 'review', 'stream', 'gdn', 'men', 'trade', 'bid', 'webcam'
    }

    BRAND_KEYWORDS: Set[str] = {
        'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'fb',
        'instagram', 'netflix', 'bank', 'dhl', 'fedex', 'usps', 'wellsfargo',
        'chase', 'citi', 'amex', 'visa', 'mastercard', 'linkedin', 'twitter',
        'dropbox', 'icloud', 'outlook', 'office365', 'adobe', 'spotify',
        'steam', 'ebay', 'walmart', 'costco', 'target', 'bestbuy'
    }

    SUSPICIOUS_PATH_KEYWORDS: Set[str] = {
        'login', 'signin', 'sign-in', 'verify', 'account', 'update', 'secure',
        'banking', 'confirm', 'password', 'credential', 'validate', 'auth',
        'authentication', 'webscr', 'cmd', 'recover', 'restore', 'suspended'
    }

    SUSPICIOUS_PARAMS: Set[str] = {
        'email', 'password', 'user', 'token', 'session', 'id', 'account',
        'card', 'ssn', 'pin', 'cvv', 'secure', 'cmd', 'dispatch'
    }

    URL_SHORTENERS: Set[str] = {
        'bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd',
        'buff.ly', 'shorte.st', 'adf.ly', 'j.mp', 'rb.gy', 'cutt.ly'
    }

    SUSPICIOUS_EXTENSIONS: Set[str] = {
        '.exe', '.php', '.html', '.htm', '.js', '.asp', '.aspx', '.cgi'
    }

    # IP address pattern
    IP_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )

    # Hex encoding pattern
    HEX_PATTERN = re.compile(r'%[0-9a-fA-F]{2}')

    def extract(self, url: str) -> URLFeatures:
        """Extract all features from a URL."""
        features = URLFeatures()

        try:
            # Decode URL
            url = unquote(url)

            # Parse URL
            parsed = urlparse(url)
            extracted = tldextract.extract(url)

            domain = extracted.domain
            subdomain = extracted.subdomain
            suffix = extracted.suffix
            full_domain = f"{subdomain}.{domain}.{suffix}" if subdomain else f"{domain}.{suffix}"
            path = parsed.path
            query = parsed.query

            # Length-based features
            features.url_length = len(url)
            features.domain_length = len(domain)
            features.path_length = len(path)
            features.query_length = len(query)
            features.subdomain_length = len(subdomain)

            # Count-based features
            features.num_dots = url.count('.')
            features.num_hyphens = url.count('-')
            features.num_underscores = url.count('_')
            features.num_slashes = url.count('/')
            features.num_question_marks = url.count('?')
            features.num_equal_signs = url.count('=')
            features.num_at_symbols = url.count('@')
            features.num_ampersands = url.count('&')
            features.num_exclamation = url.count('!')
            features.num_tilde = url.count('~')
            features.num_percent = url.count('%')
            features.num_hash = url.count('#')

            # Digit-based features
            features.num_digits = sum(c.isdigit() for c in url)
            features.num_digits_in_domain = sum(c.isdigit() for c in full_domain)
            features.digit_ratio = features.num_digits / len(url) if len(url) > 0 else 0

            # Letter-based features
            features.num_letters = sum(c.isalpha() for c in url)
            features.letter_ratio = features.num_letters / len(url) if len(url) > 0 else 0

            # Special patterns
            features.has_ip_address = self._has_ip_address(full_domain)
            features.has_port = parsed.port is not None
            features.uses_https = parsed.scheme == 'https'
            features.has_double_slash_in_path = '//' in path
            features.has_at_symbol = '@' in url
            features.has_hex_chars = bool(self.HEX_PATTERN.search(url))

            # Domain features
            features.num_subdomains = subdomain.count('.') + 1 if subdomain else 0
            features.tld_length = len(suffix)
            features.is_common_tld = suffix.lower() in self.COMMON_TLDS
            features.is_suspicious_tld = suffix.lower() in self.SUSPICIOUS_TLDS
            features.domain_has_digits = any(c.isdigit() for c in domain)
            features.domain_has_hyphen = '-' in domain

            # Path features
            features.path_depth = path.count('/') - 1 if path.startswith('/') else path.count('/')
            features.has_suspicious_path = self._has_suspicious_path(path)
            features.has_file_extension = bool(re.search(r'\.\w{2,4}$', path))
            features.has_suspicious_extension = any(
                path.lower().endswith(ext) for ext in self.SUSPICIOUS_EXTENSIONS
            )

            # Query features
            if query:
                params = parse_qs(query)
                features.num_query_params = len(params)
                features.has_suspicious_params = self._has_suspicious_params(params)
                values = [v for vals in params.values() for v in vals]
                features.query_value_length_avg = (
                    sum(len(v) for v in values) / len(values) if values else 0
                )

            # Brand/keyword detection
            url_lower = url.lower()
            subdomain_lower = subdomain.lower()
            path_lower = path.lower()

            features.has_brand_in_subdomain = any(
                brand in subdomain_lower for brand in self.BRAND_KEYWORDS
            )
            features.has_brand_in_path = any(
                brand in path_lower for brand in self.BRAND_KEYWORDS
            )
            features.brand_mismatch = self._detect_brand_mismatch(
                domain.lower(), subdomain_lower, path_lower
            )

            # Entropy and randomness
            features.domain_entropy = self._calculate_entropy(full_domain)
            features.path_entropy = self._calculate_entropy(path)
            features.url_entropy = self._calculate_entropy(url)

            # Suspicious patterns
            features.contains_shortened_url = any(
                shortener in url_lower for shortener in self.URL_SHORTENERS
            )
            features.has_punycode = 'xn--' in url_lower
            features.consecutive_chars_max = self._max_consecutive_chars(url)
            features.special_char_ratio = self._special_char_ratio(url)

            # Additional suspicious indicators
            features.has_login_keyword = 'login' in url_lower or 'signin' in url_lower
            features.has_secure_keyword = 'secure' in url_lower or 'security' in url_lower
            features.has_account_keyword = 'account' in url_lower
            features.has_update_keyword = 'update' in url_lower
            features.has_verify_keyword = 'verify' in url_lower or 'confirm' in url_lower

            # Token analysis
            tokens = re.split(r'[./\-_?=&]', url)
            tokens = [t for t in tokens if t and len(t) > 1]
            features.domain_token_count = len(re.split(r'[.\-]', full_domain))
            features.path_token_count = len([t for t in path.split('/') if t])
            features.avg_token_length = (
                sum(len(t) for t in tokens) / len(tokens) if tokens else 0
            )
            features.longest_token_length = max((len(t) for t in tokens), default=0)

        except Exception as e:
            # Return default features on parsing error
            pass

        return features

    def _has_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address."""
        # Remove port if present
        domain = domain.split(':')[0]
        return bool(self.IP_PATTERN.match(domain))

    def _has_suspicious_path(self, path: str) -> bool:
        """Check if path contains suspicious keywords."""
        path_lower = path.lower()
        return any(keyword in path_lower for keyword in self.SUSPICIOUS_PATH_KEYWORDS)

    def _has_suspicious_params(self, params: dict) -> bool:
        """Check if query params contain suspicious keywords."""
        param_names = {k.lower() for k in params.keys()}
        return bool(param_names & self.SUSPICIOUS_PARAMS)

    def _detect_brand_mismatch(
        self, domain: str, subdomain: str, path: str
    ) -> bool:
        """Detect if brand name appears but domain doesn't match."""
        for brand in self.BRAND_KEYWORDS:
            # Brand in subdomain or path but not in main domain
            if (brand in subdomain or brand in path) and brand not in domain:
                return True
        return False

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    @staticmethod
    def _max_consecutive_chars(text: str) -> int:
        """Find maximum consecutive identical characters."""
        if not text:
            return 0
        max_count = 1
        current_count = 1
        for i in range(1, len(text)):
            if text[i] == text[i-1]:
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 1
        return max_count

    @staticmethod
    def _special_char_ratio(text: str) -> float:
        """Calculate ratio of special characters."""
        if not text:
            return 0.0
        special = sum(1 for c in text if not c.isalnum())
        return special / len(text)

    def to_feature_vector(self, features: URLFeatures) -> List[float]:
        """Convert URLFeatures to a numeric vector for ML model."""
        feature_dict = features.to_dict()
        vector = []

        for key, value in feature_dict.items():
            if isinstance(value, bool):
                vector.append(1.0 if value else 0.0)
            elif isinstance(value, (int, float)):
                vector.append(float(value))
            # Skip non-numeric values

        return vector

    @staticmethod
    def get_feature_names() -> List[str]:
        """Get ordered list of feature names."""
        sample = URLFeatures()
        feature_dict = sample.to_dict()
        return [
            key for key, value in feature_dict.items()
            if isinstance(value, (bool, int, float))
        ]
