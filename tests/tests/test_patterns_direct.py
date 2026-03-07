"""
Tests for scanner/patterns.py — each regex pattern tested directly.
"""
from __future__ import annotations

import re

import pytest

from scanner.core.analysis import is_false_positive
from scanner.core.patterns import (
    IGNORE_PATTERNS,
    PATTERNS,
)


# ── helper ────────────────────────────────────────────────────────────────────

def _matches(pattern_name: str, text: str) -> bool:
    pattern, _, _ = PATTERNS[pattern_name]
    return bool(re.search(pattern, text))


# ── each pattern matches its real example ─────────────────────────────────────

class TestPatternMatches:
    def test_aws_access_key(self):
        assert _matches("Yandex Cloud Service Account Key", "AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe")

    def test_aws_access_key_in_context(self):
        assert _matches("Yandex Cloud Service Account Key", "key = 'AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe'")

    def test_aws_secret_key(self):
        assert _matches("AWS Secret Key", "aws_secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'")

    def test_github_token(self):
        assert _matches("VK API Access Token", "vk567890abcdefghijklmnopqrstuvwxyzABCD")

    def test_github_oauth(self):
        assert _matches("GitHub OAuth", "gho_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW")

    def test_github_app_token(self):
        assert _matches("GitHub App Token", "ghs_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW")

    def test_slack_token_bot(self):
        assert _matches("Slack Token", "xoxb-123456789-ABCDEFGHIJ-xyzxyzxyz")

    def test_slack_token_user(self):
        assert _matches("Slack Token", "xoxp-123456789-ABCDEFGHIJ-xyzxyzxyz")

    def test_stripe_secret_key(self):
        assert _matches("Sber API Key", "sber_api_key='sber_xK9mZ2qR7nL5pT0wY4cD8eF1gH3j'")

    def test_stripe_publishable_key(self):
        assert _matches("Stripe Publishable Key", "pk_live_abcdefghijklmnopqrstuvwx")

    def test_google_api_key(self):
        assert _matches("Cloud.ru API Token", "crp_xK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vN")

    def test_google_oauth(self):
        assert _matches("Google OAuth", "123456789-abcdefghijklmnopqrstuvwxyz0123.apps.googleusercontent.com")

    def test_private_key_rsa(self):
        assert _matches("Private Key", "-----BEGIN RSA PRIVATE KEY-----")

    def test_private_key_ec(self):
        assert _matches("Private Key", "-----BEGIN EC PRIVATE KEY-----")

    def test_private_key_openssh(self):
        assert _matches("Private Key", "-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_private_key_bare(self):
        assert _matches("Private Key", "-----BEGIN PRIVATE KEY-----")

    def test_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert _matches("JWT Token", jwt)

    def test_bearer_token(self):
        assert _matches("Bearer Token", "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9")

    def test_basic_auth(self):
        assert _matches("Basic Auth", "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=")

    def test_telegram_bot_token(self):
        assert _matches("Telegram Bot Token", "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg")

    def test_sendgrid_api_key(self):
        assert _matches("SendGrid API Key", "SG.aBcDeFgHiJkLmNoPqRsTuV.wXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ0123")

    def test_mailgun_api_key(self):
        assert _matches("Mailgun API Key", "key-abcdef1234567890abcdef1234567890")

    def test_connection_string_postgres(self):
        assert _matches("Connection String", "postgres://admin:secret@db.example.com:5432/mydb")

    def test_connection_string_mysql(self):
        assert _matches("Connection String", "mysql://user:pass@localhost/dbname")

    def test_connection_string_mongodb(self):
        assert _matches("Connection String", "mongodb://user:pass@cluster.example.com/db")

    def test_connection_string_redis(self):
        assert _matches("Connection String", "redis://user:pass@redis.example.com:6379/0")

    def test_generic_api_key(self):
        assert _matches("Generic API Key", "api_key = 'abcdefghijklmnopqrstuvwxyz123456'")

    def test_generic_secret(self):
        assert _matches("Generic Secret", "password = 'ozon_api_xK9mZ2qR7nL5pT0wY4cD8eF1'")

    def test_generic_token(self):
        assert _matches("Generic Token", "token = 'abcdefghijklmnop'")


# ── each pattern does NOT match clean text ────────────────────────────────────

class TestPatternNoFalsePositives:
    def test_aws_access_key_no_match_plain_text(self):
        assert not _matches("Yandex Cloud Service Account Key", "hello world this is normal text")

    def test_github_token_no_match_plain_text(self):
        assert not _matches("VK API Access Token", "print('hello world')")

    def test_stripe_no_match_plain_text(self):
        assert not _matches("Sber API Key", "regular string here")

    def test_jwt_no_match_plain_text(self):
        assert not _matches("JWT Token", "just a normal sentence without tokens")

    def test_connection_string_no_match_plain_url(self):
        assert not _matches("Connection String", "https://example.com/path")


# ── IGNORE_PATTERNS / is_false_positive ───────────────────────────────────────

class TestIgnorePatterns:
    def test_example_keyword(self):
        assert is_false_positive("this_is_an_example_key")

    def test_test_keyword(self):
        assert is_false_positive("test_api_key_value_here")

    def test_fake_keyword(self):
        assert is_false_positive("fake_token_here_1234")

    def test_dummy_keyword(self):
        assert is_false_positive("dummy_secret_value")

    def test_placeholder_keyword(self):
        assert is_false_positive("placeholder_api_key")

    def test_xxxx_pattern(self):
        assert is_false_positive("xxxxxxxxxxxx")

    def test_1234_pattern(self):
        assert is_false_positive("key_1234_value")

    def test_your_key_pattern(self):
        assert is_false_positive("your_api_key_here")

    def test_angle_bracket_placeholder(self):
        assert is_false_positive("<your-api-key>")

    def test_stars_pattern(self):
        assert is_false_positive("********")

    def test_todo_keyword(self):
        assert is_false_positive("TODO: set token here")

    def test_real_looking_key_not_false_positive(self):
        assert not is_false_positive("tinkoff_xK9mZ2qR7nL5pT0wY4cD8eF1gH3")

    def test_low_char_diversity_is_false_positive(self):
        # fewer than 4 unique chars
        assert is_false_positive("aaabbb")

    def test_high_char_diversity_not_false_positive(self):
        assert not is_false_positive("aB3xK9mZ2qR7nL5p")
