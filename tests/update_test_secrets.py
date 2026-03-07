#!/usr/bin/env python3
"""Replace Western secret patterns with Russian ones in test files."""

import re
from pathlib import Path

# Mapping of Western patterns to Russian equivalents
REPLACEMENTS = {
    # AWS Access Key -> Yandex Cloud Service Account
    "AKIAJX7LKQHMBQWRFP2A": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB",
    "AKIA[0-9A-Z]{16}": "AQ[A-Za-z0-9_-]{38,}",
    
    # GitHub Token -> VK API Access Token  
    "ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW": "vk1234567890abcdefghijklmnopqrstuvwxyz",
    "ghp_[a-zA-Z0-9]{36}": "vk[a-z0-9]{10,}[A-Za-z0-9_-]{10,}",
    
    # Stripe Secret -> Sber API Key
    "sk_live_abcdefghijklmnopqrstuvwx": "sberbank_api_secret_key_567890abcdef",
    
    # Google API Key -> Cloud.ru API Token
    "AIzaSyD8mNpQrStUvWxYzAbCdEfGhIjKlMnOpQr": "crp_abcdefghijklmnopqrstuvwxyz567890ABCD",
    
    # Generic secrets for tests
    "kJH78sdKJH9823kjsdKJHsdkj23Rz": "tinkoff_abcdefghijklmnop567890ABCD",
    "UltraSecret_456!": "sber_test_secret_key_567890ABCD",
    "SuperSecret123!": "ozon_api_key_567890abcdef",
    "SuperSecretP@ss": "cloudru_secret_567890ABC",
    "d41d8cd98f00b204e9800998ecf8427e": "vk_token_567890abcdefghij",
}

def update_file(filepath: Path) -> bool:
    """Update a single file. Returns True if changed."""
    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    
    original = content
    for old, new in REPLACEMENTS.items():
        content = re.sub(old, new, content)
    
    # Also update expected secret type assertions
    content = content.replace('"AWS Access Key"', '"Yandex Cloud Service Account Key"')
    content = content.replace('"GitHub Token"', '"VK API Access Token"')
    content = content.replace('"Stripe Secret Key"', '"Sber API Key"')
    content = content.replace('"Google API Key"', '"Cloud.ru API Token"')
    
    if content != original:
        filepath.write_text(content, encoding="utf-8")
        return True
    return False

def main():
    tests_dir = Path("/workspaces/nuclear/tests/tests")
    updated = 0
    
    for py_file in tests_dir.glob("*.py"):
        if update_file(py_file):
            print(f"Updated: {py_file.name}")
            updated += 1
    
    print(f"\nTotal files updated: {updated}")

if __name__ == "__main__":
    main()
