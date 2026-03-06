#!/usr/bin/env python3
"""Replace low-entropy test secrets with realistic ones."""

from pathlib import Path

# Low entropy -> High entropy replacements
REALISTIC_SECRETS = {
    # Yandex Cloud Service Account (was AWS)
    "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB": 
        "AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe",
    
    # VK API Token (was GitHub)  
    "vk1234567890abcdefghijklmnopqrstuvwxyz":
        "vkxK9mZ2qR7nL5pT0wYcD8eF1gH3jB6vN",
    
    # Sber API Key (was Stripe)
    "sberbank_api_secret_key_567890abcdef":
        "sber_xK9mZ2qR7nL5pT0wY4cD8eF1gH3j",
    
    # Cloud.ru API (was Google)
    "crp_abcdefghijklmnopqrstuvwxyz567890ABCD":
        "crp_xK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vN",
    
    # Tinkoff (was generic)
    "tinkoff_abcdefghijklmnop567890ABCD":
        "tinkoff_xK9mZ2qR7nL5pT0wY4cD8eF1gH3",
    
    # Generic secrets
    "sber_test_secret_key_567890ABCD":
        "sber_test_xK9mZ2qR7nL5pT0wY4cD8eF",
    
    "ozon_api_key_567890abcdef":
        "ozon_api_xK9mZ2qR7nL5pT0wY4cD8eF1",
    
    "cloudru_secret_567890ABC":
        "cloudru_xK9mZ2qR7nL5pT0wY4cD8",
    
    "vk_token_567890abcdefghij":
        "vk_token_xK9mZ2qR7nL5pT0wY4c",
}

def update_file(filepath: Path) -> bool:
    """Update a single file. Returns True if changed."""
    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    
    original = content
    for old, new in REALISTIC_SECRETS.items():
        content = content.replace(old, new)
    
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
