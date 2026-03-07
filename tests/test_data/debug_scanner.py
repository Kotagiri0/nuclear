import re
from scanner.core.patterns import PATTERNS, IGNORE_PATTERNS, HASH_PATTERNS

test_lines = [
    ('CLOUDRU_API=crp_abcdefghijklmnopqrstuvwxyz1234567890ABCD', 30),
    ('CLOUDRU_SA=crsa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd', 30),
    ('SBER_ID=sber_abcdefghijklmnop1234567890ABCDEFGH', 30),
    ('sber_api_key="sberbank_api_secret_key_1234567890abcdef"', 30),
    ('TINKOFF_API=tinkoff_abcdefghijklmnop1234567890ABCD', 30),
    ('TINKOFF_MERCHANT=merchant_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab', 30),
    ("api-key='ozon_api_key_abcdefghijklmnop1234567890ABCD'", 30),
    ('TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789AB', 30),
]

def is_false_positive(value: str) -> bool:
    for p in IGNORE_PATTERNS:
        if re.search(p, value, re.IGNORECASE):
            return True
    return len(set(value)) < 4

def is_likely_hash(value: str) -> bool:
    v = value.strip()
    for p in HASH_PATTERNS:
        if re.match(p, v, re.IGNORECASE):
            return True
    return False

print("Testing each line against patterns:\n")
for line, lineno in test_lines:
    print(f"Line {lineno}: {line}")
    found = False
    for secret_type, (pattern, base_score, category) in PATTERNS.items():
        for match in re.finditer(pattern, line):
            value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            
            fp = is_false_positive(value)
            is_hash = is_likely_hash(value)
            
            if fp:
                print(f"  ✗ {secret_type}: FALSE POSITIVE filtered")
            elif is_hash:
                print(f"  ✗ {secret_type}: HASH filtered (score -3)")
            else:
                print(f"  ✓ {secret_type}: {value[:50]}... (base_score={base_score})")
                found = True
    if not found:
        print("  ✗ NO MATCHES")
    print()
