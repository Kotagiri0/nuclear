import re
test_lines = [
    'CLOUDRU_API=crp_abcdefghijklmnopqrstuvwxyz1234567890ABCD',
    'CLOUDRU_SA=crsa_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcd',
    'SBER_ID=sber_abcdefghijklmnop1234567890ABCDEFGH',
    'sber_api_key="sberbank_api_secret_key_1234567890abcdef"',
    'TINKOFF_API=tinkoff_abcdefghijklmnop1234567890ABCD',
    'TINKOFF_MERCHANT=merchant_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab',
    "api-key='ozon_api_key_abcdefghijklmnop1234567890ABCD'",
    'TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz123456789AB',
]

patterns = {
    'Cloud.ru API': r'\bcrp_[a-zA-Z0-9_-]{32,}\b',
    'Cloud.ru SA': r'\bcrsa_[a-zA-Z0-9_-]{32,}\b',
    'Sber ID': r'\bsber_[a-zA-Z0-9_-]{24,}\b',
    'Sber API': r'(?i)sber[_-]?api[_-]?key\s*[=:]\s*["\']?[a-zA-Z0-9_-]{20,}["\']?',
    'Tinkoff': r'\btinkoff_[a-zA-Z0-9_-]{28,}\b',
    'Merchant': r'\bmerchant_[a-zA-Z0-9_-]{32,}\b',
    'Ozon': r'(?i)api-key\s*[=:]\s*["\']?[a-zA-Z0-9_-]{28,}["\']?',
    'Telegram': r'\b\d{8,10}:[A-Za-z0-9_-]{33,}\b',
}

for line in test_lines:
    print(f'Line: {line}')
    for name, pattern in patterns.items():
        match = re.search(pattern, line)
        if match:
            print(f'  ✓ {name}: {match.group()}')
    print()
