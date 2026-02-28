# filepath: nuclear/nuclear/config.py
def load_config():
    return {
        "format": "text",
        "severity": "MEDIUM",
        "fail_on": "HIGH",
        "history": False,
        "commits": 5,
        "output_file": None,
    }