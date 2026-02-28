# Nuclear Project

## Overview
Nuclear is a secret scanning tool designed to identify API keys, tokens, and sensitive data within files, directories, or archives. It provides a command-line interface for easy usage and integrates with various output formats for reporting findings.

## Features
- Scans files, directories, and .zip archives for sensitive information.
- Supports scanning of Git commit history.
- Configurable severity levels for findings.
- Generates reports in multiple formats (text, JSON, SARIF).

## Installation
To install Nuclear, clone the repository and install it in editable mode:

```bash
git clone <repository-url>
cd nuclear
pip install -e .
```

## Usage
You can run the Nuclear scanner using the command:

```bash
nuclear [OPTIONS] [TARGET]
```

### Options
- `TARGET`: The file, directory, or .zip archive to scan.
- `--url`: A remote Git/HTTP/ZIP URL for downloading and scanning.
- `--format`: Output format for the report (choices: text, json, sarif).
- `--min-severity`: Minimum severity level to report (choices: LOW, MEDIUM, HIGH, CRITICAL).
- `--fail-on`: Set the severity level that will cause the command to fail.
- `--scan-history`: Scan the history of Git commits.
- `--history-commits`: Maximum number of commits to scan.
- `--output`: Path to the report file (default is stdout).

## Example
To scan a directory for sensitive data and generate a report in JSON format:

```bash
nuclear /path/to/directory --format json --output report.json
```

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.