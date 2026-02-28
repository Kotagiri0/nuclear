# Nuclear Project

## Overview
Nuclear is a secret scanning tool designed to identify API keys, tokens, and sensitive data within files, directories, or archives. It provides a command-line interface for easy usage and integrates with Git to scan commit histories.

## Features
- Scans files, directories, and ZIP archives for sensitive information.
- Supports scanning of Git commit histories.
- Generates reports in various formats (text, JSON, SARIF).
- Configurable severity levels for findings.

## Installation
To install Nuclear, clone the repository and install it in editable mode:

```bash
git clone <repository-url>
cd nuclear
pip install -e .
```

## Usage
You can run the scanner using the command:

```bash
nuclear [options]
```

### Options
- `target`: Specify a file, directory, or ZIP archive to scan.
- `--url`: Provide a remote Git/HTTP/ZIP URL for scanning.
- `--format`: Choose the output format (text, json, sarif).
- `--min-severity`: Set the minimum severity level for findings (LOW, MEDIUM, HIGH, CRITICAL).
- `--fail-on`: Define the severity level that should cause the scan to fail.
- `--scan-history`: Enable scanning of Git commit history.
- `--history-commits`: Set the maximum number of commits to scan.
- `--output`: Specify the path for the report file (default is stdout).

## Example
To scan a directory for sensitive data and generate a report in JSON format:

```bash
nuclear /path/to/directory --format json --output report.json
```

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.