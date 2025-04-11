# CBOM Detector Usage Guide

This guide provides detailed instructions on how to install, run, and interpret the results of the CBOM Detector tool.

## Table of Contents
1. [Installation](#installation)
2. [Running the Tool](#running-the-tool)
3. [Understanding the Reports](#understanding-the-reports)
4. [Interpreting the Quantum Readiness Score](#interpreting-the-quantum-readiness-score)
5. [Taking Action](#taking-action)
6. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites
- Python 3.6 or higher
- Pip package manager
- Administrative privileges (for system scanning)

### Installation Methods

#### Method 1: Using the Install Script

1. Download the CBOM Detector package or clone it from the repository
2. Navigate to the package directory
3. Run the install script:

```bash
python install.py
```

This will install all required dependencies and the CBOM Detector tool.

#### Method 2: Using pip

```bash
pip install cbom-detector
```

#### Method 3: Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cbom-detector.git
```

2. Navigate to the directory:
```bash
cd cbom-detector
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install the package:
```bash
pip install -e .
```

## Running the Tool

After installation, you can run the CBOM Detector tool using the command:

```bash
cbom-detector
```

The tool will automatically:

1. Scan your system for cryptographic components
2. Analyze installed browsers
3. Check for hardware security tokens
4. Generate a risk assessment
5. Create JSON and HTML reports

You'll see real-time progress in your terminal as the scan proceeds.

## Understanding the Reports

### Terminal Output

The scan results will be displayed in your terminal with color-coded risk levels:
- **RED**: CRITICAL risk
- **YELLOW**: HIGH risk
- **BLUE**: MODERATE risk
- **GREEN**: LOW risk
- **MAGENTA**: Quantum Vulnerable components

### JSON Report

A detailed JSON report (`cbom_report_YYYYMMDD_HHMMSS.json`) is generated with all scan data. This is useful for:
- Programmatic analysis
- Integration with other tools
- Record-keeping and tracking over time

### HTML Report

An HTML report (`cbom_report_YYYYMMDD_HHMMSS.html`) provides a user-friendly visualization of results, including:
- System information
- Risk summary
- Browser cryptography
- System cryptography
- Hardware tokens
- Recommendations

## Interpreting the Quantum Readiness Score

The Quantum Readiness Score (0-100) indicates how well your system can withstand quantum computing attacks:

| Score Range | Interpretation | Action Needed |
|-------------|----------------|---------------|
| 90-100 |