# 🛡️ HashSentry — Password Hash Security Auditing Tool

> **A modular, multi-strategy password hash auditing and security assessment engine.**  
> Evaluates the true exposure and recovery cost of password hashes across fast and slow cryptographic algorithms.

---

## 🚀 Key Features

* **Multi-Strategy Cracking Engine**:
  * **Dictionary Attack**: Memory-efficient streaming against custom wordlists.
  * **Rule-Based Mutation Engine**: Realistic human mutations (leetspeak, capitalizations, digit/year suffixes, reversals).
  * **Mask Attack**: Hashcat-compatible token syntax (`?l`, `?u`, `?d`, `?s`, `?a`, `?h`, literals).
  * **Hybrid Attack**: Dictionary base words + brute-forced variable suffixes.
  * **Exhaustive Brute-Force**: Configurable character sets and length bounds.
* **Broad Algorithm Support**:
  * **Fast Hashes**: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, MD4, NTLM (UTF-16LE).
  * **Slow / Salted Hashes**: Native verification for `bcrypt`, `Argon2` (`argon2id`), and `scrypt`.
* **Hash Type Auto-Detection**: Instant identification of hash formats with ambiguous digest resolution.
* **Multi-Core Parallelism**: Scales candidate testing linearly across CPU cores using Python multiprocessing.
* **Session Resilience & Checkpointing**: Graceful interruption (`Ctrl+C`) saves atomic state to resume without repeating work.
* **Security Scoring & Policy Auditing**: Shannon entropy calculations, pattern detection (`name+year`, `keyboard walks`), and exportable reports (**CSV**, **JSON**, **Text**).
* **Terminal UI**: Rich live progress display showing attempts, speed (`H/s`), elapsed time, and ETA.

---

## 📦 Project Architecture

```
HashSentry/
├── hashsentry/               # Core Python Package
│   ├── core/                 # Detector, Hasher, Handlers, Prioritizer
│   ├── strategies/           # Brute-force, Dictionary, Rules, Mask/Hybrid
│   ├── execution/            # Multiprocessing Manager & Checkpoint Store
│   ├── reporting/            # Strength Scorer, Policy Auditor, Exporters
│   └── cli.py                # Rich Interactive Interface & Argument Parser
├── tests/                    # Comprehensive Unit Test Suite (30 Tests)
├── requirements.txt          # Project Dependencies
├── run.py                    # Root Launcher
└── .gitignore                # Git Configuration
```

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/HashSentry.git
cd HashSentry

# Install dependencies
pip install -r requirements.txt
```

---

## ⚡ Quick Start

### 1. Interactive Menu Mode
Launch the interactive CLI:
```bash
python run.py
```

### 2. Command-Line / Headless Mode
Audit a specific hash via flags:
```bash
# Dictionary + Rules Attack with CSV report export
python run.py -t 5f4dcc3b5aa765d61d8327deb882cf99 -a md5 -m rules --export-csv reports/audit.csv

# Mask Attack on SHA-1 (e.g. pattern 'bante?a')
python run.py -t ece65a739691022cf74253c16c8c3a35a9670e16 -a sha1 -m mask --mask "xyz?a"

# Run Feature Demonstration
python run.py --demo
```

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

---

## ⚖️ Legal & Ethical Notice

This tool is strictly designed for authorized security auditing, academic research, and credential testing on systems you own or have explicit, documented permission to test.
