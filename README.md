# 🛡️ HashSentry — Password Hash Security Auditing Tool

> **A modular, multi-strategy password hash auditing and security assessment engine.**  
> Evaluates the true exposure and recovery cost of password hashes across fast and slow cryptographic algorithms using **in-memory streaming candidate generation ($O(1)$ RAM, zero disk storage)**.

---

## 🚀 Key Features

* **Pure In-Memory Streaming Candidate Generation**:
  * **Pattern & Combinatorial Stream**: Dynamic Cartesian product streaming (`itertools.product`). Supports optional base prefixes (e.g. `bante`) combined with full 94-character ASCII (`A-Z`, `a-z`, `0-9`, symbols), alphanumeric, or custom character sets across configurable length ranges without creating disk files.
  * **Mask Attack**: Hashcat-compatible token syntax (`?l`, `?u`, `?d`, `?s`, `?a`, `?h`, literals).
  * **Smart Human Mutation Engine**: In-memory rule mutations on root patterns (leetspeak, capitalizations, digit/year suffixes, reversals).
  * **Hybrid Attack**: Base words + brute-forced variable token suffixes.
  * **Exhaustive Brute-Force**: Configurable character sets and length bounds.
* **Broad Algorithm Support**:
  * **Fast Hashes**: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, MD4, NTLM (UTF-16LE).
  * **Slow / Salted Hashes**: Native verification for `bcrypt`, `Argon2` (`argon2id`), and `scrypt`.
* **Zero Wordlist File Footprint**: No bloated `.txt` wordlist files required. All candidates are generated on-the-fly and immediately discarded.
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
│   ├── strategies/           # Pattern Streaming, Brute-force, Rules, Mask, Hybrid
│   ├── execution/            # Multiprocessing Manager & Checkpoint Store
│   ├── reporting/            # Strength Scorer, Policy Auditor, Exporters
│   └── cli.py                # Rich Interactive Interface & Argument Parser
├── tests/                    # Comprehensive Unit Test Suite (31 Tests)
├── requirements.txt          # Project Dependencies
├── run.py                    # Root Launcher
└── .gitignore                # Git Configuration
```

---

## 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/supan1676/HashSentry.git
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
# Pattern Streaming on SHA-1 (Prefix 'bante' + 1 suffix character across all 94 ASCII symbols)
python run.py -t fd1fa8af619ee320f1fab31824616394cc62716a -a sha1 -m pattern --prefix "bante" --max-suffix 1

# Mask Attack on MD5
python run.py -t 72c430cbf240a47a9f7d9a7d6a6fc36a -a md5 -m mask --mask "bante?l"

# Smart Human Mutations on MD5
python run.py -t 5f4dcc3b5aa765d61d8327deb882cf99 -a md5 -m rules --base-words "password" --export-csv reports/audit.csv

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
