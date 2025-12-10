# ECDSA-Cracker

A tool for recovering ECDSA private keys and nonces from cryptographic signatures exploiting various vulnerability patterns.

## Overview

ECDSA-Cracker is a Python library designed to identify and exploit common ECDSA signature vulnerabilities to recover private keys and ephemeral nonces. It implements multiple cryptographic attack strategies to crack ECDSA keys from signature datasets.

### Key Features

- **Multiple Attack Vectors**: Supports various ECDSA key recovery techniques:
  - Recovery from repeated nonces
  - Linear equation system solving
  - Nonce derivation from known private keys
  - Private key derivation from known nonces

- **Efficient Data Processing**: Uses pandas DataFrames with pandera validation for robust data handling
- **Graph-Based Propagation**: Network analysis to propagate cracked keys and nonces across signature relationships
- **ECDSA Curve Support**:Designed to work with SECP256k1, but could be adapted to work on some other curves.
- **Comprehensive Logging**: Detailed progress tracking and statistics reporting
- **Persistent Storage**: Save and restore analysis states using parquet files

## Installation

### Prerequisites

- Python 3.9 or higher

### Setup

Clone the repository and install the package with its dependencies:

```bash
git clone https://github.com/jack695/ECDSA-Cracker.git
cd ECDSA-Cracker
pip install -e .
```
## Usage

### Basic Example

```python
from ecdsa_cracker.ECDSABreaker import ECDSABreaker
from ecdsa_cracker.SignatureDB import SignatureFolder
import ecdsa

# Define signature sources
signature_folders = [
    SignatureFolder(path="/path/to/signatures", check_signatures=True)
]

# Create and run the cracker
breaker = ECDSABreaker.from_scratch(
    signature_folders=signature_folders,
    curve=ecdsa.SECP256k1,
    out_folder="/path/to/output"
)

# Execute all attack rounds
breaker.crack()
```

### Loading Previous Results

```python
# Restore from a previous analysis
breaker = ECDSABreaker.from_dump(
    dump_dir_path="/path/to/previous_output",
    curve=ecdsa.SECP256k1,
    out_folder="/path/to/new_output"
)

breaker.crack()
```

### Working with Signatures

The library expects signature data with some fields. Please refer to [data](data) for an example.