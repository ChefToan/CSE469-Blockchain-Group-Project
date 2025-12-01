# Blockchain Chain of Custody System
**CSE469 Group Project - Fall 2025**

---

## GROUP INFORMATION

**Group Number:** 18

### Team Members

| Name | ASU ID | Email |
|------|--------|-------|
| Toan Pham | 1226931604 | kpham34@asu.edu |
| John Bostater | 1225430986 | jbostate@asu.edu |
| Allan Binu | 1226049710 | abinu4@asu.edu |
| Sriram Nesan | 1224881268 | snesan@asu.edu |
| Tyler Woodburn | 1221183496 | twoodbu4@asu.edu |

---

## PROGRAM DESCRIPTION

This program implements a **blockchain-based chain of custody system** for digital forensics evidence management. It provides a secure and immutable record of all actions taken on evidence items throughout their lifecycle.

The system uses blockchain technology to ensure the integrity of evidence records, with each action (add, checkout, checkin, remove) creating a new block in the chain. All blocks are cryptographically linked using **SHA-256 hashing**, and case IDs and item IDs are encrypted using **AES ECB mode** for security.

---

## IMPLEMENTATION DETAILS

**Programming Language:** Python 3
**Dependencies:** pycryptodome (for AES encryption)

### Key Features:
- Binary blockchain storage format
- AES ECB encryption for case IDs and item IDs
- SHA-256 hashing for block integrity
- Support for multiple evidence items per case
- Password-based access control with role validation
- Complete chain of custody verification

---

## HOW IT WORKS

### 1. Blockchain Structure
- Each block contains: previous hash, timestamp, encrypted case ID, encrypted item ID, state, creator, owner, and data
- The first block is always the **INITIAL block** (genesis block)
- All subsequent blocks are linked via cryptographic hashes

### 2. Evidence States
| State | Description |
|-------|-------------|
| `INITIAL` | Genesis block state |
| `CHECKEDIN` | Evidence is stored and available |
| `CHECKEDOUT` | Evidence is being examined |
| `DISPOSED` | Evidence has been disposed |
| `DESTROYED` | Evidence has been destroyed |
| `RELEASED` | Evidence has been released to owner |

### 3. Security
- **Case IDs** (UUIDs) and **Item IDs** (integers) are encrypted using AES-128 ECB mode
- Block integrity is verified using **SHA-256 hashing**
- Password authentication required for all operations
- Creator password required for `add` and `remove` operations

### 4. File Storage
- The blockchain is stored in **binary format**
- File path is determined by `BCHOC_FILE_PATH` environment variable
- Default path is `blockchain.bin` if not specified

---

## USAGE

### Build the program:
```bash
make
```

### Clean build artifacts:
```bash
make clean
```

### Initialize blockchain:
```bash
./bchoc init
```

### Add evidence to a case:
```bash
./bchoc add -c <case_uuid> -i <item_id> [-i <item_id> ...] -g <creator> -p <password>
```

### Check out evidence:
```bash
./bchoc checkout -i <item_id> -p <password>
```

### Check in evidence:
```bash
./bchoc checkin -i <item_id> -p <password>
```

### Show all cases:
```bash
./bchoc show cases [-p <password>]
```

### Show items in a case:
```bash
./bchoc show items -c <case_uuid> [-p <password>]
```

### Show history:
```bash
./bchoc show history [-c <case_uuid>] [-i <item_id>] [-n <num>] [-r] [-p <password>]
```

### Remove evidence:
```bash
./bchoc remove -i <item_id> -y <reason> [-o <owner>] -p <password>
```
**Reasons:** `DISPOSED`, `DESTROYED`, `RELEASED`

### Verify blockchain integrity:
```bash
./bchoc verify
```

### Show case summary:
```bash
./bchoc summary -c <case_uuid> -p <password>
```

---

## ENVIRONMENT VARIABLES

Required environment variables for testing:

| Variable | Description |
|----------|-------------|
| `BCHOC_FILE_PATH` | Path to blockchain file (optional, defaults to blockchain.bin) |
| `BCHOC_PASSWORD_POLICE` | Password for police role |
| `BCHOC_PASSWORD_LAWYER` | Password for lawyer role |
| `BCHOC_PASSWORD_ANALYST` | Password for analyst role |
| `BCHOC_PASSWORD_EXECUTIVE` | Password for executive role |
| `BCHOC_PASSWORD_CREATOR` | Password for creator role (required for add/remove) |

---

## EXAMPLES

### Example 1: Initialize and add evidence
```bash
export BCHOC_FILE_PATH="evidence.bin"
export BCHOC_PASSWORD_CREATOR="C67C"
./bchoc init
./bchoc add -c c84e339e-5c0f-4f4d-84c5-bb79a3c1d2a2 -i 1004820154 -g Investigator1 -p C67C
```

### Example 2: Check out and check in evidence
```bash
export BCHOC_PASSWORD_ANALYST="A65A"
./bchoc checkout -i 1004820154 -p A65A
./bchoc checkin -i 1004820154 -p A65A
```

### Example 3: View history and verify
```bash
./bchoc show history -i 1004820154 -p A65A
./bchoc verify
```

### Example 4: Generate case summary
```bash
./bchoc summary -c c84e339e-5c0f-4f4d-84c5-bb79a3c1d2a2 -p A65A
```

---

## ERROR HANDLING

The program exits with code **0** on success and code **1** on errors, including:
- Invalid password
- Invalid UUID format
- Item not found
- Invalid state transitions
- Blockchain verification failures

---

## DESIGN DECISIONS

1. **Binary Storage:** Uses struct packing for efficient binary storage as required
2. **Encryption:** AES ECB mode for case/item ID encryption (as specified)
3. **Password System:** Environment variables for flexible password configuration
4. **Block Linking:** SHA-256 hashing ensures cryptographic integrity
5. **State Validation:** Enforces valid state transitions (e.g., cannot remove checked-out items)

---

## TESTING

The implementation has been tested against all common requirements:
- Initialization with and without existing blockchain
- Adding single and multiple items
- Checkout/checkin operations
- Remove operations with all reasons
- History display with various filters
- Blockchain verification
- Case summary generation
- Password validation
- Error handling

---

## SUBMISSION CONTENTS

- `bchoc.py` - Main program source code
- `Makefile` - Build configuration
- `packages` - List of required system packages
- `requirements.txt` - Python dependencies
- `README.md` - This file