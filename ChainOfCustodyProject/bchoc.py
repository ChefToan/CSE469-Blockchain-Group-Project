#!/usr/bin/env python3
"""
Blockchain Chain of Custody System
CSE469 Group Project - Fall 2025
"""

import sys
import os
import struct
import hashlib
import argparse
import uuid
from datetime import datetime, timezone

# Constants
AES_KEY = b"R0chLi4uLi4uLi4="
BLOCK_HEADER_SIZE = 144
INITIAL_BLOCK_SIZE = 158

# Password environment variables
PASSWORDS = {
    "POLICE": os.environ.get("BCHOC_PASSWORD_POLICE", "P80P"),
    "LAWYER": os.environ.get("BCHOC_PASSWORD_LAWYER", "L76L"),
    "ANALYST": os.environ.get("BCHOC_PASSWORD_ANALYST", "A65A"),
    "EXECUTIVE": os.environ.get("BCHOC_PASSWORD_EXECUTIVE", "E69E"),
    "CREATOR": os.environ.get("BCHOC_PASSWORD_CREATOR", "C67C"),
}

# Valid states
STATES = ["INITIAL", "CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"]
REMOVAL_REASONS = ["DISPOSED", "DESTROYED", "RELEASED"]


# ============================================================================
# Pure Python AES Implementation (ECB mode only, no external dependencies)
# ============================================================================

# AES S-box
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-box
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Round constants
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def xtime(a):
    """Multiply by x in GF(2^8)."""
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def multiply(a, b):
    """Multiply two numbers in GF(2^8)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def sub_bytes(state):
    """Apply S-box substitution to state."""
    return [SBOX[b] for b in state]


def inv_sub_bytes(state):
    """Apply inverse S-box substitution to state."""
    return [INV_SBOX[b] for b in state]


def shift_rows(state):
    """Shift rows of state."""
    return [
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ]


def inv_shift_rows(state):
    """Inverse shift rows of state."""
    return [
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3]
    ]


def mix_columns(state):
    """Mix columns of state."""
    result = []
    for i in range(4):
        col = state[i*4:(i+1)*4]
        result.append(multiply(2, col[0]) ^ multiply(3, col[1]) ^ col[2] ^ col[3])
        result.append(col[0] ^ multiply(2, col[1]) ^ multiply(3, col[2]) ^ col[3])
        result.append(col[0] ^ col[1] ^ multiply(2, col[2]) ^ multiply(3, col[3]))
        result.append(multiply(3, col[0]) ^ col[1] ^ col[2] ^ multiply(2, col[3]))
    return result


def inv_mix_columns(state):
    """Inverse mix columns of state."""
    result = []
    for i in range(4):
        col = state[i*4:(i+1)*4]
        result.append(multiply(14, col[0]) ^ multiply(11, col[1]) ^ multiply(13, col[2]) ^ multiply(9, col[3]))
        result.append(multiply(9, col[0]) ^ multiply(14, col[1]) ^ multiply(11, col[2]) ^ multiply(13, col[3]))
        result.append(multiply(13, col[0]) ^ multiply(9, col[1]) ^ multiply(14, col[2]) ^ multiply(11, col[3]))
        result.append(multiply(11, col[0]) ^ multiply(13, col[1]) ^ multiply(9, col[2]) ^ multiply(14, col[3]))
    return result


def add_round_key(state, round_key):
    """XOR state with round key."""
    return [s ^ k for s, k in zip(state, round_key)]


def key_expansion(key):
    """Expand key to round keys."""
    key_words = []
    for i in range(4):
        key_words.append(list(key[i*4:(i+1)*4]))
    
    for i in range(4, 44):
        temp = key_words[i-1][:]
        if i % 4 == 0:
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [SBOX[b] for b in temp]
            # XOR with Rcon
            temp[0] ^= RCON[i//4 - 1]
        key_words.append([a ^ b for a, b in zip(key_words[i-4], temp)])
    
    round_keys = []
    for i in range(11):
        round_key = []
        for j in range(4):
            round_key.extend(key_words[i*4 + j])
        round_keys.append(round_key)
    
    return round_keys


def aes_encrypt_block(plaintext, key):
    """Encrypt a single 16-byte block using AES-128."""
    state = list(plaintext)
    round_keys = key_expansion(key)
    
    # Initial round
    state = add_round_key(state, round_keys[0])
    
    # Main rounds
    for i in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[i])
    
    # Final round
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    return bytes(state)


def aes_decrypt_block(ciphertext, key):
    """Decrypt a single 16-byte block using AES-128."""
    state = list(ciphertext)
    round_keys = key_expansion(key)
    
    # Initial round
    state = add_round_key(state, round_keys[10])
    
    # Main rounds
    for i in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[i])
        state = inv_mix_columns(state)
    
    # Final round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    
    return bytes(state)


# ============================================================================
# End of AES Implementation
# ============================================================================


def get_blockchain_path():
    """Get the blockchain file path from environment or use default."""
    return os.environ.get("BCHOC_FILE_PATH", "blockchain.bin")


def encrypt_case_id(case_uuid):
    """Encrypt a UUID case_id using AES ECB and return hex-encoded 32 bytes."""
    # Convert UUID to bytes (16 bytes)
    uuid_bytes = uuid.UUID(case_uuid).bytes
    # Encrypt the 16-byte UUID
    encrypted = aes_encrypt_block(uuid_bytes, AES_KEY)
    # Convert to hex string (32 characters) and encode as bytes
    return encrypted.hex().encode('ascii')


def decrypt_case_id(encrypted_hex_bytes):
    """Decrypt case_id from hex-encoded bytes to UUID string."""
    # Convert hex bytes to binary
    encrypted = bytes.fromhex(encrypted_hex_bytes.decode('ascii'))
    # Decrypt
    decrypted = aes_decrypt_block(encrypted, AES_KEY)
    # Convert to UUID
    return str(uuid.UUID(bytes=decrypted))


def encrypt_item_id(item_id):
    """Encrypt a 4-byte integer item_id using AES ECB and return hex-encoded 32 bytes."""
    # Convert integer to 16 bytes (little-endian, padded with zeros)
    item_bytes = struct.pack('<I', int(item_id)) + b'\x00' * 12
    # Encrypt
    encrypted = aes_encrypt_block(item_bytes, AES_KEY)
    # Convert to hex string (32 characters) and encode as bytes
    return encrypted.hex().encode('ascii')


def decrypt_item_id(encrypted_hex_bytes):
    """Decrypt item_id from hex-encoded bytes to integer."""
    # Convert hex bytes to binary
    encrypted = bytes.fromhex(encrypted_hex_bytes.decode('ascii'))
    # Decrypt
    decrypted = aes_decrypt_block(encrypted, AES_KEY)
    # Take first 4 bytes and convert to integer (little-endian)
    return struct.unpack('<I', decrypted[:4])[0]


def format_state(state_str):
    """Format state string to 12 bytes."""
    state_bytes = state_str.encode('utf-8')
    if len(state_bytes) > 12:
        state_bytes = state_bytes[:12]
    else:
        state_bytes = state_bytes + b'\x00' * (12 - len(state_bytes))
    return state_bytes


def format_text_field(text, max_len):
    """Format text field to fixed length."""
    text_bytes = text.encode('utf-8') if isinstance(text, str) else text
    if len(text_bytes) > max_len:
        text_bytes = text_bytes[:max_len]
    else:
        text_bytes = text_bytes + b'\x00' * (max_len - len(text_bytes))
    return text_bytes


class Block:
    """Represents a single block in the blockchain."""

    def __init__(self, prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data):
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.state = state
        self.creator = creator
        self.owner = owner
        self.data = data
        self.data_length = len(data)

    def to_bytes(self):
        """Convert block to binary format."""
        # Pack the fixed-size header
        header = struct.pack(
            '32s d 32s 32s 12s 12s 12s I',
            self.prev_hash,
            self.timestamp,
            self.case_id,
            self.evidence_id,
            self.state,
            self.creator,
            self.owner,
            self.data_length
        )
        return header + self.data

    @staticmethod
    def from_bytes(data):
        """Create a Block from binary data."""
        if len(data) < BLOCK_HEADER_SIZE:
            return None

        # Unpack the header
        header = struct.unpack('32s d 32s 32s 12s 12s 12s I', data[:BLOCK_HEADER_SIZE])

        prev_hash = header[0]
        timestamp = header[1]
        case_id = header[2]
        evidence_id = header[3]
        state = header[4]
        creator = header[5]
        owner = header[6]
        data_length = header[7]

        # Extract data
        block_data = data[BLOCK_HEADER_SIZE:BLOCK_HEADER_SIZE + data_length]

        return Block(prev_hash, timestamp, case_id, evidence_id, state, creator, owner, block_data)

    def get_hash(self):
        """Calculate and return the hash of this block."""
        block_bytes = self.to_bytes()
        # Hash everything except the prev_hash field (first 32 bytes)
        return hashlib.sha256(block_bytes[32:]).digest()


class Blockchain:
    """Manages the blockchain."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.blocks = []
        self.load_blockchain()

    def load_blockchain(self):
        """Load blockchain from file."""
        if not os.path.exists(self.filepath):
            return

        with open(self.filepath, 'rb') as f:
            data = f.read()

        offset = 0
        while offset < len(data):
            if len(data) - offset < BLOCK_HEADER_SIZE:
                break

            # Read header to get data length
            header_data = data[offset:offset + BLOCK_HEADER_SIZE]
            data_length = struct.unpack('I', header_data[140:144])[0]

            # Read full block
            block_size = BLOCK_HEADER_SIZE + data_length
            block_data = data[offset:offset + block_size]

            block = Block.from_bytes(block_data)
            if block:
                self.blocks.append(block)

            offset += block_size

    def save_blockchain(self):
        """Save blockchain to file."""
        with open(self.filepath, 'wb') as f:
            for block in self.blocks:
                f.write(block.to_bytes())

    def add_block(self, block):
        """Add a new block to the blockchain."""
        self.blocks.append(block)
        self.save_blockchain()

    def get_initial_block(self):
        """Create the genesis/initial block."""
        return Block(
            prev_hash=b'\x00' * 32,
            timestamp=0.0,
            case_id=b'0' * 32,
            evidence_id=b'0' * 32,
            state=format_state("INITIAL"),
            creator=b'\x00' * 12,
            owner=b'\x00' * 12,
            data=b'Initial block\x00'
        )

    def has_initial_block(self):
        """Check if blockchain has initial block."""
        if len(self.blocks) == 0:
            return False

        first_block = self.blocks[0]
        return (first_block.prev_hash == b'\x00' * 32 and
                first_block.timestamp == 0.0 and
                first_block.case_id == b'0' * 32)

    def get_last_block_hash(self):
        """Get hash of the last block."""
        if len(self.blocks) == 0:
            return b'\x00' * 32
        return self.blocks[-1].get_hash()

    def item_exists(self, item_id):
        """Check if an item exists in the blockchain."""
        encrypted_item = encrypt_item_id(item_id)
        for block in self.blocks:
            if block.evidence_id == encrypted_item:
                return True
        return False

    def get_item_state(self, item_id):
        """Get the current state of an item."""
        encrypted_item = encrypt_item_id(item_id)
        # Find the most recent block for this item
        for block in reversed(self.blocks):
            if block.evidence_id == encrypted_item:
                state = block.state.rstrip(b'\x00').decode('utf-8')
                return state
        return None

    def get_item_case(self, item_id):
        """Get the case_id associated with an item."""
        encrypted_item = encrypt_item_id(item_id)
        for block in self.blocks:
            if block.evidence_id == encrypted_item:
                return block.case_id
        return None


def validate_password(password, required_role=None):
    """Validate password against environment variables."""
    valid_passwords = list(PASSWORDS.values())

    if password not in valid_passwords:
        return False

    if required_role == "CREATOR":
        return password == PASSWORDS["CREATOR"]

    return True


def validate_uuid(uuid_str):
    """Validate UUID format."""
    try:
        uuid.UUID(uuid_str)
        return True
    except:
        return False


def cmd_init(args):
    """Initialize the blockchain."""
    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    if blockchain.has_initial_block():
        print("Blockchain file found with INITIAL block.")
        return 0

    # Create initial block
    initial_block = blockchain.get_initial_block()
    blockchain.add_block(initial_block)
    print("Blockchain file not found. Created INITIAL block.")
    return 0


def cmd_add(args):
    """Add new evidence item(s) to the blockchain."""
    # Validate password
    if not validate_password(args.password, "CREATOR"):
        print("Invalid password")
        return 1

    # Validate case_id
    if not validate_uuid(args.case_id):
        print("Invalid case_id format")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    # Ensure blockchain is initialized
    if not blockchain.has_initial_block():
        initial_block = blockchain.get_initial_block()
        blockchain.add_block(initial_block)

    # Process each item_id
    for item_id in args.item_id:
        # Check if item already exists
        if blockchain.item_exists(item_id):
            print(f"Item {item_id} already exists in blockchain")
            return 1

        # Create new block
        timestamp = datetime.now(timezone.utc).timestamp()
        encrypted_case = encrypt_case_id(args.case_id)
        encrypted_item = encrypt_item_id(item_id)

        block = Block(
            prev_hash=blockchain.get_last_block_hash(),
            timestamp=timestamp,
            case_id=encrypted_case,
            evidence_id=encrypted_item,
            state=format_state("CHECKEDIN"),
            creator=format_text_field(args.creator, 12),
            owner=format_text_field("", 12),
            data=b''
        )

        blockchain.add_block(block)

        # Print confirmation
        timestamp_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        print(f"Added item: {item_id}")
        print(f"Status: CHECKEDIN")
        print(f"Time of action: {timestamp_str}")

    return 0


def cmd_checkout(args):
    """Check out an evidence item."""
    # Validate password
    if not validate_password(args.password):
        print("Invalid password")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    # Check if item exists
    if not blockchain.item_exists(args.item_id):
        print(f"Item {args.item_id} not found in blockchain")
        return 1

    # Check current state
    current_state = blockchain.get_item_state(args.item_id)
    if current_state not in ["CHECKEDIN"]:
        print(f"Cannot checkout item in state {current_state}")
        return 1

    # Create checkout block
    timestamp = datetime.now(timezone.utc).timestamp()
    case_id = blockchain.get_item_case(args.item_id)
    encrypted_item = encrypt_item_id(args.item_id)

    block = Block(
        prev_hash=blockchain.get_last_block_hash(),
        timestamp=timestamp,
        case_id=case_id,
        evidence_id=encrypted_item,
        state=format_state("CHECKEDOUT"),
        creator=format_text_field("", 12),
        owner=format_text_field("", 12),
        data=b''
    )

    blockchain.add_block(block)

    # Print confirmation
    timestamp_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    decrypted_case = decrypt_case_id(case_id)
    print(f"Case: {decrypted_case}")
    print(f"Checked out item: {args.item_id}")
    print(f"Status: CHECKEDOUT")
    print(f"Time of action: {timestamp_str}")

    return 0


def cmd_checkin(args):
    """Check in an evidence item."""
    # Validate password
    if not validate_password(args.password):
        print("Invalid password")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    # Check if item exists
    if not blockchain.item_exists(args.item_id):
        print(f"Item {args.item_id} not found in blockchain")
        return 1

    # Check current state
    current_state = blockchain.get_item_state(args.item_id)
    if current_state not in ["CHECKEDOUT", "CHECKEDIN"]:
        print(f"Cannot checkin item in state {current_state}")
        return 1

    # Create checkin block
    timestamp = datetime.now(timezone.utc).timestamp()
    case_id = blockchain.get_item_case(args.item_id)
    encrypted_item = encrypt_item_id(args.item_id)

    block = Block(
        prev_hash=blockchain.get_last_block_hash(),
        timestamp=timestamp,
        case_id=case_id,
        evidence_id=encrypted_item,
        state=format_state("CHECKEDIN"),
        creator=format_text_field("", 12),
        owner=format_text_field("", 12),
        data=b''
    )

    blockchain.add_block(block)

    # Print confirmation
    timestamp_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    decrypted_case = decrypt_case_id(case_id)
    print(f"Case: {decrypted_case}")
    print(f"Checked in item: {args.item_id}")
    print(f"Status: CHECKEDIN")
    print(f"Time of action: {timestamp_str}")

    return 0


def cmd_show_cases(args):
    """Show all cases in the blockchain - always decrypted, no password needed."""
    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    # Collect unique cases
    cases = set()
    for block in blockchain.blocks:
        if block.case_id != b'0' * 32:
            try:
                case_uuid = decrypt_case_id(block.case_id)
                cases.add(case_uuid)
            except:
                pass

    # Print cases
    for case in sorted(cases):
        print(case)

    return 0


def cmd_show_items(args):
    """Show all items for a given case - always decrypted, no password needed."""
    # Validate case_id
    if not validate_uuid(args.case_id):
        print("Invalid case_id format")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    encrypted_case = encrypt_case_id(args.case_id)

    # Collect unique items for this case
    items = set()
    for block in blockchain.blocks:
        if block.case_id == encrypted_case:
            try:
                item_id = decrypt_item_id(block.evidence_id)
                items.add(item_id)
            except:
                pass

    # Print items
    for item in sorted(items):
        print(item)

    return 0


def cmd_show_history(args):
    """Show blockchain history with optional filters. Password required."""
    # Password is required for show history
    if not args.password:
        print("Password required")
        return 1
    
    if not validate_password(args.password):
        print("Invalid password")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    # Filter blocks
    filtered_blocks = []
    for block in blockchain.blocks:
        # Skip initial block
        if block.case_id == b'0' * 32:
            continue

        # Filter by case_id if specified
        if args.case_id:
            if not validate_uuid(args.case_id):
                print("Invalid case_id format")
                return 1
            encrypted_case = encrypt_case_id(args.case_id)
            if block.case_id != encrypted_case:
                continue

        # Filter by item_id if specified
        if args.item_id:
            encrypted_item = encrypt_item_id(args.item_id)
            if block.evidence_id != encrypted_item:
                continue

        filtered_blocks.append(block)

    # Reverse if requested
    if args.reverse:
        filtered_blocks = list(reversed(filtered_blocks))

    # Limit number of entries
    if args.num_entries:
        filtered_blocks = filtered_blocks[:args.num_entries]

    # Print blocks
    for i, block in enumerate(filtered_blocks):
        if i > 0:
            print()

        try:
            case_id = decrypt_case_id(block.case_id)
            item_id = decrypt_item_id(block.evidence_id)
        except:
            case_id = block.case_id.decode('ascii', errors='ignore')
            item_id = block.evidence_id.decode('ascii', errors='ignore')

        state = block.state.rstrip(b'\x00').decode('utf-8')
        timestamp_str = datetime.fromtimestamp(block.timestamp, tz=timezone.utc).isoformat()

        print(f"Case: {case_id}")
        print(f"Item: {item_id}")
        print(f"Action: {state}")
        print(f"Time: {timestamp_str}")

    return 0


def cmd_remove(args):
    """Remove an evidence item from the chain of custody."""
    # Validate password
    if not validate_password(args.password, "CREATOR"):
        print("Invalid password")
        return 1

    # Validate reason
    if args.reason not in REMOVAL_REASONS:
        print(f"Invalid removal reason. Must be one of: {', '.join(REMOVAL_REASONS)}")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    # Check if item exists
    if not blockchain.item_exists(args.item_id):
        print(f"Item {args.item_id} not found in blockchain")
        return 1

    # Check current state
    current_state = blockchain.get_item_state(args.item_id)
    if current_state != "CHECKEDIN":
        print(f"Cannot remove item in state {current_state}. Item must be CHECKEDIN.")
        return 1

    # Create removal block
    timestamp = datetime.now(timezone.utc).timestamp()
    case_id = blockchain.get_item_case(args.item_id)
    encrypted_item = encrypt_item_id(args.item_id)

    # Prepare data field
    data = b''
    if args.reason == "RELEASED" and args.owner:
        data = args.owner.encode('utf-8') + b'\x00'

    block = Block(
        prev_hash=blockchain.get_last_block_hash(),
        timestamp=timestamp,
        case_id=case_id,
        evidence_id=encrypted_item,
        state=format_state(args.reason),
        creator=format_text_field("", 12),
        owner=format_text_field(args.owner if args.owner else "", 12),
        data=data
    )

    blockchain.add_block(block)

    # Print confirmation
    timestamp_str = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    decrypted_case = decrypt_case_id(case_id)
    print(f"Case: {decrypted_case}")
    print(f"Removed item: {args.item_id}")
    print(f"Status: {args.reason}")
    if args.owner:
        print(f"Owner info: {args.owner}")
    print(f"Time of action: {timestamp_str}")

    return 0


def cmd_verify(args):
    """Verify the integrity of the blockchain."""
    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    if len(blockchain.blocks) == 0:
        print("Blockchain is empty")
        return 1

    num_transactions = len(blockchain.blocks)
    errors = []

    # Track removed items
    removed_items = set()

    # Build parent map
    parent_map = {}
    for i, block in enumerate(blockchain.blocks):
        block_hash = block.get_hash()
        parent_hash = block.prev_hash

        if parent_hash not in parent_map:
            parent_map[parent_hash] = []
        parent_map[parent_hash].append((i, block_hash))

    # Verify each block
    for i, block in enumerate(blockchain.blocks):
        block_hash = block.get_hash()

        # Skip initial block for some checks
        if i == 0:
            continue

        # Check if parent exists
        prev_hash = block.prev_hash
        parent_found = False
        for j in range(i):
            if blockchain.blocks[j].get_hash() == prev_hash:
                parent_found = True
                break

        if not parent_found:
            errors.append({
                'type': 'parent_not_found',
                'block_hash': block_hash.hex(),
                'parent_hash': prev_hash.hex()
            })
            continue

        # Check for duplicate parent
        if prev_hash in parent_map and len(parent_map[prev_hash]) > 1:
            errors.append({
                'type': 'duplicate_parent',
                'block_hash': block_hash.hex(),
                'parent_hash': prev_hash.hex()
            })
            continue

        # Check for operations after removal
        item_id = block.evidence_id
        state = block.state.rstrip(b'\x00').decode('utf-8')

        if item_id in removed_items:
            errors.append({
                'type': 'operation_after_removal',
                'block_hash': block_hash.hex()
            })
            continue

        if state in REMOVAL_REASONS:
            removed_items.add(item_id)

    # Print results
    print(f"Transactions in blockchain: {num_transactions}")

    if len(errors) == 0:
        print("State of blockchain: CLEAN")
        return 0
    else:
        print("State of blockchain: ERROR")
        error = errors[0]  # Report first error
        print(f"Bad block: {error['block_hash']}")

        if error['type'] == 'parent_not_found':
            print(f"Parent block: NOT FOUND")
        elif error['type'] == 'duplicate_parent':
            print(f"Parent block: {error['parent_hash']}")
            print("Two blocks were found with the same parent.")
        elif error['type'] == 'operation_after_removal':
            print("Item checked out or checked in after removal from chain.")

        return 1


def cmd_summary(args):
    """Display summary statistics for a case - counts ALL state transitions."""
    # Validate password
    if not validate_password(args.password):
        print("Invalid password")
        return 1

    # Validate case_id
    if not validate_uuid(args.case_id):
        print("Invalid case_id format")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    encrypted_case = encrypt_case_id(args.case_id)

    # Track unique items and count ALL state transitions
    unique_items = set()
    checked_in = 0
    checked_out = 0
    disposed = 0
    destroyed = 0
    released = 0

    for block in blockchain.blocks:
        if block.case_id == encrypted_case:
            item_id = decrypt_item_id(block.evidence_id)
            unique_items.add(item_id)
            state = block.state.rstrip(b'\x00').decode('utf-8')
            
            # Count every state transition
            if state == "CHECKEDIN":
                checked_in += 1
            elif state == "CHECKEDOUT":
                checked_out += 1
            elif state == "DISPOSED":
                disposed += 1
            elif state == "DESTROYED":
                destroyed += 1
            elif state == "RELEASED":
                released += 1

    total_items = len(unique_items)

    # Print summary
    print(f"Case Summary for Case ID: {args.case_id}")
    print(f"Total Evidence Items: {total_items}")
    print(f"Checked In: {checked_in}")
    print(f"Checked Out: {checked_out}")
    print(f"Disposed: {disposed}")
    print(f"Destroyed: {destroyed}")
    print(f"Released: {released}")

    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Blockchain Chain of Custody')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # init command
    parser_init = subparsers.add_parser('init', help='Initialize blockchain')

    # add command
    parser_add = subparsers.add_parser('add', help='Add evidence item')
    parser_add.add_argument('-c', '--case_id', required=True, help='Case ID (UUID)')
    parser_add.add_argument('-i', '--item_id', required=True, action='append', help='Item ID (can specify multiple)')
    parser_add.add_argument('-g', '--creator', required=True, help='Creator')
    parser_add.add_argument('-p', '--password', required=True, help='Password')

    # checkout command
    parser_checkout = subparsers.add_parser('checkout', help='Checkout evidence item')
    parser_checkout.add_argument('-i', '--item_id', required=True, help='Item ID')
    parser_checkout.add_argument('-p', '--password', required=True, help='Password')

    # checkin command
    parser_checkin = subparsers.add_parser('checkin', help='Checkin evidence item')
    parser_checkin.add_argument('-i', '--item_id', required=True, help='Item ID')
    parser_checkin.add_argument('-p', '--password', required=True, help='Password')

    # show cases command
    parser_show_cases = subparsers.add_parser('show', help='Show information')
    show_subparsers = parser_show_cases.add_subparsers(dest='show_command')

    parser_cases = show_subparsers.add_parser('cases', help='Show all cases')

    # show items command
    parser_items = show_subparsers.add_parser('items', help='Show items in a case')
    parser_items.add_argument('-c', '--case_id', required=True, help='Case ID')

    # show history command
    parser_history = show_subparsers.add_parser('history', help='Show history')
    parser_history.add_argument('-c', '--case_id', help='Filter by case ID')
    parser_history.add_argument('-i', '--item_id', help='Filter by item ID')
    parser_history.add_argument('-n', '--num_entries', type=int, help='Number of entries to show')
    parser_history.add_argument('-r', '--reverse', action='store_true', help='Reverse order')
    parser_history.add_argument('-p', '--password', required=True, help='Password')

    # remove command
    parser_remove = subparsers.add_parser('remove', help='Remove evidence item')
    parser_remove.add_argument('-i', '--item_id', required=True, help='Item ID')
    parser_remove.add_argument('-y', '--reason', required=True, help='Reason (DISPOSED, DESTROYED, RELEASED)')
    parser_remove.add_argument('-o', '--owner', help='Owner info (required for RELEASED)')
    parser_remove.add_argument('-p', '--password', required=True, help='Password')

    # verify command
    parser_verify = subparsers.add_parser('verify', help='Verify blockchain integrity')

    # summary command
    parser_summary = subparsers.add_parser('summary', help='Show case summary')
    parser_summary.add_argument('-c', '--case_id', required=True, help='Case ID')
    parser_summary.add_argument('-p', '--password', required=True, help='Password')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Handle show subcommands
    if args.command == 'show':
        if args.show_command == 'cases':
            return cmd_show_cases(args)
        elif args.show_command == 'items':
            return cmd_show_items(args)
        elif args.show_command == 'history':
            return cmd_show_history(args)
        else:
            parser_show_cases.print_help()
            return 1

    # Execute command
    commands = {
        'init': cmd_init,
        'add': cmd_add,
        'checkout': cmd_checkout,
        'checkin': cmd_checkin,
        'remove': cmd_remove,
        'verify': cmd_verify,
        'summary': cmd_summary,
    }

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
