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
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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


def get_blockchain_path():
    """Get the blockchain file path from environment or use default."""
    return os.environ.get("BCHOC_FILE_PATH", "blockchain.bin")


def encrypt_case_id(case_uuid):
    """Encrypt a UUID case_id using AES ECB."""
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    # Convert UUID to bytes (16 bytes)
    uuid_bytes = uuid.UUID(case_uuid).bytes
    # Pad to 32 bytes
    padded = uuid_bytes + b'\x00' * 16
    encrypted = cipher.encrypt(padded)
    return encrypted


def decrypt_case_id(encrypted_data):
    """Decrypt case_id to UUID string."""
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_data)
    # Take first 16 bytes and convert to UUID
    uuid_bytes = decrypted[:16]
    return str(uuid.UUID(bytes=uuid_bytes))


def encrypt_item_id(item_id):
    """Encrypt a 4-byte integer item_id using AES ECB."""
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    # Convert integer to 4-byte representation
    item_bytes = struct.pack('I', int(item_id))
    # Pad to 32 bytes
    padded = item_bytes + b'\x00' * 28
    encrypted = cipher.encrypt(padded)
    return encrypted


def decrypt_item_id(encrypted_data):
    """Decrypt item_id to integer."""
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted_data)
    # Take first 4 bytes and convert to integer
    item_int = struct.unpack('I', decrypted[:4])[0]
    return item_int


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


def calculate_block_hash(block_data):
    """Calculate SHA-256 hash of block data (excluding the hash field itself)."""
    # Hash everything after the first 32 bytes (previous hash)
    return hashlib.sha256(block_data[32:]).digest()


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
    """Show all cases in the blockchain."""
    # Validate password if provided
    has_password = hasattr(args, 'password') and args.password is not None

    if has_password and not validate_password(args.password):
        print("Invalid password")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    # Collect unique cases
    cases = set()
    for block in blockchain.blocks:
        if block.case_id != b'0' * 32:
            if has_password:
                try:
                    case_uuid = decrypt_case_id(block.case_id)
                    cases.add(case_uuid)
                except:
                    cases.add(block.case_id.hex())
            else:
                # Show encrypted hex without password
                cases.add(block.case_id.hex())

    # Print cases
    for case in sorted(cases):
        print(case)

    return 0


def cmd_show_items(args):
    """Show all items for a given case."""
    # Validate password if provided
    has_password = hasattr(args, 'password') and args.password is not None

    if has_password and not validate_password(args.password):
        print("Invalid password")
        return 1

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
            if has_password:
                try:
                    item_id = decrypt_item_id(block.evidence_id)
                    items.add(item_id)
                except:
                    items.add(block.evidence_id.hex())
            else:
                # Show encrypted hex without password
                items.add(block.evidence_id.hex())

    # Print items
    for item in sorted(items):
        print(item)

    return 0


def cmd_show_history(args):
    """Show blockchain history with optional filters."""
    # Validate password if provided
    has_password = args.password is not None

    if has_password and not validate_password(args.password):
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

        # Decrypt if password provided
        if has_password:
            try:
                case_id = decrypt_case_id(block.case_id)
                item_id = decrypt_item_id(block.evidence_id)
            except:
                case_id = block.case_id.hex()
                item_id = block.evidence_id.hex()
        else:
            case_id = block.case_id.hex()
            item_id = block.evidence_id.hex()

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

        # Verify block checksum
        recalc_hash = block.get_hash()
        if recalc_hash != block_hash:
            errors.append({
                'type': 'checksum_mismatch',
                'block_hash': block_hash.hex()
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
        elif error['type'] == 'checksum_mismatch':
            print("Block contents do not match block checksum.")
        elif error['type'] == 'operation_after_removal':
            print("Item checked out or checked in after removal from chain.")

        return 1


def cmd_summary(args):
    """Display summary statistics for a case."""
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

    # Track items and their states
    items = {}  # item_id -> current state

    for block in blockchain.blocks:
        if block.case_id == encrypted_case:
            item_id = decrypt_item_id(block.evidence_id)
            state = block.state.rstrip(b'\x00').decode('utf-8')
            items[item_id] = state

    # Count states
    total_items = len(items)
    checked_in = sum(1 for state in items.values() if state == "CHECKEDIN")
    checked_out = sum(1 for state in items.values() if state == "CHECKEDOUT")
    disposed = sum(1 for state in items.values() if state == "DISPOSED")
    destroyed = sum(1 for state in items.values() if state == "DESTROYED")
    released = sum(1 for state in items.values() if state == "RELEASED")

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
    parser_cases.add_argument('-p', '--password', help='Password (optional, shows decrypted with password)')

    # show items command
    parser_items = show_subparsers.add_parser('items', help='Show items in a case')
    parser_items.add_argument('-c', '--case_id', required=True, help='Case ID')
    parser_items.add_argument('-p', '--password', help='Password (optional, shows decrypted with password)')

    # show history command
    parser_history = show_subparsers.add_parser('history', help='Show history')
    parser_history.add_argument('-c', '--case_id', help='Filter by case ID')
    parser_history.add_argument('-i', '--item_id', help='Filter by item ID')
    parser_history.add_argument('-n', '--num_entries', type=int, help='Number of entries to show')
    parser_history.add_argument('-r', '--reverse', action='store_true', help='Reverse order')
    parser_history.add_argument('-p', '--password', help='Password')

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
