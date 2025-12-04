#!/usr/bin/env python3
"""
Blockchain Chain of Custody System
CSE469 Group Project
"""

import sys
import os
import struct
import hashlib
import argparse
import uuid
from datetime import datetime, timezone
from Crypto.Cipher import AES

# Constants
AES_KEY = b"R0chLi4uLi4uLi4="
BLOCK_HEADER_SIZE = 144

# Password configuration
PASSWORDS = {
    "POLICE": os.environ.get("BCHOC_PASSWORD_POLICE", "P80P"),
    "LAWYER": os.environ.get("BCHOC_PASSWORD_LAWYER", "L76L"),
    "ANALYST": os.environ.get("BCHOC_PASSWORD_ANALYST", "A65A"),
    "EXECUTIVE": os.environ.get("BCHOC_PASSWORD_EXECUTIVE", "E69E"),
    "CREATOR": os.environ.get("BCHOC_PASSWORD_CREATOR", "C67C"),
}

PASSWORD_TO_ROLE = {v: k for k, v in PASSWORDS.items()}

STATES = ["INITIAL", "CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"]
REMOVAL_REASONS = ["DISPOSED", "DESTROYED", "RELEASED"]

# AES cipher for encryption/decryption
_cipher = AES.new(AES_KEY, AES.MODE_ECB)


def aes_encrypt_block(plaintext):
    return _cipher.encrypt(plaintext)


def aes_decrypt_block(ciphertext):
    return _cipher.decrypt(ciphertext)


def get_blockchain_path():
    return os.environ.get("BCHOC_FILE_PATH", "blockchain.bin")


def encrypt_case_id(case_uuid):
    """Encrypt a UUID using AES ECB, return 32 hex bytes."""
    uuid_bytes = uuid.UUID(case_uuid).bytes
    encrypted = aes_encrypt_block(uuid_bytes)
    return encrypted.hex().encode('ascii')


def decrypt_case_id(encrypted_bytes):
    """Decrypt case_id from hex-encoded bytes to UUID string."""
    encrypted = bytes.fromhex(encrypted_bytes.decode('ascii'))
    decrypted = aes_decrypt_block(encrypted)
    return str(uuid.UUID(bytes=decrypted))


def encrypt_item_id(item_id):
    """Encrypt item_id using AES ECB, return 32 hex bytes."""
    item_int = int(item_id)
    item_bytes = item_int.to_bytes(16, byteorder='big')
    encrypted = aes_encrypt_block(item_bytes)
    return encrypted.hex().encode('ascii')


def decrypt_item_id(encrypted_bytes):
    """Decrypt item_id from hex-encoded bytes to integer."""
    encrypted = bytes.fromhex(encrypted_bytes.decode('ascii'))
    decrypted = aes_decrypt_block(encrypted)
    return int.from_bytes(decrypted, byteorder='big')


def format_state(state_str):
    """Format state string to exactly 12 bytes with null padding."""
    state_bytes = state_str.encode('utf-8')
    if len(state_bytes) > 12:
        state_bytes = state_bytes[:12]
    state_bytes = state_bytes.ljust(12, b'\x00')
    return state_bytes


def format_text_field(text, max_len):
    """Format text field to fixed length with null padding."""
    text_bytes = text.encode('utf-8') if isinstance(text, str) else text
    if len(text_bytes) > max_len:
        text_bytes = text_bytes[:max_len]
    else:
        text_bytes = text_bytes + b'\x00' * (max_len - len(text_bytes))
    return text_bytes


class Block:
    """Represents a single block in the blockchain."""

    def __init__(self, prev_hash, timestamp, case_id, evidence_id, state, creator, owner, data, raw_bytes=None):
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.case_id = case_id
        self.evidence_id = evidence_id
        self.state = state
        self.creator = creator
        self.owner = owner
        self.data = data
        self.data_length = len(data)
        self._raw_bytes = raw_bytes

    def to_bytes(self):
        header = struct.pack(
            '=32s d 32s 32s 12s 12s 12s I',
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
        header_size = BLOCK_HEADER_SIZE
        if len(data) < header_size:
            return None

        header = struct.unpack('=32s d 32s 32s 12s 12s 12s I', data[:header_size])

        prev_hash = header[0]
        timestamp = header[1]
        case_id = header[2]
        evidence_id = header[3]
        state = header[4]
        creator = header[5]
        owner = header[6]
        data_length = header[7]

        block_data = data[header_size:header_size + data_length]
        return Block(prev_hash, timestamp, case_id, evidence_id, state, creator, owner, block_data, raw_bytes=data)

    def get_hash(self):
        block_bytes = self._raw_bytes if self._raw_bytes is not None else self.to_bytes()
        return hashlib.sha256(block_bytes).digest()


class Blockchain:
    """Manages the blockchain."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.blocks = []
        self.load_blockchain()

    def load_blockchain(self):
        if not os.path.exists(self.filepath):
            return

        try:
            with open(self.filepath, 'rb') as f:
                data = f.read()

            if len(data) == 0:
                return

            offset = 0
            while offset < len(data):
                if len(data) - offset < BLOCK_HEADER_SIZE:
                    break

                header_data = data[offset:offset + BLOCK_HEADER_SIZE]
                data_length = struct.unpack('=I', header_data[140:144])[0]

                block_size = BLOCK_HEADER_SIZE + data_length
                if offset + block_size > len(data):
                    break
                    
                block_data = data[offset:offset + block_size]

                block = Block.from_bytes(block_data)
                if block:
                    self.blocks.append(block)

                offset += block_size
        except Exception:
            self.blocks = []

    def save_blockchain(self):
        with open(self.filepath, 'wb') as f:
            for block in self.blocks:
                f.write(block.to_bytes())

    def add_block(self, block):
        self.blocks.append(block)
        self.save_blockchain()

    def get_initial_block(self):
        return Block(
            prev_hash=b'\x00' * 32,
            timestamp=datetime.now(timezone.utc).timestamp(),
            case_id=b'0' * 32,
            evidence_id=b'0' * 32,
            state=b'INITIAL\x00\x00\x00\x00\x00',
            creator=b'\x00' * 12,
            owner=b'\x00' * 12,
            data=b'Initial block\x00'
        )

    def has_initial_block(self):
        if len(self.blocks) == 0:
            return False

        first_block = self.blocks[0]
        try:
            state = first_block.state.rstrip(b'\x00').decode('utf-8', errors='ignore').strip()
        except:
            return False
        
        is_initial_state = ("INITIAL" in state)
        has_zero_prev_hash = (first_block.prev_hash == b'\x00' * 32)
        return has_zero_prev_hash and is_initial_state

    def is_valid_blockchain(self):
        """Check if the blockchain file is valid."""
        if len(self.blocks) == 0:
            return False
        return self.has_initial_block()

    def get_last_block_hash(self):
        if len(self.blocks) == 0:
            return b'\x00' * 32
        return self.blocks[-1].get_hash()

    def item_exists(self, item_id):
        encrypted_item = encrypt_item_id(item_id)
        for block in self.blocks:
            if block.evidence_id == encrypted_item:
                return True
        return False

    def get_item_state(self, item_id):
        encrypted_item = encrypt_item_id(item_id)
        for block in reversed(self.blocks):
            if block.evidence_id == encrypted_item:
                state = block.state.rstrip(b'\x00').decode('utf-8')
                return state
        return None

    def get_item_case(self, item_id):
        encrypted_item = encrypt_item_id(item_id)
        for block in self.blocks:
            if block.evidence_id == encrypted_item:
                return block.case_id
        return None

    def get_item_creator(self, item_id):
        """Get the original creator of an item."""
        encrypted_item = encrypt_item_id(item_id)
        for block in self.blocks:
            if block.evidence_id == encrypted_item:
                return block.creator
        return b'\x00' * 12

    def get_item_last_checkin_owner(self, item_id):
        """Get the owner from the last checkin for this item."""
        encrypted_item = encrypt_item_id(item_id)
        for block in reversed(self.blocks):
            if block.evidence_id == encrypted_item:
                state = block.state.rstrip(b'\x00').decode('utf-8')
                if state == "CHECKEDIN":
                    return block.owner
        return b'\x00' * 12


def validate_password(password, required_role=None):
    valid_passwords = list(PASSWORDS.values())

    if password not in valid_passwords:
        return False

    if required_role == "CREATOR":
        return password == PASSWORDS["CREATOR"]

    return True


def get_role_from_password(password):
    """Get the role name from a password."""
    return PASSWORD_TO_ROLE.get(password, "")


def validate_uuid(uuid_str):
    try:
        uuid.UUID(uuid_str)
        return True
    except:
        return False


def format_timestamp(ts):
    """Format timestamp as ISO format."""
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f') + '+00:00'


def cmd_init(args):
    """Initialize the blockchain."""
    blockchain_path = get_blockchain_path()
    
    if os.path.exists(blockchain_path):
        blockchain = Blockchain(blockchain_path)
        if blockchain.has_initial_block():
            print("Blockchain file found with INITIAL block.")
            return 0
        else:
            print("Invalid blockchain file.")
            return 1

    blockchain = Blockchain(blockchain_path)
    initial_block = blockchain.get_initial_block()
    blockchain.add_block(initial_block)
    print("Blockchain file not found. Created INITIAL block.")
    return 0


def cmd_add(args):
    """Add new evidence item(s) to the blockchain."""
    if not validate_password(args.password, "CREATOR"):
        print("Invalid password")
        return 1

    if not validate_uuid(args.case_id):
        print("Invalid case_id format")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    if not blockchain.has_initial_block():
        initial_block = blockchain.get_initial_block()
        blockchain.add_block(initial_block)

    for item_id in args.item_id:
        if blockchain.item_exists(item_id):
            print(f"Item {item_id} already exists in blockchain")
            return 1

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
            owner=b'\x00' * 12,
            data=b''
        )

        blockchain.add_block(block)

        timestamp_str = format_timestamp(timestamp)
        print(f"Added item: {item_id}")
        print(f"Status: CHECKEDIN")
        print(f"Time of action: {timestamp_str}")

    return 0


def cmd_checkout(args):
    """Check out an evidence item."""
    if not validate_password(args.password):
        print("Invalid password")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    if not blockchain.item_exists(args.item_id):
        print(f"Item {args.item_id} not found in blockchain")
        return 1

    current_state = blockchain.get_item_state(args.item_id)
    if current_state != "CHECKEDIN":
        print(f"Cannot checkout item in state {current_state}")
        return 1

    timestamp = datetime.now(timezone.utc).timestamp()
    case_id = blockchain.get_item_case(args.item_id)
    encrypted_item = encrypt_item_id(args.item_id)
    original_creator = blockchain.get_item_creator(args.item_id)
    role = get_role_from_password(args.password)

    block = Block(
        prev_hash=blockchain.get_last_block_hash(),
        timestamp=timestamp,
        case_id=case_id,
        evidence_id=encrypted_item,
        state=format_state("CHECKEDOUT"),
        creator=original_creator,
        owner=format_text_field(role, 12),
        data=b''
    )

    blockchain.add_block(block)

    timestamp_str = format_timestamp(timestamp)
    decrypted_case = decrypt_case_id(case_id)
    print(f"Case: {decrypted_case}")
    print(f"Checked out item: {args.item_id}")
    print(f"Status: CHECKEDOUT")
    print(f"Time of action: {timestamp_str}")

    return 0


def cmd_checkin(args):
    """Check in an evidence item."""
    if not validate_password(args.password):
        print("Invalid password")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    if not blockchain.item_exists(args.item_id):
        print(f"Item {args.item_id} not found in blockchain")
        return 1

    current_state = blockchain.get_item_state(args.item_id)
    if current_state != "CHECKEDOUT":
        print(f"Cannot checkin item in state {current_state}")
        return 1

    timestamp = datetime.now(timezone.utc).timestamp()
    case_id = blockchain.get_item_case(args.item_id)
    encrypted_item = encrypt_item_id(args.item_id)
    original_creator = blockchain.get_item_creator(args.item_id)
    role = get_role_from_password(args.password)

    block = Block(
        prev_hash=blockchain.get_last_block_hash(),
        timestamp=timestamp,
        case_id=case_id,
        evidence_id=encrypted_item,
        state=format_state("CHECKEDIN"),
        creator=original_creator,
        owner=format_text_field(role, 12),
        data=b''
    )

    blockchain.add_block(block)

    timestamp_str = format_timestamp(timestamp)
    decrypted_case = decrypt_case_id(case_id)
    print(f"Case: {decrypted_case}")
    print(f"Checked in item: {args.item_id}")
    print(f"Status: CHECKEDIN")
    print(f"Time of action: {timestamp_str}")

    return 0


def cmd_show_cases(args):
    """Show all cases in the blockchain."""
    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    cases = set()
    for block in blockchain.blocks:
        state = block.state.rstrip(b'\x00').decode('utf-8', errors='ignore')
        if state == "INITIAL":
            continue
        try:
            case_uuid = decrypt_case_id(block.case_id)
            cases.add(case_uuid)
        except:
            pass

    for case in sorted(cases):
        print(case)

    return 0


def cmd_show_items(args):
    """Show all items for a given case."""
    if not validate_uuid(args.case_id):
        print("Invalid case_id format")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    encrypted_case = encrypt_case_id(args.case_id)

    items = set()
    for block in blockchain.blocks:
        if block.case_id == encrypted_case:
            try:
                item_id = decrypt_item_id(block.evidence_id)
                items.add(item_id)
            except:
                pass

    for item in sorted(items):
        print(item)

    return 0


def cmd_show_history(args):
    """Show blockchain history with optional filters."""
    if not args.password:
        print("Password required")
        return 1
    
    if not validate_password(args.password):
        print("Invalid password")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    filtered_blocks = []
    for block in blockchain.blocks:
        is_initial = (block.state.rstrip(b'\x00').decode('utf-8', errors='ignore') == "INITIAL")
        
        if args.case_id:
            if not validate_uuid(args.case_id):
                print("Invalid case_id format")
                return 1
            encrypted_case = encrypt_case_id(args.case_id)
            if block.case_id != encrypted_case:
                if is_initial:
                    continue
                continue

        if args.item_id:
            encrypted_item = encrypt_item_id(args.item_id)
            if block.evidence_id != encrypted_item:
                if is_initial:
                    continue
                continue

        filtered_blocks.append(block)

    if args.reverse:
        filtered_blocks = list(reversed(filtered_blocks))

    if args.num_entries:
        filtered_blocks = filtered_blocks[:args.num_entries]

    for i, block in enumerate(filtered_blocks):
        if i > 0:
            print()

        state = block.state.rstrip(b'\x00').decode('utf-8')
        
        if state == "INITIAL":
            case_id = "00000000-0000-0000-0000-000000000000"
            item_id = "0"
        else:
            try:
                case_id = decrypt_case_id(block.case_id)
                item_id = decrypt_item_id(block.evidence_id)
            except:
                case_id = block.case_id.decode('ascii', errors='ignore')
                item_id = block.evidence_id.decode('ascii', errors='ignore')
        
        timestamp_str = format_timestamp(block.timestamp)

        print(f"Case: {case_id}")
        print(f"Item: {item_id}")
        print(f"Action: {state}")
        print(f"Time: {timestamp_str}")

    return 0


def cmd_remove(args):
    """Remove an evidence item from the chain of custody."""
    if not validate_password(args.password, "CREATOR"):
        print("Invalid password")
        return 1

    if args.reason not in REMOVAL_REASONS:
        print(f"Invalid removal reason. Must be one of: {', '.join(REMOVAL_REASONS)}")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    if not blockchain.item_exists(args.item_id):
        print(f"Item {args.item_id} not found in blockchain")
        return 1

    current_state = blockchain.get_item_state(args.item_id)
    if current_state != "CHECKEDIN":
        print(f"Cannot remove item in state {current_state}. Item must be CHECKEDIN.")
        return 1

    timestamp = datetime.now(timezone.utc).timestamp()
    case_id = blockchain.get_item_case(args.item_id)
    encrypted_item = encrypt_item_id(args.item_id)
    original_creator = blockchain.get_item_creator(args.item_id)
    
    last_checkin_owner = blockchain.get_item_last_checkin_owner(args.item_id)
    owner_str = last_checkin_owner.rstrip(b'\x00').decode('utf-8')
    if not owner_str:
        owner_str = "POLICE"
    
    if args.owner:
        owner_str = args.owner

    block = Block(
        prev_hash=blockchain.get_last_block_hash(),
        timestamp=timestamp,
        case_id=case_id,
        evidence_id=encrypted_item,
        state=format_state(args.reason),
        creator=original_creator,
        owner=format_text_field(owner_str, 12),
        data=b''
    )

    blockchain.add_block(block)

    timestamp_str = format_timestamp(timestamp)
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

    block_hashes = {}
    computed_hashes = []
    for i, block in enumerate(blockchain.blocks):
        block_hash = block.get_hash()
        computed_hashes.append(block_hash)
        block_hashes[block_hash] = i

    item_states = {}
    added_items = set()
    parent_children = {}

    for i, block in enumerate(blockchain.blocks):
        block_hash = computed_hashes[i]
        prev_hash = block.prev_hash

        if i == 0:
            if prev_hash != b'\x00' * 32:
                errors.append({
                    'type': 'invalid_initial',
                    'block_hash': block_hash.hex()
                })
            continue

        if prev_hash == b'\x00' * 32:
            errors.append({
                'type': 'parent_not_found',
                'block_hash': block_hash.hex(),
                'parent_hash': prev_hash.hex()
            })
            continue
        
        parent_found = prev_hash in block_hashes and block_hashes[prev_hash] < i
        if not parent_found:
            errors.append({
                'type': 'parent_not_found',
                'block_hash': block_hash.hex(),
                'parent_hash': prev_hash.hex()
            })
            continue

        if prev_hash not in parent_children:
            parent_children[prev_hash] = []
        parent_children[prev_hash].append(block_hash)

        if len(parent_children[prev_hash]) > 1:
            errors.append({
                'type': 'duplicate_parent',
                'block_hash': block_hash.hex(),
                'parent_hash': prev_hash.hex()
            })
            continue

        item_id = block.evidence_id
        state = block.state.rstrip(b'\x00').decode('utf-8')

        if state == "CHECKEDIN":
            if item_id in added_items:
                prev_state = item_states.get(item_id)
                if prev_state not in ["CHECKEDOUT"]:
                    errors.append({
                        'type': 'invalid_state_transition',
                        'block_hash': block_hash.hex(),
                        'detail': f'CHECKEDIN after {prev_state}'
                    })
                    continue
            else:
                added_items.add(item_id)
            item_states[item_id] = "CHECKEDIN"

        elif state == "CHECKEDOUT":
            prev_state = item_states.get(item_id)
            if prev_state != "CHECKEDIN":
                errors.append({
                    'type': 'invalid_state_transition',
                    'block_hash': block_hash.hex(),
                    'detail': f'CHECKEDOUT after {prev_state}'
                })
                continue
            item_states[item_id] = "CHECKEDOUT"

        elif state in REMOVAL_REASONS:
            prev_state = item_states.get(item_id)
            if prev_state != "CHECKEDIN":
                errors.append({
                    'type': 'invalid_state_transition',
                    'block_hash': block_hash.hex(),
                    'detail': f'{state} after {prev_state}'
                })
                continue
            item_states[item_id] = state

    print(f"Transactions in blockchain: {num_transactions}")

    if len(errors) == 0:
        print("State of blockchain: CLEAN")
        return 0
    else:
        print("State of blockchain: ERROR")
        error = errors[0]
        print(f"Bad block: {error['block_hash']}")

        if error['type'] == 'parent_not_found':
            print(f"Parent block: NOT FOUND")
        elif error['type'] == 'duplicate_parent':
            print(f"Parent block: {error['parent_hash']}")
            print("Two blocks were found with the same parent.")
        elif error['type'] == 'invalid_state_transition':
            print(f"Invalid state transition: {error.get('detail', '')}")
        elif error['type'] == 'invalid_initial':
            print("Invalid initial block.")

        return 1


def cmd_summary(args):
    """Display summary statistics for a case."""
    if hasattr(args, 'password') and args.password:
        if not validate_password(args.password):
            print("Invalid password")
            return 1

    if not validate_uuid(args.case_id):
        print("Invalid case_id format")
        return 1

    blockchain_path = get_blockchain_path()
    blockchain = Blockchain(blockchain_path)

    encrypted_case = encrypt_case_id(args.case_id)

    unique_items = set()
    checked_in = 0
    checked_out = 0
    disposed = 0
    destroyed = 0
    released = 0

    for block in blockchain.blocks:
        if block.case_id == encrypted_case:
            try:
                item_id = decrypt_item_id(block.evidence_id)
                unique_items.add(item_id)
            except:
                continue
            state = block.state.rstrip(b'\x00').decode('utf-8')
            
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

    print(f"Case Summary for Case ID: {args.case_id}")
    print(f"Total Evidence Items: {total_items}")
    print(f"Checked In: {checked_in}")
    print(f"Checked Out: {checked_out}")
    print(f"Disposed: {disposed}")
    print(f"Destroyed: {destroyed}")
    print(f"Released: {released}")

    return 0


def main():
    parser = argparse.ArgumentParser(description='Blockchain Chain of Custody')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # init command
    parser_init = subparsers.add_parser('init', help='Initialize blockchain')

    # add command
    parser_add = subparsers.add_parser('add', help='Add evidence item')
    parser_add.add_argument('-c', '--case_id', required=True, help='Case ID (UUID)')
    parser_add.add_argument('-i', '--item_id', required=True, action='append', help='Item ID')
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

    # show command
    parser_show = subparsers.add_parser('show', help='Show information')
    show_subparsers = parser_show.add_subparsers(dest='show_command')

    parser_cases = show_subparsers.add_parser('cases', help='Show all cases')

    parser_items = show_subparsers.add_parser('items', help='Show items in a case')
    parser_items.add_argument('-c', '--case_id', required=True, help='Case ID')

    parser_history = show_subparsers.add_parser('history', help='Show history')
    parser_history.add_argument('-c', '--case_id', help='Filter by case ID')
    parser_history.add_argument('-i', '--item_id', help='Filter by item ID')
    parser_history.add_argument('-n', '--num_entries', type=int, help='Number of entries')
    parser_history.add_argument('-r', '--reverse', action='store_true', help='Reverse order')
    parser_history.add_argument('-p', '--password', required=True, help='Password')

    # remove command - support both -y/--reason and --why
    parser_remove = subparsers.add_parser('remove', help='Remove evidence item')
    parser_remove.add_argument('-i', '--item_id', required=True, help='Item ID')
    parser_remove.add_argument('-y', '--reason', '--why', dest='reason', required=True, 
                               help='Reason (DISPOSED, DESTROYED, RELEASED)')
    parser_remove.add_argument('-o', '--owner', help='Owner info')
    parser_remove.add_argument('-p', '--password', required=True, help='Password')

    # verify command
    parser_verify = subparsers.add_parser('verify', help='Verify blockchain integrity')

    # summary command - password is optional
    parser_summary = subparsers.add_parser('summary', help='Show case summary')
    parser_summary.add_argument('-c', '--case_id', required=True, help='Case ID')
    parser_summary.add_argument('-p', '--password', help='Password (optional)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'show':
        if args.show_command == 'cases':
            return cmd_show_cases(args)
        elif args.show_command == 'items':
            return cmd_show_items(args)
        elif args.show_command == 'history':
            return cmd_show_history(args)
        else:
            parser_show.print_help()
            return 1

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
