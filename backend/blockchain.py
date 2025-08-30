import hashlib
import json
import time
import threading
from typing import List, Dict, Any, Set, Tuple
from urllib.parse import urlparse
from uuid import uuid4
from flask import Flask, jsonify, request
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Configuration constants
GENESIS_PREV_HASH = "912a2343d51cdba6e4adc1ab3037c21977d1f9a588d81b7d0553b30ced7542f8"
MINING_REWARD = 50.0
INITIAL_DIFFICULTY = 2
TARGET_BLOCK_TIME = 20.0
N_ADJUST = 5  # Number of blocks to consider for difficulty adjustment
MAX_TX_PER_BLOCK = 10
SYSTEM_ADDRESS = "SYSTEM"

class Transaction:
    def __init__(self, sender_pub_key: str, recipient_pub_key: str, amount: float, 
                 signature: str = None, timestamp: float = None, tx_id: str = None):
        self.sender_pub_key = sender_pub_key
        self.recipient_pub_key = recipient_pub_key
        self.amount = amount
        self.signature = signature
        self.timestamp = timestamp or time.time()
        self.tx_id = tx_id or self.calculate_tx_id()
    
    def calculate_tx_id(self) -> str:
        """Calculate transaction ID from content"""
        tx_data = f"{self.sender_pub_key}{self.recipient_pub_key}{self.amount}{self.timestamp}"
        return hashlib.sha256(tx_data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction to dictionary for serialization"""
        return {
            'tx_id': self.tx_id,
            'sender_pub_key': self.sender_pub_key,
            'recipient_pub_key': self.recipient_pub_key,
            'amount': self.amount,
            'signature': self.signature,
            'timestamp': self.timestamp
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Transaction':
        """Create Transaction from dictionary"""
        return Transaction(
            data['sender_pub_key'],
            data['recipient_pub_key'],
            data['amount'],
            data['signature'],
            data['timestamp'],
            data['tx_id']
        )
    
    def sign_transaction(self, private_key_pem: str) -> None:
        """Sign the transaction with the sender's private key"""
        if self.sender_pub_key == SYSTEM_ADDRESS:
            return  # System transactions don't need signatures
        
        # Load private key from PEM format
        priv_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
        # Create the message to sign (canonical JSON representation)
        signable_data = {
            'sender': self.sender_pub_key,
            'recipient': self.recipient_pub_key,
            'amount': self.amount,
            'timestamp': self.timestamp,
            'tx_id': self.tx_id
        }
        message = json.dumps(signable_data, sort_keys=True).encode()
        
        # Sign the message
        signature = priv_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        self.signature = signature.hex()
    
    def verify_signature(self) -> bool:
        """Verify the transaction signature"""
        if self.sender_pub_key == SYSTEM_ADDRESS:
            return True  # System transactions are always valid
        
        if not self.signature:
            return False
        
        try:
            # Load public key from PEM format
            pub_key = serialization.load_pem_public_key(
                self.sender_pub_key.encode(),
                backend=default_backend()
            )
            
            # Create the message that was signed (canonical JSON representation)
            signable_data = {
                'sender': self.sender_pub_key,
                'recipient': self.recipient_pub_key,
                'amount': self.amount,
                'timestamp': self.timestamp,
                'tx_id': self.tx_id
            }
            message = json.dumps(signable_data, sort_keys=True).encode()
            
            # Verify the signature
            pub_key.verify(
                bytes.fromhex(self.signature),
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except (InvalidSignature, ValueError, Exception):
            return False

class Block:
    def __init__(self, index: int, transactions: List[Transaction], 
                 previous_hash: str, nonce: int = 0, timestamp: float = None,
                 merkle_root: str = None, hash: str = None):
        self.index = index
        self.timestamp = timestamp or time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.merkle_root = merkle_root or self.calculate_merkle_root()
        self.hash = hash or self.calculate_hash()
        self.difficulty = INITIAL_DIFFICULTY  # Will be set by blockchain
    
    def calculate_hash(self) -> str:
        """Calculate the hash of the block"""
        block_string = f"{self.index}{self.timestamp}{self.previous_hash}{self.merkle_root}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def calculate_merkle_root(self) -> str:
        """Calculate the Merkle root of all transactions in the block using double SHA-256"""
        if not self.transactions:
            return hashlib.sha256("".encode()).hexdigest()
        
        # Use transaction IDs for merkle tree
        transaction_hashes = [tx.tx_id for tx in self.transactions]
        
        # Build merkle tree
        while len(transaction_hashes) > 1:
            new_hashes = []
            for i in range(0, len(transaction_hashes), 2):
                left = transaction_hashes[i]
                right = transaction_hashes[i + 1] if i + 1 < len(transaction_hashes) else left
                # Double hash for security
                combined = hashlib.sha256((left + right).encode()).hexdigest()
                combined = hashlib.sha256(combined.encode()).hexdigest()
                new_hashes.append(combined)
            transaction_hashes = new_hashes
        
        return transaction_hashes[0]
    
    def mine_block(self, difficulty: int) -> None:
        """Mine the block with the given difficulty"""
        self.difficulty = difficulty
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'merkle_root': self.merkle_root,
            'hash': self.hash,
            'difficulty': self.difficulty
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Block':
        """Create Block from dictionary"""
        transactions = [Transaction.from_dict(tx) for tx in data['transactions']]
        return Block(
            data['index'],
            transactions,
            data['previous_hash'],
            data['nonce'],
            data['timestamp'],
            data['merkle_root'],
            data['hash']
        )

class Wallet:
    def __init__(self):
        # Generate RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.address = self.get_public_key_pem()
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    def get_private_key_pem(self) -> str:
        """Get private key in PEM format (should be stored securely)"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    
    def create_transaction(self, recipient_pub_key: str, amount: float) -> Transaction:
        """Create and sign a new transaction"""
        transaction = Transaction(self.address, recipient_pub_key, amount)
        transaction.sign_transaction(self.get_private_key_pem())
        return transaction

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.nodes: Set[str] = set()
        self.difficulty = INITIAL_DIFFICULTY
        self.mining_reward = MINING_REWARD
        
        # Create the genesis block
        self.create_genesis_block()
    
    def create_genesis_block(self) -> None:
        """Create the genesis block with a proper system transaction"""
        # Create a special system transaction for the genesis block
        genesis_transaction = Transaction(
            SYSTEM_ADDRESS,
            "Genesis",  # Initial recipient
            1000.0,     # Initial supply
            None,       # No signature for system transactions
            time.time(),
            "genesis_tx_001"  # Fixed ID for genesis transaction
        )
        
        genesis_block = Block(0, [genesis_transaction], GENESIS_PREV_HASH)
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
    
    def get_last_block(self) -> Block:
        """Get the last block in the chain"""
        return self.chain[-1] if self.chain else None
    
    def add_transaction(self, transaction: Transaction) -> Tuple[bool, str]:
        """Add a new transaction to the pending transactions list with validation"""
        # Verify the transaction signature
        if not transaction.verify_signature():
            return False, "Invalid signature"
        
        # Check for duplicate transaction
        if any(tx.tx_id == transaction.tx_id for tx in self.pending_transactions):
            return False, "Duplicate transaction"
        
        # Check if transaction already exists in the blockchain
        for block in self.chain:
            if any(tx.tx_id == transaction.tx_id for tx in block.transactions):
                return False, "Transaction already confirmed"
        
        # Check if sender has enough balance
        sender_balance = self.get_balance(transaction.sender_pub_key)
        if sender_balance < transaction.amount:
            return False, "Insufficient balance"
        
        self.pending_transactions.append(transaction)
        return True, "Transaction added"
    
    def mine_pending_transactions(self, miner_address: str) -> Block:
        """Mine all pending transactions and create a new block"""
        if not self.pending_transactions:
            raise ValueError("No transactions to mine")
        
        # Get up to MAX_TX_PER_BLOCK transactions
        transactions_to_mine = self.pending_transactions[:MAX_TX_PER_BLOCK]
        
        # Add mining reward transaction
        reward_transaction = Transaction(
            SYSTEM_ADDRESS,
            miner_address,
            self.mining_reward,
            None,  # No signature for system transactions
            time.time(),
            f"reward_{uuid4().hex}"
        )
        transactions_to_mine.append(reward_transaction)
        
        # Create new block
        last_block = self.get_last_block()
        new_block = Block(
            len(self.chain),
            transactions_to_mine,
            last_block.hash if last_block else GENESIS_PREV_HASH
        )
        
        # Mine the block with current difficulty
        new_block.mine_block(self.difficulty)
        
        # Add the block to the chain
        self.chain.append(new_block)
        
        # Remove mined transactions from pending
        mined_tx_ids = {tx.tx_id for tx in transactions_to_mine}
        self.pending_transactions = [
            tx for tx in self.pending_transactions 
            if tx.tx_id not in mined_tx_ids
        ]
        
        # Adjust difficulty based on recent block times
        self.adjust_difficulty()
        
        return new_block
    
    def adjust_difficulty(self) -> None:
        """Adjust the mining difficulty based on the average time of last N_ADJUST blocks"""
        if len(self.chain) <= N_ADJUST:
            return  # Not enough blocks to adjust difficulty
        
        # Calculate average time of last N_ADJUST blocks
        total_time = 0
        for i in range(len(self.chain) - N_ADJUST, len(self.chain) - 1):
            total_time += self.chain[i + 1].timestamp - self.chain[i].timestamp
        
        average_time = total_time / (N_ADJUST - 1)
        
        # Adjust difficulty to target block time
        if average_time < TARGET_BLOCK_TIME / 2:
            self.difficulty += 1
        elif average_time > TARGET_BLOCK_TIME * 2:
            self.difficulty = max(1, self.difficulty - 1)
    
    def is_chain_valid(self, chain: List[Block] = None) -> Tuple[bool, str]:
        """Check if the blockchain is valid"""
        if chain is None:
            chain = self.chain
        
        # Check genesis block
        if not chain or chain[0].index != 0 or chain[0].previous_hash != GENESIS_PREV_HASH:
            return False, "Invalid genesis block"
        
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i-1]
            
            # Check if the current block hash is correct
            if current_block.hash != current_block.calculate_hash():
                return False, f"Invalid block hash at index {current_block.index}"
            
            # Check if the previous hash matches
            if current_block.previous_hash != previous_block.hash:
                return False, f"Previous hash mismatch at index {current_block.index}"
            
            # Check if the block has been mined (proof of work)
            target = "0" * current_block.difficulty
            if current_block.hash[:current_block.difficulty] != target:
                return False, f"Block {current_block.index} doesn't meet difficulty requirement"
            
            # Verify all transactions in the block
            for tx in current_block.transactions:
                if not tx.verify_signature():
                    return False, f"Invalid transaction signature in block {current_block.index}"
        
        return True, "Chain is valid"
    
    def get_balance(self, address: str) -> float:
        """Get the balance of an address by scanning the blockchain"""
        balance = 0.0
        
        # Calculate balance from confirmed transactions
        for block in self.chain:
            for tx in block.transactions:
                if tx.recipient_pub_key == address:
                    balance += tx.amount
                if tx.sender_pub_key == address:
                    balance -= tx.amount
        
        # Subtract pending outgoing transactions
        for tx in self.pending_transactions:
            if tx.sender_pub_key == address:
                balance -= tx.amount
        
        return balance
    
    def add_node(self, address: str) -> None:
        """Add a new node to the network"""
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        else:
            self.nodes.add(address)
    
    def resolve_conflicts(self) -> Tuple[bool, str]:
        """Consensus algorithm: resolves conflicts by replacing chain with longest valid chain"""
        max_length = len(self.chain)
        new_chain = None
        replacement_reason = ""
        
        # Check all nodes for longer valid chains
        for node in self.nodes:
            try:
                response = requests.get(f'http://{node}/chain', timeout=5)
                if response.status_code == 200:
                    chain_data = response.json()['chain']
                    
                    if len(chain_data) > max_length:
                        # Convert chain data to Block objects
                        chain = []
                        for block_data in chain_data:
                            block = Block.from_dict(block_data)
                            chain.append(block)
                        
                        # Check if the chain is valid
                        is_valid, reason = self.is_chain_valid(chain)
                        if is_valid:
                            max_length = len(chain_data)
                            new_chain = chain
                            replacement_reason = f"Longer chain from {node}"
            except requests.exceptions.RequestException:
                continue
        
        # Replace our chain if we found a longer valid chain
        if new_chain:
            self.chain = new_chain
            # Remove any pending transactions that are now in the chain
            chain_tx_ids = {tx.tx_id for block in self.chain for tx in block.transactions}
            self.pending_transactions = [
                tx for tx in self.pending_transactions 
                if tx.tx_id not in chain_tx_ids
            ]
            return True, replacement_reason
        
        return False, "No longer valid chain found"

# Initialize Flask application
app = Flask(__name__)

# Generate a unique node identifier
node_identifier = str(uuid4()).replace('-', '')

# Initialize blockchain and wallet
blockchain = Blockchain()
wallet = Wallet()

def broadcast_transaction(transaction: Transaction):
    """Broadcast transaction to all nodes in a separate thread"""
    def broadcast():
        for node in blockchain.nodes:
            try:
                requests.post(
                    f'http://{node}/transactions/broadcast', 
                    json=transaction.to_dict(),
                    timeout=3
                )
            except requests.exceptions.RequestException:
                continue
    
    threading.Thread(target=broadcast).start()

def broadcast_block(block: Block):
    """Broadcast block to all nodes in a separate thread"""
    def broadcast():
        for node in blockchain.nodes:
            try:
                requests.post(
                    f'http://{node}/blocks/new', 
                    json=block.to_dict(),
                    timeout=3
                )
            except requests.exceptions.RequestException:
                continue
    
    threading.Thread(target=broadcast).start()

@app.route('/mine', methods=['POST'])
def mine():
    """Mine a new block"""
    try:
        # Mine a new block
        mined_block = blockchain.mine_pending_transactions(wallet.address)
        
        response = {
            'message': 'New block mined',
            'block': mined_block.to_dict()
        }
        
        # Broadcast the new block to all nodes
        broadcast_block(mined_block)
        
        return jsonify(response), 200
    except ValueError as e:
        return jsonify({'message': str(e)}), 400
    except Exception as e:
        return jsonify({'message': 'Mining failed', 'error': str(e)}), 500

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    """Create a new transaction"""
    values = request.get_json()
    
    required = ['recipient', 'amount']
    if not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400
    
    try:
        # Create a new transaction
        transaction = wallet.create_transaction(values['recipient'], float(values['amount']))
        
        # Add to pending transactions
        success, message = blockchain.add_transaction(transaction)
        
        if not success:
            return jsonify({'message': message}), 400
        
        # Broadcast the transaction to all nodes
        broadcast_transaction(transaction)
        
        response = {'message': f'Transaction will be added to Block {len(blockchain.chain)}'}
        return jsonify(response), 201
    except Exception as e:
        return jsonify({'message': 'Transaction failed', 'error': str(e)}), 500

@app.route('/chain', methods=['GET'])
def full_chain():
    """Return the full blockchain"""
    response = {
        'chain': [block.to_dict() for block in blockchain.chain],
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    """Register new nodes"""
    values = request.get_json()
    
    nodes = values.get('nodes')
    if nodes is None:
        return jsonify({"message": "Please supply a valid list of nodes"}), 400
    
    for node in nodes:
        blockchain.add_node(node)
    
    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes)
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    """Resolve blockchain conflicts"""
    replaced, reason = blockchain.resolve_conflicts()
    
    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'reason': reason,
            'new_chain': [block.to_dict() for block in blockchain.chain]
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'reason': reason,
            'chain': [block.to_dict() for block in blockchain.chain]
        }
    
    return jsonify(response), 200

@app.route('/wallet/info', methods=['GET'])
def wallet_info():
    """Get wallet information (public only)"""
    balance = blockchain.get_balance(wallet.address)
    
    response = {
        'address': wallet.address,
        'balance': balance
    }
    return jsonify(response), 200

@app.route('/transactions/broadcast', methods=['POST'])
def broadcast_transaction_receive():
    """Receive a broadcasted transaction"""
    values = request.get_json()
    
    try:
        transaction = Transaction.from_dict(values)
        
        # Add to pending transactions
        success, message = blockchain.add_transaction(transaction)
        
        if not success:
            return jsonify({'message': message}), 400
        
        return jsonify({'message': 'Transaction added'}), 201
    except Exception as e:
        return jsonify({'message': 'Invalid transaction', 'error': str(e)}), 400

@app.route('/blocks/new', methods=['POST'])
def receive_block():
    """Receive a new block from the network"""
    values = request.get_json()
    
    try:
        block = Block.from_dict(values)
        
        # Basic validation
        last_block = blockchain.get_last_block()
        if (block.index != len(blockchain.chain) or 
            block.previous_hash != last_block.hash or
            block.hash != block.calculate_hash() or
            block.hash[:block.difficulty] != "0" * block.difficulty):
            return jsonify({'message': 'Invalid block'}), 400
        
        # Add the block to the chain
        blockchain.chain.append(block)
        
        # Remove transactions from pending
        block_tx_ids = {tx.tx_id for tx in block.transactions}
        blockchain.pending_transactions = [
            tx for tx in blockchain.pending_transactions 
            if tx.tx_id not in block_tx_ids
        ]
        
        return jsonify({'message': 'Block added'}), 201
    except Exception as e:
        return jsonify({'message': 'Invalid block', 'error': str(e)}), 400

@app.route('/pending_transactions', methods=['GET'])
def get_pending_transactions():
    """Get pending transactions"""
    response = {
        'pending_transactions': [tx.to_dict() for tx in blockchain.pending_transactions],
        'count': len(blockchain.pending_transactions)
    }
    return jsonify(response), 200

@app.route('/', methods=['GET'])
def index():
    """Return a welcome message and API guide"""
    return jsonify({
        'message': 'Welcome to the Green Hydrogen Credits (GHC) Blockchain API!',
        'api_routes': {
            '/': 'This API guide.',
            '/mine [POST]': 'Mine a new block.',
            '/transactions/new [POST]': 'Create a new transaction.',
            '/chain [GET]': 'View the full blockchain.',
            '/pending_transactions [GET]': 'View pending transactions.',
            '/nodes/register [POST]': 'Register a new node on the network.',
            '/nodes/resolve [GET]': 'Resolve conflicts and synchronize the chain.',
            '/wallet/info [GET]': 'Get your wallet public key and balance.'
        }
    }), 200

if __name__ == '__main__':
    from argparse import ArgumentParser
    
    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='Port to listen on')
    args = parser.parse_args()
    
    port = args.port
    
    print(f"Starting GHC node on port {port}")
    print(f"Wallet address: {wallet.address}")
    print(f"Genesis block hash: {blockchain.chain[0].hash}")
    
    app.run(host='0.0.0.0', port=port, threaded=True)