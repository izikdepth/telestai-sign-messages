import os
from bitcoinrpc.authproxy import AuthServiceProxy
from dotenv import load_dotenv
from bitcoinlib.keys import Key
from ecdsa import SECP256k1, SigningKey, VerifyingKey
import hashlib
import re

load_dotenv()

# Set up RPC connection
TELESTAI_WALLET_USERNAME = os.getenv("TELESTAI_WALLET_USER")
TELESTAI_WALLET_PASSWORD = os.getenv("TELESTAI_WALLET_PASSWORD")
TELESTAI_WALLET_HOST = os.getenv("TELESTAI_WALLET_IP")
TELESTAI_WALLET_PORT = os.getenv("TELESTAI_PORT")
TELESTAI_WALLET_SEED = os.getenv("TELESTAI_WALLET_SEED")


def validate_seed_phrase(seed):
    # Check if the seed consists of 12 to 24 words separated by spaces
    words = seed.split()
    if len(words) not in [12, 24]:
        return False
    
    # Regular expression to check that each word contains only lowercase letters (BIP39 format)
    word_pattern = re.compile(r'^[a-z]+$')
    return all(word_pattern.match(word) for word in words)

# Validate seed phrase
if not validate_seed_phrase(TELESTAI_WALLET_SEED):
    raise ValueError("Invalid seed phrase. Please ensure it's a valid BIP39 12- or 24-word phrase.")


def connect_to_wallet():
    try:
        rpc_url = f"http://{TELESTAI_WALLET_USERNAME}:{TELESTAI_WALLET_PASSWORD}@{TELESTAI_WALLET_HOST}:{TELESTAI_WALLET_PORT}"
        return AuthServiceProxy(rpc_url)
    except Exception as e:
        print(f"Failed to connect to wallet: {str(e)}")
        return None

# Function to unlock the wallet temporarily
def unlock_wallet(rpc_connection, duration=60):
    try:
        rpc_connection.walletpassphrase(TELESTAI_WALLET_SEED, duration)
        print("Wallet unlocked.")
    except Exception as e:
        print(f"Failed to unlock wallet: {str(e)}")
        
def is_wallet_encrypted(rpc_connection):
    try:
        # Check wallet encryption status (if its encrypted or not)
        info = rpc_connection.getwalletinfo()
        # If the wallet is encrypted, 'encryptionstatus' will exist and be 'locked' or 'unlocked'
        return 'encryptionstatus' in info
    except Exception as e:
        print(f"Failed to check wallet encryption status: {str(e)}")
        return False

# Function to unlock the wallet temporarily (only if encrypted)
def unlock_wallet_if_encrypted(rpc_connection, duration=60):
    if is_wallet_encrypted(rpc_connection):
        try:
            #if wallet is locked,  unlock it with the seed phrase
            rpc_connection.walletpassphrase(TELESTAI_WALLET_SEED, duration)
            print("Wallet unlocked.")
        except Exception as e:
            print(f"Failed to unlock wallet: {str(e)}")
    else:
        # Skip unlocking because the wallet is unencrypted
        print("Wallet is not encrypted, no need to unlock.")

# Function to get the default address from the wallet
def get_wallet_address(rpc_connection):
    try:
        # Fetch the default wallet address
        return rpc_connection.getnewaddress()
    except Exception as e:
        print(f"Failed to retrieve wallet address: {str(e)}")
        return None

# Function to get private key for an address
def get_private_key(rpc_connection, wallet_address):
    try:
        # Unlock the wallet if encrypted before retrieving private key
        unlock_wallet_if_encrypted(rpc_connection)  
        return rpc_connection.dumpprivkey(wallet_address)
    except Exception as e:
        print(f"Failed to retrieve private key: {str(e)}")
        return None
    
    
# Function to sign a message (post, comment, like, etc)
def sign_message(post_message, private_key):
    message_hash = hashlib.sha256(post_message.encode('utf-8')).digest()
    signing_key = SigningKey.from_string(private_key.private_byte, curve=SECP256k1)
    signed_message = signing_key.sign(message_hash)
    return signed_message.hex()

# Function to verify a signed message
def verify_message(post_message, signed_message, pub_key):
    message_hash = hashlib.sha256(post_message.encode('utf-8')).digest()
    verifying_key = VerifyingKey.from_string(pub_key, curve=SECP256k1)
    return verifying_key.verify(bytes.fromhex(signed_message), message_hash)
        

# Main program logic
if __name__ == "__main__":
    # Connect to the wallet
    wallet = connect_to_wallet()

    if wallet:
        # Get the wallet address automatically
        address = get_wallet_address(wallet)

        if address:
            print(f"Using wallet address: {address}")

            # Get private key for the address
            private_key_wif = get_private_key(wallet, address)

            if private_key_wif:
                # Import the private key
                key = Key(import_key=private_key_wif)
                
                # Example message 
                message = "TELESTAI ROCKS"

                # Sign the message
                signature = sign_message(message, key)

                # Get the public key
                public_key = key.public_byte.hex()

                # Verify the signature
                is_valid = verify_message(message, signature, bytes.fromhex(public_key))

                print("Signature:", signature)
                print("Is valid:", is_valid)
            else:
                print("Private key retrieval failed.")
        else:
            print("Wallet address retrieval failed.")
    else:
        print("Wallet connection failed.")