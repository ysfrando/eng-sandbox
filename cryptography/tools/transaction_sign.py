import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


class TransactionSigner:
    def __init__(self):
        # Generate keys (in prod these would be securely stored/managed)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        def get_public_key_pem(self):
            """Return public key in PEM format for distribution"""
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')  
            
        def sign_transaction(self, transaction_data) -> dict:
            """
            Sign a transaction with the private key
            
            Args:
                transaction_data (dict): Transaction data to sign
                
            Returns:
                dict: Original transaction with signature attached
            """
            # Convert transaction to canonical string representation
            data_string = self._canonicalize(transaction_data)
            
            # Create signature
            signature = self.private_key.sign(
                data_string.encode('uft-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Encode signature as base64 string
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            # Return transaction with signature
            signed_tx = transaction_data.copy()
            signed_tx['signature'] = signature_b64
            return signed_tx
        
        def _canonicalize(self, data):
            """Convert dictionary to canonical string for consistent signing"""
            # Single implementation - in prod would use a more robuse method
            return str(sorted(data.items()))
        
class TransactionVerifier:
    def __init__(self, public_key_pem):
        """
        Initialize verifier with send's public key
        
        Args:
            public_key_pem (str): Public key in PEM format
        """
        self.public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        
    def verify_transaction(self, transaction_data):
        """
        Verify that a transaction was signed by the holder of the private key
        
        Args:
            transaction_data (dict): Transaction data with signature
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Extract and decode signature
        signature = base64.b64decode(transaction_data.pop('signature'))
        
        # Convert transaction to canonical string representation (same as signing)
        data_string = self._canonicalize(transaction_data)
        
        try:
            # Verify signature
            self.public_key.verify(
                signature,
                data_string.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        
    def _canonicalize(self, data):
        """Convert dictionary to canonical string for consistent verification"""
        # Simple implementation - in production would use a more robust method
        return str(sorted(data.items()))
    
    
# Example usage
if __name__ == "__main__":
    # Backend service that creates and signs transactions
    signer = TransactionSigner()
    
    # Create a cryptocurrency withdrawal transaction
    withdrawal = {
        'user_id': 'user_12345',
        'amount': '0.25',
        'currency': 'BTC',
        'destination_address': '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy',
        'timestamp': '2025-03-27T14:28:31.456Z',
        'nonce': '8a7b4c3d'
    }
    
    # Sign the transaction
    signed_withdrawal = signer.sign_transaction(withdrawal)
    print(f"Signed transaction: {signed_withdrawal}\n")
    
    # On receiving system (e.g., blockchain interface service)
    verifier = TransactionVerifier(signer.get_public_key_pem())
    is_valid = verifier.verify_transaction(signed_withdrawal.copy())
    
    print(f"Signature verification: {'Success' if is_valid else 'Failed'}")
    
    # Example of tampering detection
    tampered_tx = signed_withdrawal.copy()
    tampered_tx['amount'] = '1.25'  # Attacker tries to increase withdrawal amount
    is_valid = verifier.verify_transaction(tampered_tx)
    
    print(f"Tampered transaction verification: {'Success' if is_valid else 'Failed'}")
