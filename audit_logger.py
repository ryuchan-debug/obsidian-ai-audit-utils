"""
Audit Logger with Hash Chain and RSA Signature

Phase 2 Implementation:
- Hash chain for tamper detection
- RSA-SHA256 signature
- Request/response hashing (content not stored)
- OpenTelemetry-compatible fields

Security Features:
- Integrity: log_hash = SHA256(current_log)
- Chain: previous_hash = hash of previous log
- Signature: RSA-SHA256(log_hash + previous_hash)
"""

import json
import hashlib
import datetime
import os
import logging
from typing import Dict, Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp":"%(asctime)s","level":"%(levelname)s","module":"%(module)s","message":"%(message)s"}'
)

class AuditLogger:
    def __init__(self, key_dir: str = "./keys"):
        """
        Initialize audit logger with RSA key management.
        
        Args:
            key_dir: Directory to store RSA keys
        """
        self.key_dir = key_dir
        os.makedirs(key_dir, exist_ok=True)
        
        self.private_key_path = os.path.join(key_dir, "audit_private_key.pem")
        self.public_key_path = os.path.join(key_dir, "audit_public_key.pem")
        
        # Load or generate keys
        if os.path.exists(self.private_key_path):
            self.private_key = self._load_private_key()
            self.public_key = self._load_public_key()
        else:
            self.private_key, self.public_key = self._generate_keys()
        
        # Track previous hash for chain
        self.previous_hash = "0" * 64  # Genesis hash
    
    def _generate_keys(self):
        """Generate RSA-2048 key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        try:
            # Save private key
            with open(self.private_key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save public key
            with open(self.public_key_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            logging.info(f"Generated RSA keys: {self.key_dir}")
            print(f"✅ Generated RSA keys: {self.key_dir}")
            return private_key, public_key
        except Exception as e:
            logging.error(f"Failed to save RSA keys: {e}")
            raise
    
    def _load_private_key(self):
        """Load private key from file."""
        try:
            with open(self.private_key_path, "rb") as f:
                return serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
        except FileNotFoundError:
            logging.error(f"Private key not found: {self.private_key_path}")
            raise
        except Exception as e:
            logging.error(f"Failed to load private key: {e}")
            raise
    
    def _load_public_key(self):
        """Load public key from file."""
        try:
            with open(self.public_key_path, "rb") as f:
                return serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
        except FileNotFoundError:
            logging.error(f"Public key not found: {self.public_key_path}")
            raise
        except Exception as e:
            logging.error(f"Failed to load public key: {e}")
            raise
    
    def _hash_data(self, data: str) -> str:
        """Generate SHA-256 hash."""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _sign_data(self, data: str) -> str:
        """Generate RSA-SHA256 signature."""
        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()
    
    def log(self, trace_id: str, request: Dict, response: Dict, 
            image_audit: Optional[Dict] = None) -> Dict:
        """
        Create audit log entry with hash chain and signature.
        
        Args:
            trace_id: Unique trace identifier
            request: Request metadata (method, body_hash, pii_detection)
            response: Response metadata (status, content_hash, tokens)
            image_audit: Optional image audit metadata
            
        Returns:
            Complete audit log entry
        """
        # Build audit log
        audit_log = {
            "id": trace_id,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "request": request,
            "response": response
        }
        
        if image_audit:
            audit_log["image_audit"] = image_audit
        
        # Calculate log hash
        log_content = json.dumps(audit_log, sort_keys=True)
        log_hash = self._hash_data(log_content)
        
        # Create signature (log_hash + previous_hash)
        signature_data = f"{log_hash}:{self.previous_hash}"
        signature = self._sign_data(signature_data)
        
        # Add integrity section
        audit_log["integrity"] = {
            "log_hash": log_hash,
            "previous_hash": self.previous_hash,
            "signature": signature,
            "signature_algorithm": "RSA-SHA256"
        }
        
        # Update previous hash for next log
        self.previous_hash = log_hash
        
        return audit_log
    
    def verify_signature(self, audit_log: Dict) -> bool:
        """
        Verify audit log signature.
        
        Args:
            audit_log: Audit log entry to verify
            
        Returns:
            True if signature is valid
        """
        try:
            integrity = audit_log["integrity"]
            signature_data = f"{integrity['log_hash']}:{integrity['previous_hash']}"
            signature_bytes = bytes.fromhex(integrity["signature"])
            
            self.public_key.verify(
                signature_bytes,
                signature_data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"❌ Signature verification failed: {e}")
            return False

# Test
if __name__ == "__main__":
    logger = AuditLogger(key_dir="./keys")
    
    # Create test log
    log_entry = logger.log(
        trace_id="550e8400-e29b-41d4-a716-446655440000:2025-11-20T03:47:14Z",
        request={
            "method": "POST",
            "body_hash": "sha256:abc123...",
            "pii_detection": {"score": 0.3, "status": "PASS"}
        },
        response={
            "status": 200,
            "content_hash": "sha256:def456...",
            "tokens": 1500
        }
    )
    
    print("✅ Audit log created:")
    print(json.dumps(log_entry, indent=2))
    
    # Verify signature
    is_valid = logger.verify_signature(log_entry)
    print(f"\n✅ Signature valid: {is_valid}")
