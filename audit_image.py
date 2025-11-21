"""
Image Audit Module

Phase 2 Implementation:
- SHA-256 hashing
- AES-256-GCM encryption
- 7-day TTL automatic deletion
- Metadata-only logging

Phase 2 Limitations:
- Key management: Local keys (manual rotation)
- Image PII detection: Not implemented (OCR/EXIF not supported)
- Deletion audit trail: No signature verification

Phase 3a Improvements:
- Cloud KMS integration (CMEK, automatic rotation)
- Image DLP (OCR/EXIF PII detection, location removal)
- Deletion audit trail with cryptographic signature
"""

import hashlib
import os
import logging
from datetime import datetime, timedelta
from typing import Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp":"%(asctime)s","level":"%(levelname)s","module":"%(module)s","message":"%(message)s"}'
)

class ImageAuditor:
    def __init__(self, storage_dir: str = "./logs/images", key_dir: str = "./keys"):
        """
        Initialize image auditor.
        
        Args:
            storage_dir: Directory for encrypted images
            key_dir: Directory for encryption keys
        """
        self.storage_dir = storage_dir
        self.key_dir = key_dir
        os.makedirs(storage_dir, exist_ok=True)
        os.makedirs(key_dir, exist_ok=True)
        
        # Load or generate encryption key
        self.key_path = os.path.join(key_dir, "image_encryption_key.bin")
        try:
            if os.path.exists(self.key_path):
                with open(self.key_path, "rb") as f:
                    self.encryption_key = f.read()
            else:
                self.encryption_key = os.urandom(32)  # AES-256
                with open(self.key_path, "wb") as f:
                    f.write(self.encryption_key)
                logging.info(f"Generated encryption key: {self.key_path}")
                print(f"✅ Generated encryption key: {self.key_path}")
        except Exception as e:
            logging.error(f"Failed to load/generate encryption key: {e}")
            raise
    
    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _encrypt_file(self, file_path: str) -> bytes:
        """Encrypt file with AES-256-GCM."""
        try:
            # Read file
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Generate random IV (12 bytes for GCM)
            iv = os.urandom(12)
            
            # Encrypt
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Return: IV + Tag + Ciphertext
            return iv + encryptor.tag + ciphertext
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            raise
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            raise
    
    def audit_image(self, image_path: str, trace_id: str) -> Dict:
        """
        Audit image file: hash, encrypt, store, schedule deletion.
        
        Args:
            image_path: Path to image file
            trace_id: Associated trace_id for tracking
            
        Returns:
            Audit metadata (no image content)
        """
        # 1. SHA-256 hash
        image_hash = self._calculate_hash(image_path)
        
        # 2. AES-256-GCM encryption
        encrypted_data = self._encrypt_file(image_path)
        
        # 3. Storage path (organized by hash prefix)
        storage_filename = f"{image_hash}.enc"
        storage_path = os.path.join(self.storage_dir, image_hash[:8], storage_filename)
        os.makedirs(os.path.dirname(storage_path), exist_ok=True)
        
        # Save encrypted file
        with open(storage_path, 'wb') as f:
            f.write(encrypted_data)
        
        # 4. TTL (7 days)
        deletion_time = datetime.utcnow() + timedelta(days=7)
        
        # 5. Audit metadata
        metadata = {
            "image_hash": f"sha256:{image_hash}",
            "encryption_status": "AES-256-GCM",
            "storage_path": storage_path,
            "ttl": "7days",
            "deletion_scheduled": deletion_time.isoformat() + "Z",
            "key_management": "phase2_local_kms_pending",
            "trace_id": trace_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "limitations": "Key management: manual rotation, PII detection: not implemented"
        }
        
        return metadata
    
    def cleanup_expired(self):
        """Delete images past TTL (7 days)."""
        now = datetime.utcnow()
        deleted_count = 0
        
        for root, dirs, files in os.walk(self.storage_dir):
            for file in files:
                if file.endswith(".enc"):
                    file_path = os.path.join(root, file)
                    # Check file modification time
                    mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    age_days = (now - mtime).days
                    
                    if age_days >= 7:
                        os.remove(file_path)
                        deleted_count += 1
                        print(f"🗑️ Deleted expired image: {file_path}")
        
        return deleted_count

# Test
if __name__ == "__main__":
    auditor = ImageAuditor(storage_dir="./logs/images", key_dir="./keys")
    
    # Create test image file
    test_image_path = "test_image.png"
    with open(test_image_path, "wb") as f:
        f.write(b"Test image content")
    
    # Audit image
    metadata = auditor.audit_image(
        image_path=test_image_path,
        trace_id="550e8400-e29b-41d4-a716-446655440000:2025-11-20T03:47:14Z"
    )
    
    print("✅ Image audit metadata:")
    import json
    print(json.dumps(metadata, indent=2))
    
    # Cleanup test file
    os.remove(test_image_path)
