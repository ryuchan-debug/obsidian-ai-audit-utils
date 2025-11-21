"""
PII Masking Module for Audit Logging

Phase 2 Minimum Implementation:
- Regex-based detection for common PII types
- Limitations: Cannot detect free-form text, images, or ambiguous expressions
- Detection method logged as: pii_detection.method = "regex_baseline_phase2"

Phase 3a Improvements:
- ML-assisted detection (AWS Comprehend, GCP DLP API)
- Deterministic tokenization with keyed hashing
- 3-tier disclosure levels (L1/L2/L3) with RBAC
"""

import re
from typing import Dict, List, Tuple

# PII Detection Patterns (Phase 2 - Improved)
PII_PATTERNS = {
    "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "phone_jp": r'\b0\d{1,4}-\d{1,4}-\d{4}\b',  # Japanese phone number (xxx-xxxx-xxxx)
    "phone_intl": r'\+81[-\s]?\d{1,4}[-\s]?\d{1,4}[-\s]?\d{4}\b',  # +81 format
    "my_number": r'\b\d{4}-\d{4}-\d{4}\b',  # Japanese My Number (xxxx-xxxx-xxxx)
    "zip_code_jp": r'\b\d{3}-\d{4}\b',  # Japanese postal code (xxx-xxxx)
    "credit_card": r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    "ipv4": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
}

def mask_pii(text: str) -> Tuple[str, Dict]:
    """
    Mask PII in text using regex patterns.
    
    Args:
        text: Input text to mask
        
    Returns:
        Tuple of (masked_text, detection_metadata)
    """
    try:
        masked_text = text
        detections = {}
        
        for key, pattern in PII_PATTERNS.items():
            matches = re.findall(pattern, text)
            if matches:
                detections[key] = len(matches)
                masked_text = re.sub(pattern, f"[MASKED_{key.upper()}]", masked_text)
        
        metadata = {
            "method": "regex_baseline_phase2_improved",
            "detections": detections,
            "total_masked": sum(detections.values()),
            "improvements": "Added: phone_jp, phone_intl, my_number, zip_code_jp",
            "limitations": "Cannot detect free-form text, images, or ambiguous expressions"
        }
        
        return masked_text, metadata
    except re.error as e:
        print(f"❌ Regex error: {e}")
        return text, {"error": str(e), "method": "failed"}
    except Exception as e:
        print(f"❌ Masking failed: {e}")
        return text, {"error": str(e), "method": "failed"}

def calculate_pii_score(text: str) -> float:
    """
    Calculate PII risk score (0.0 - 1.0).
    
    Higher score = more PII detected.
    Used for Perplexity safety checks.
    """
    total_chars = len(text)
    if total_chars == 0:
        return 0.0
    
    pii_chars = 0
    for pattern in PII_PATTERNS.values():
        matches = re.findall(pattern, text)
        for match in matches:
            pii_chars += len(match)
    
    score = min(pii_chars / total_chars, 1.0)
    return round(score, 2)

# Test
if __name__ == "__main__":
    test_text = "Email: test@example.com, Phone: 090-1234-5678, SSN: 123-4567-8901"
    masked, metadata = mask_pii(test_text)
    print("Original:", test_text)
    print("Masked:", masked)
    print("Metadata:", metadata)
    print("PII Score:", calculate_pii_score(test_text))
