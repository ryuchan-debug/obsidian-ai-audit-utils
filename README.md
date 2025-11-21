# Audit Utils - Phase 2 Monitoring Infrastructure (Extended)

**Version**: 2.0.0 (Phase 2 Extended)  
**Status**: Production Ready (with limitations)  
**GitHub**: https://github.com/ryuchan-debug/obsidian-ai-scripts/tree/main/audit_utils

---

## 📋 Overview

Phase 2 Extended monitoring infrastructure for AI script auditing:
- **trace_id generation**: UUID v4 + ISO8601 timestamp
- **PII masking**: Amazon Comprehend + Regex-based fallback
- **Sentiment analysis**: POSITIVE/NEGATIVE/NEUTRAL/MIXED detection
- **Key phrase extraction**: Automatic keyword extraction with scores
- **Entity recognition**: Person, Location, Organization, Date extraction
- **Audit logging**: Hash chain + RSA-SHA256 signature
- **Image auditing**: AES-256-GCM encryption, 7-day TTL
- **CloudWatch integration**: Centralized log monitoring

---

## 🚀 Setup

### 1. Install Dependencies

```powershell
pip install cryptography boto3
```

### 2. Generate Keys (First Time Only)

```powershell
cd C:\Users\kasab\scripts\audit_utils
python audit_logger.py  # Auto-generates RSA keys in ./keys/
python audit_image.py   # Auto-generates AES key in ./keys/
```

**Security Note**: Keys are stored in `./keys/` directory. **DO NOT** commit to Git.

### 3. Configure AWS (Optional - for CloudWatch)

```powershell
aws configure --profile obsidian
# Region: ap-northeast-1
```

### 4. Add to PATH (Optional)

```powershell
$env:PATH += ";C:\Users\kasab\scripts\audit_utils"
# Add to PowerShell profile for persistence:
# echo '$env:PATH += ";C:\Users\kasab\scripts\audit_utils"' >> $PROFILE
```

---

## ⚠️ Known Limitations

### PII Masking (Regex-Based)

**Phase 2 Limitations:**
- **My Number**: No check digit validation (false positive possible)
- **Credit Card**: No Luhn algorithm validation (false positive possible)
- **Zip Code (Japan)**: May detect other number formats (false positive possible)
- **Free-form text**: Cannot detect PII in natural language descriptions
- **Image PII**: OCR/EXIF metadata not processed

**Mitigation:**
- All limitations are logged in audit metadata: `pii_detection.method = "regex_baseline_phase2"`
- Phase 3a will implement deterministic tokenization with ML-assisted detection

### Amazon Comprehend Integration (Phase 2 Extended)

**Supported Features:**
1. **PII Detection** (English/Spanish only)
2. **Sentiment Analysis** (Japanese/English/Spanish)
3. **Key Phrase Extraction** (Japanese/English/Spanish)
4. **Entity Recognition** (Japanese/English/Spanish)

**Language Support:**
- ✅ English (en): All features supported
- ✅ Spanish (es): All features supported
- ⚠️ Japanese (ja): Sentiment/KeyPhrase/Entity only (PII detection uses regex fallback)

**Usage:**

```python
from comprehend_pii import ComprehendPIIMasker

masker = ComprehendPIIMasker()

# 1. PII Detection
# Japanese (regex only)
masked_ja, meta_ja = masker.mask_with_comprehend(
    "メール: test@example.com",
    use_comprehend=False  # Japanese not supported
)

# English (Comprehend + regex)
masked_en, meta_en = masker.mask_with_comprehend(
    "Email: test@example.com",
    use_comprehend=True,
    language_code='en'
)

# 2. Sentiment Analysis
sentiment = masker.analyze_sentiment(
    "今日はとても良い天気で、素晴らしい一日でした。",
    language_code='ja'
)
print(sentiment['Sentiment'])  # POSITIVE
print(sentiment['SentimentScore'])  # {'Positive': 0.9998, ...}

# 3. Key Phrase Extraction
key_phrases = masker.extract_key_phrases(
    "AWSのAmazon Comprehendは自然言語処理サービスです。",
    language_code='ja'
)
for phrase in key_phrases:
    print(f"{phrase['Text']} (score: {phrase['Score']})")

# 4. Entity Recognition
entities = masker.extract_entities(
    "山田太郎さんは東京都にあるABC株式会社に勤務しています。",
    language_code='ja'
)
for entity in entities:
    print(f"{entity['Text']} ({entity['Type']})")  # PERSON, LOCATION, ORGANIZATION

# 5. Comprehensive Analysis
result = masker.analyze_text_comprehensive(
    "今日は素晴らしい会議でした。",
    language_code='ja'
)
print(result['sentiment'])      # 感情分析結果
print(result['key_phrases'])    # キーフレーズリスト
print(result['entities'])       # エンティティリスト
```

**Free Tier:**
- 50,000 units/month (12 months)
- ~10,000 API calls/month for 500-character texts
- Default `use_comprehend=False` to conserve quota

**Error Handling:**
- ClientError with detailed logging (AccessDenied, Throttling, etc.)
- Input validation (empty text, size limits)
- Graceful fallback to regex-only mode on API failures

---

## 📖 Usage

### Generate trace_id

```powershell
$traceId = .\Generate-TraceId.ps1
Write-Host "Generated: $traceId"
# Output: 550e8400-e29b-41d4-a716-446655440000:2025-11-20T03:47:14Z
```

### Mask PII

```python
from mask_pii import mask_pii

text = "Contact: test@example.com, Phone: 090-1234-5678, My Number: 1234-5678-9012"
masked_text, metadata = mask_pii(text)
print(masked_text)
# Output: Contact: [MASKED_EMAIL], Phone: [MASKED_PHONE_JP], My Number: [MASKED_MY_NUMBER]
```

### Create Audit Log

```python
from audit_logger import AuditLogger
import hashlib

logger = AuditLogger(key_dir="./keys")

log_entry = logger.log(
    trace_id="550e8400-e29b-41d4-a716-446655440000:2025-11-20T03:47:14Z",
    request={
        "method": "POST",
        "body_hash": hashlib.sha256(b"request body").hexdigest(),
        "pii_detection": {"score": 0.3, "status": "PASS"}
    },
    response={
        "status": 200,
        "content_hash": hashlib.sha256(b"response body").hexdigest(),
        "tokens": 1500
    }
)

print(log_entry)
```

### Audit Image

```python
from audit_image import ImageAuditor

auditor = ImageAuditor(storage_dir="./logs/images", key_dir="./keys")
metadata = auditor.audit_image(
    image_path="photo.png",
    trace_id="550e8400-e29b-41d4-a716-446655440000:2025-11-20T03:47:14Z"
)
print(metadata)
```

### Send to CloudWatch Logs

```powershell
$logEntry = Get-Content audit_log.json -Raw
.\Send-AuditLog.ps1 -LogEntry $logEntry
```

---

## 🔗 Integration with Existing Scripts

### chatgpt.py Integration

```python
# Add to chatgpt.py
import sys
sys.path.append("C:\\Users\\kasab\\scripts\\audit_utils")

from audit_logger import AuditLogger
from mask_pii import mask_pii

# In main():
logger = AuditLogger(key_dir="C:\\Users\\kasab\\scripts\\audit_utils\\keys")

# Before API call:
masked_prompt, pii_meta = mask_pii(user_prompt)

# After API call:
log_entry = logger.log(
    trace_id=generate_trace_id(),
    request={"prompt": masked_prompt, "pii_detection": pii_meta},
    response={"content": response.choices[0].message.content}
)
```

### sgemini.ps1 Integration

```powershell
# Add to sgemini.ps1
$traceId = & "C:\Users\kasab\scripts\audit_utils\Generate-TraceId.ps1"

# After API call:
$logEntry = @{
    id = $traceId
    request = @{ prompt = $maskedPrompt }
    response = @{ content = $response }
} | ConvertTo-Json

& "C:\Users\kasab\scripts\audit_utils\Send-AuditLog.ps1" -LogEntry $logEntry
```

---

## 🧪 Testing

### Run Integration Tests

```powershell
cd C:\Users\kasab\scripts\audit_utils
python test_audit_system.py
```

**Expected Output:**

```
=== Test 1: trace_id Generation ===
✅ Generated trace_id: 550e8400-e29b-41d4-a716-446655440000:2025-11-20T03:47:14Z

=== Test 2: PII Masking ===
✅ Masked: Contact: [MASKED_EMAIL], Phone: [MASKED_PHONE_JP]

=== Test 3: Audit Logging ===
✅ Audit log created
✅ Signature verification: True

=== Test 4: Image Auditing ===
✅ Image audit metadata: {"encryption_status": "AES-256-GCM", ...}

=== Test 5: CloudWatch Logs Integration ===
✅ Log sent to CloudWatch Logs (or ⚠️ if AWS not configured)

============================================================
✅ All tests passed!
============================================================
```

---

## 🔒 Security Considerations

### Phase 2 Limitations

1. **Key Management**: Local keys with no automatic rotation
2. **PII Detection**: Regex-based (cannot detect free-form text, images)
3. **Deletion Audit**: No cryptographic signature verification

### Phase 3a Planned Improvements

- AWS KMS integration for key management
- ML-assisted PII detection (AWS Comprehend, GCP DLP API)
- Image DLP (OCR/EXIF PII detection)
- Deletion audit trail with signature

### Best Practices

- **DO NOT** commit `keys/` or `logs/` to Git
- Rotate keys every 90 days (manual process in Phase 2)
- Review PII masking regularly (false positives/negatives)
- Monitor CloudWatch Logs for anomalies

---

## 📚 File Structure

```
audit_utils/
├── Generate-TraceId.ps1      # trace_id generation
├── mask_pii.py                # PII masking
├── audit_logger.py            # Audit logging with hash chain
├── audit_image.py             # Image encryption and auditing
├── Send-AuditLog.ps1          # CloudWatch Logs integration
├── test_audit_system.py       # Integration tests
├── .gitignore                 # Exclude keys and logs
├── README.md                  # This file
├── keys/                      # RSA/AES keys (NOT in Git)
│   ├── audit_private_key.pem
│   ├── audit_public_key.pem
│   └── image_encryption_key.bin
└── logs/                      # Encrypted images (NOT in Git)
    └── images/
```

---

## 🛠️ Troubleshooting

### Error: "Private key not found"

**Cause**: Keys not generated yet.

**Solution**:
```powershell
python audit_logger.py  # Auto-generates keys
```

### Error: "ModuleNotFoundError: No module named 'cryptography'"

**Cause**: Dependencies not installed.

**Solution**:
```powershell
pip install cryptography
```

### Error: "AWS credentials not configured"

**Cause**: CloudWatch integration requires AWS CLI setup.

**Solution**:
```powershell
aws configure --profile obsidian
```

Or skip CloudWatch (logs will be local only).

---

## 📝 Version History

- **1.0.0** (2025-11-20): Initial release
  - Phase 2 minimum implementation
  - Multi-AI code review completed
  - Security fixes: Keys removed from Git, error handling added
  - PII masking improved: Added phone_jp, my_number, zip_code_jp

---

## 📞 Support

- **GitHub Issues**: https://github.com/ryuchan-debug/obsidian-ai-scripts/issues
- **Documentation**: `.copilot\_CopilotWork\` directory
- **Related Docs**:
  - [タスク3_監査要件定義_最終まとめ.md](../../ObsidianVault/.copilot/_CopilotWork/タスク3_監査要件定義_最終まとめ.md)
  - [タスク4_コードレビュー結果.md](../../ObsidianVault/.copilot/_CopilotWork/タスク4_コードレビュー結果.md)

---

**Author**: Multi-AI Team (Claude Haiku 4.5, GPT-5, Gemini 2.0 Flash)  
**License**: MIT  
**Last Updated**: 2025-11-20
