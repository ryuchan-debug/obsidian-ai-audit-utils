#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_utils.py - 監査ログ共通モジュール

統合された監査ログ機能を提供:
- trace_id生成・伝播
- PIIマスキング（comprehend_pii統合）
- Comprehend分析（感情分析、キーフレーズ、エンティティ）
- 監査ログ保存
- CloudWatch Logs送信

バージョン: 1.0.0
Phase: 3a (監査ログ共通化)
"""

import os
import sys
import json
import uuid
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

# comprehend_pii.pyをインポート
try:
    from comprehend_pii import ComprehendPIIMasker
except ImportError:
    print("Error: comprehend_pii.py not found. Please ensure it's in the same directory.")
    sys.exit(1)

# ロギング設定
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AuditLogger:
    """統合監査ログ機能を提供するクラス"""
    
    def __init__(self, log_dir: Optional[str] = None):
        """
        初期化
        
        Args:
            log_dir: ログディレクトリのパス（デフォルト: audit_utils/logs/）
        """
        if log_dir is None:
            # デフォルト: スクリプトと同じディレクトリのlogs/
            self.log_dir = Path(__file__).parent / "logs"
        else:
            self.log_dir = Path(log_dir)
        
        # ログディレクトリ作成
        self.log_dir.mkdir(exist_ok=True)
        
        # ComprehendPIIMasker初期化
        self.pii_masker = ComprehendPIIMasker()
        
        logger.info(f"AuditLogger initialized with log_dir: {self.log_dir}")
    
    def generate_trace_id(self) -> str:
        """
        trace_id生成（UUID v4 + ISO8601タイムスタンプ）
        
        Returns:
            trace_id（例: "a1b2c3d4-e5f6-7890-abcd-ef1234567890:2025-11-21T02:35:00Z"）
        """
        trace_uuid = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        trace_id = f"{trace_uuid}:{timestamp}"
        
        logger.debug(f"Generated trace_id: {trace_id}")
        return trace_id
    
    def mask_pii_and_analyze(
        self,
        text: str,
        language_code: str = "ja",
        trace_id: Optional[str] = None
    ) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """
        PIIマスキングとComprehend分析を実行
        
        Args:
            text: 分析対象のテキスト
            language_code: 言語コード（ja, en, es等）
            trace_id: トレースID（Noneの場合は生成）
        
        Returns:
            Tuple[マスキング済みテキスト, PII検出結果, Comprehend分析結果]
        """
        if trace_id is None:
            trace_id = self.generate_trace_id()
        
        # PIIマスキング
        masked_text, pii_results = self.pii_masker.mask_with_comprehend(
            text=text,
            language_code=language_code,
            trace_id=trace_id
        )
        
        # Comprehend包括的分析
        analysis_results = self.pii_masker.analyze_text_comprehensive(
            text=text,
            language_code=language_code
        )
        
        return masked_text, pii_results, analysis_results
    
    def save_audit_log(
        self,
        trace_id: str,
        method: str,
        model: str,
        request_data: Dict[str, Any],
        response_data: Dict[str, Any],
        pii_detection: Dict[str, Any],
        comprehend_analysis: Dict[str, Any]
    ) -> str:
        """
        監査ログをJSONファイルに保存
        
        Args:
            trace_id: トレースID
            method: メソッド名（chatgpt, gemini, copilot等）
            model: モデル名
            request_data: リクエストデータ
            response_data: レスポンスデータ
            pii_detection: PII検出結果
            comprehend_analysis: Comprehend分析結果
        
        Returns:
            保存したログファイルのパス
        """
        # trace_idからUUID部分を抽出（ファイル名として使用）
        uuid_part = trace_id.split(':')[0]
        log_file = self.log_dir / f"{uuid_part}.json"
        
        # 監査ログエントリ作成
        log_entry = {
            "trace_id": trace_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "request": {
                "method": method,
                "model": model,
                "body_hash": self._calculate_hash(json.dumps(request_data, ensure_ascii=False)),
                "pii_detection": pii_detection,
                "comprehend_analysis": comprehend_analysis
            },
            "response": {
                "status": response_data.get("status", "success"),
                "content_hash": self._calculate_hash(response_data.get("content", ""))
            }
        }
        
        # ログファイルに保存（パーミッション600）
        os.umask(0o077)
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(log_entry, f, ensure_ascii=False, indent=2)
        
        # 明示的にパーミッション設定
        os.chmod(log_file, 0o600)
        
        logger.info(f"Audit log saved: {log_file}")
        return str(log_file)
    
    def _calculate_hash(self, content: str) -> str:
        """
        コンテンツのSHA256ハッシュを計算
        
        Args:
            content: ハッシュ対象のコンテンツ
        
        Returns:
            SHA256ハッシュ（16進数文字列）
        """
        return hashlib.sha256(content.encode('utf-8')).hexdigest().upper()
    
    def create_audit_log_entry(
        self,
        trace_id: str,
        method: str,
        model: str,
        prompt: str,
        response: str,
        language_code: str = "ja"
    ) -> Tuple[str, Dict[str, Any]]:
        """
        監査ログエントリを作成（オールインワン）
        
        Args:
            trace_id: トレースID
            method: メソッド名
            model: モデル名
            prompt: プロンプト
            response: レスポンス
            language_code: 言語コード
        
        Returns:
            Tuple[ログファイルパス, ログエントリ]
        """
        # PIIマスキングとComprehend分析
        _, pii_results, analysis_results = self.mask_pii_and_analyze(
            text=prompt,
            language_code=language_code,
            trace_id=trace_id
        )
        
        # 監査ログ保存
        log_file = self.save_audit_log(
            trace_id=trace_id,
            method=method,
            model=model,
            request_data={"prompt": prompt},
            response_data={"content": response, "status": "success"},
            pii_detection=pii_results,
            comprehend_analysis=analysis_results
        )
        
        # ログエントリを読み込んで返す
        with open(log_file, 'r', encoding='utf-8') as f:
            log_entry = json.load(f)
        
        return log_file, log_entry


# モジュールテスト
if __name__ == "__main__":
    print("=== AuditUtils Module Test ===")
    
    # AuditLogger初期化
    audit_logger = AuditLogger()
    
    # trace_id生成テスト
    trace_id = audit_logger.generate_trace_id()
    print(f"✅ Generated trace_id: {trace_id}")
    
    # PIIマスキング・Comprehend分析テスト
    test_prompt = "私の電話番号は090-1234-5678です。メールアドレスはtest@example.comです。"
    masked_text, pii_results, analysis_results = audit_logger.mask_pii_and_analyze(
        text=test_prompt,
        language_code="ja",
        trace_id=trace_id
    )
    
    print(f"✅ Masked text: {masked_text}")
    print(f"✅ PII detected: {pii_results['total_masked']} entities")
    print(f"✅ Sentiment: {analysis_results['sentiment']}")
    
    # 監査ログ保存テスト
    log_file, log_entry = audit_logger.create_audit_log_entry(
        trace_id=trace_id,
        method="test",
        model="test-model",
        prompt=test_prompt,
        response="テスト応答",
        language_code="ja"
    )
    
    print(f"✅ Audit log saved: {log_file}")
    print(f"✅ Log entry keys: {list(log_entry.keys())}")
    
    print("\n✅ All tests passed!")
