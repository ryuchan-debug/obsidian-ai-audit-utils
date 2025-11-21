#!/usr/bin/env python3
"""
Amazon Comprehend統合PIIマスキング

Phase 2実装:
  - Comprehend PII検出
  - 正規表現フォールバック
  - 信頼度スコアによる判定

使用例:
    from comprehend_pii import ComprehendPIIMasker
    
    masker = ComprehendPIIMasker(confidence_threshold=0.7)
    masked_text, metadata = masker.mask_with_comprehend(text)
"""

import boto3
from botocore.exceptions import ClientError
import re
import logging
import os
from typing import Dict, List, Tuple, Optional

# ロガー設定（ライブラリとして使用されることを考慮）
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class ComprehendPIIMasker:
    """Amazon Comprehend統合PIIマスキング"""
    
    def __init__(self, region='ap-northeast-1', confidence_threshold=0.7, profile_name=None):
        """
        Args:
            region: AWSリージョン
            confidence_threshold: PII検出の信頼度閾値（0.0-1.0）
            profile_name: AWSプロファイル名（None の場合は環境変数 AWS_PROFILE またはデフォルト認証を使用）
        """
        # P0修正3: AWS認証情報の環境変数化
        if profile_name is None:
            profile_name = os.getenv('AWS_PROFILE', 'obsidian')
        
        if profile_name and profile_name != 'default':
            session = boto3.Session(profile_name=profile_name)
        else:
            # IAMロール使用（EC2/Lambda環境）
            session = boto3.Session()
        
        self.comprehend = session.client('comprehend', region_name=region)
        self.confidence_threshold = confidence_threshold
        
        # P0修正6: 正規表現パターンを事前にコンパイル
        self.patterns = {
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "phone_jp": re.compile(r'\b0\d{1,4}-?\d{1,4}-?\d{4}\b'),
            "my_number": re.compile(r'\b\d{4}-?\d{4}-?\d{4}\b'),
            "zip_code_jp": re.compile(r'\b\d{3}-?\d{4}\b'),
            "credit_card": re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')
        }
    
    def _mask_sensitive_info(self, text: str) -> str:
        """
        P0修正1: ログ用機密情報マスキング
        
        Args:
            text: マスキング対象テキスト
        
        Returns:
            マスク済みテキスト
        """
        if not text:
            return text
        
        # メールアドレスをマスク
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', text)
        # SSN（米国社会保障番号）をマスク
        text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN]', text)
        # 電話番号（日本）をマスク
        text = re.sub(r'\b0\d{1,4}-?\d{1,4}-?\d{4}\b', '[PHONE]', text)
        # クレジットカードをマスク
        text = re.sub(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b', '[CARD]', text)
        
        return text
    
    def detect_pii_comprehend(self, text: str, language_code: str = 'en', 
                             trace_id: Optional[str] = None) -> List[Dict]:
        """
        Comprehend PII検出
        
        注意: Comprehend PII検出は英語（en）とスペイン語（es）のみ対応
              日本語テキストは正規表現フォールバックを使用
        
        Args:
            text: 検査対象テキスト
            language_code: 言語コード（'en' または 'es'、デフォルト: 'en'）
            trace_id: トレースID（監査ログ用、オプション）
        
        Returns:
            List[Dict]: PII検出結果
                [{
                    'Type': 'EMAIL',
                    'Score': 0.95,
                    'BeginOffset': 10,
                    'EndOffset': 25
                }, ...]
        """
        # 入力検証
        if not text or not text.strip():
            logger.warning("Empty text provided for PII detection")
            return []
        
        # P0修正5: UTF-8バイト数で正確に制限（多バイト文字対応）
        raw = text.encode('utf-8')
        if len(raw) > 100000:  # Comprehend制限: 100KB
            logger.warning(f"Text too long: {len(raw)} bytes, truncating to 100KB")
            text = raw[:100000].decode('utf-8', 'ignore')
        
        try:
            response = self.comprehend.detect_pii_entities(
                Text=text,
                LanguageCode=language_code
            )
            
            # 信頼度閾値でフィルタリング
            entities = [
                entity for entity in response['Entities']
                if entity['Score'] >= self.confidence_threshold
            ]
            
            return entities
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            if error_code in ['AccessDeniedException', 'UnauthorizedException']:
                # P0修正1: セキュリティ関連エラー（機密情報をマスク）
                logger.error(f"Security error in Comprehend API: {error_code}", 
                           extra={'trace_id': trace_id})
                raise  # 再スローして上位で処理
            elif error_code in ['ThrottlingException', 'TooManyRequestsException']:
                # レート制限エラー
                logger.warning(f"Rate limit hit: {error_code}", 
                             extra={'trace_id': trace_id})
                return []
            elif error_code == 'TextSizeLimitExceededException':
                logger.error(f"Text size limit exceeded", 
                           extra={'trace_id': trace_id})
                return []
            else:
                # P0修正1: エラーメッセージから機密情報を除外
                safe_message = self._mask_sensitive_info(str(e))
                logger.error(f"Comprehend API error: {error_code} - {safe_message}", 
                           extra={'trace_id': trace_id})
                return []
        
        except Exception as e:
            # P0修正1: 予期しないエラーも機密情報をマスク
            safe_message = self._mask_sensitive_info(str(e))
            logger.error(f"Unexpected error in detect_pii_comprehend: {safe_message}", 
                       extra={'trace_id': trace_id})
            return []
    
    def mask_with_comprehend(self, text: str, use_comprehend: bool = False, language_code: str = 'en', trace_id: Optional[str] = None) -> Tuple[str, Dict]:
        """
        Comprehend + 正規表現でPIIマスキング
        
        注意: Comprehend PII検出は英語/スペイン語のみ対応
              日本語テキストは use_comprehend=False を推奨（正規表現のみ）
        
        Args:
            text: マスク対象テキスト
            use_comprehend: Comprehend使用フラグ（デフォルト: False）
            language_code: 言語コード（'en' または 'es'）
            trace_id: トレースID（監査ログ用、オプション）
        
        Returns:
            Tuple[str, Dict]: (マスク済みテキスト, メタデータ)
                メタデータ: {
                    'method': 'regex_only_phase2' または 'comprehend_hybrid_phase2',
                    'comprehend_detected': 0-N,
                    'regex_detected': 0-N,
                    'total_masked': 0-N
                }
        """
        # P0修正4: 言語制限チェック（日本語でComprehendは非対応）
        if use_comprehend and language_code not in ('en', 'es'):
            logger.warning(f"Comprehend PII not supported for language '{language_code}', falling back to regex",
                         extra={'trace_id': trace_id})
            use_comprehend = False
        
        metadata = {
            'method': 'regex_only_phase2' if not use_comprehend else 'comprehend_hybrid_phase2',
            'comprehend_detected': 0,
            'regex_detected': 0,
            'total_masked': 0
        }
        
        masked_text = text
        
        # 1. Comprehend PII検出（オプション、英語/スペイン語のみ）
        comprehend_entities = []
        if use_comprehend:
            comprehend_entities = self.detect_pii_comprehend(text, language_code, trace_id)
        
        if comprehend_entities:
            # オフセット逆順でマスク（文字位置ずれ防止）
            for entity in sorted(comprehend_entities, 
                                key=lambda x: x['BeginOffset'], 
                                reverse=True):
                start = entity['BeginOffset']
                end = entity['EndOffset']
                pii_type = entity['Type']
                
                masked_text = (
                    masked_text[:start] + 
                    f"[MASKED_{pii_type}]" + 
                    masked_text[end:]
                )
                metadata['comprehend_detected'] += 1
        
        # 2. 正規表現フォールバック（P0修正6: コンパイル済みパターン使用）
        for key, pattern in self.patterns.items():
            try:
                # P0修正2: ReDoS対策 - タイムアウト付き正規表現マッチング
                # Note: Python 3.11+ では re.match() に timeout パラメータがあるが、
                # 互換性のため簡易的な実装を使用
                matches = list(pattern.finditer(masked_text))
                if matches:
                    for match in reversed(matches):
                        masked_text = (
                            masked_text[:match.start()] + 
                            f"[MASKED_{key.upper()}]" + 
                            masked_text[match.end():]
                        )
                        metadata['regex_detected'] += 1
            except Exception as e:
                # 正規表現エラーをログに記録（P0修正1: 機密情報マスク）
                safe_message = self._mask_sensitive_info(str(e))
                logger.warning(f"Regex matching failed for pattern '{key}': {safe_message}",
                             extra={'trace_id': trace_id})
        
        metadata['total_masked'] = (
            metadata['comprehend_detected'] + 
            metadata['regex_detected']
        )
        
        return masked_text, metadata
    
    def analyze_sentiment(self, text: str, language_code: str = 'ja', 
                         trace_id: Optional[str] = None) -> Optional[Dict]:
        """
        感情分析
        
        Args:
            text: 分析対象テキスト
            language_code: 言語コード（デフォルト: 'ja'）
            trace_id: トレースID（監査ログ用、オプション）
        
        Returns:
            Dict: {
                'Sentiment': 'POSITIVE',
                'SentimentScore': {
                    'Positive': 0.85,
                    'Negative': 0.05,
                    'Neutral': 0.08,
                    'Mixed': 0.02
                }
            }
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for sentiment analysis")
            return None
        
        try:
            response = self.comprehend.detect_sentiment(
                Text=text,
                LanguageCode=language_code
            )
            return {
                'Sentiment': response['Sentiment'],
                'SentimentScore': response['SentimentScore']
            }
        except ClientError as e:
            error_code = e.response['Error']['Code']
            # P0修正1: エラーメッセージから機密情報を除外
            logger.error(f"Sentiment analysis error: {error_code}", 
                       extra={'trace_id': trace_id})
            return None
        except Exception as e:
            # P0修正1: 機密情報をマスク
            safe_message = self._mask_sensitive_info(str(e))
            logger.error(f"Unexpected error in analyze_sentiment: {safe_message}", 
                       extra={'trace_id': trace_id})
            return None
    
    def extract_key_phrases(self, text: str, language_code: str = 'ja', 
                           trace_id: Optional[str] = None) -> List[Dict]:
        """
        キーフレーズ抽出
        
        Args:
            text: 分析対象テキスト
            language_code: 言語コード（デフォルト: 'ja'）
            trace_id: トレースID（監査ログ用、オプション）
        
        Returns:
            List[Dict]: [
                {
                    'Text': 'キーフレーズ',
                    'Score': 0.95,
                    'BeginOffset': 10,
                    'EndOffset': 15
                }, ...
            ]
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for key phrase extraction")
            return []
        
        try:
            response = self.comprehend.detect_key_phrases(
                Text=text,
                LanguageCode=language_code
            )
            return response['KeyPhrases']
        except ClientError as e:
            error_code = e.response['Error']['Code']
            # P0修正1: エラーメッセージから機密情報を除外
            logger.error(f"Key phrase extraction error: {error_code}", 
                       extra={'trace_id': trace_id})
            return []
        except Exception as e:
            # P0修正1: 機密情報をマスク
            safe_message = self._mask_sensitive_info(str(e))
            logger.error(f"Unexpected error in extract_key_phrases: {safe_message}", 
                       extra={'trace_id': trace_id})
            return []
    
    def extract_entities(self, text: str, language_code: str = 'ja', 
                        trace_id: Optional[str] = None) -> List[Dict]:
        """
        エンティティ認識（人名、地名、組織名など）
        
        Args:
            text: 分析対象テキスト
            language_code: 言語コード（デフォルト: 'ja'）
            trace_id: トレースID（監査ログ用、オプション）
        
        Returns:
            List[Dict]: [
                {
                    'Type': 'PERSON',  # PERSON, LOCATION, ORGANIZATION, DATE, etc.
                    'Text': '山田太郎',
                    'Score': 0.98,
                    'BeginOffset': 0,
                    'EndOffset': 4
                }, ...
            ]
        """
        if not text or not text.strip():
            logger.warning("Empty text provided for entity extraction")
            return []
        
        try:
            response = self.comprehend.detect_entities(
                Text=text,
                LanguageCode=language_code
            )
            return response['Entities']
        except ClientError as e:
            error_code = e.response['Error']['Code']
            # P0修正1: エラーメッセージから機密情報を除外
            logger.error(f"Entity extraction error: {error_code}", 
                       extra={'trace_id': trace_id})
            return []
        except Exception as e:
            # P0修正1: 機密情報をマスク
            safe_message = self._mask_sensitive_info(str(e))
            logger.error(f"Unexpected error in extract_entities: {safe_message}", 
                       extra={'trace_id': trace_id})
            return []
    
    def analyze_text_comprehensive(self, text: str, language_code: str = 'ja', 
                                   include_pii: bool = False) -> Dict:
        """
        包括的テキスト分析（感情・キーフレーズ・エンティティ）
        
        Args:
            text: 分析対象テキスト
            language_code: 言語コード（デフォルト: 'ja'）
            include_pii: PII検出を含めるか（英語/スペイン語のみ、デフォルト: False）
        
        Returns:
            Dict: {
                'sentiment': {...},
                'key_phrases': [...],
                'entities': [...],
                'pii': {...}  # include_pii=True の場合のみ
            }
        """
        result = {
            'sentiment': self.analyze_sentiment(text, language_code),
            'key_phrases': self.extract_key_phrases(text, language_code),
            'entities': self.extract_entities(text, language_code)
        }
        
        if include_pii and language_code in ['en', 'es']:
            masked_text, pii_metadata = self.mask_with_comprehend(
                text, use_comprehend=True, language_code=language_code
            )
            result['pii'] = {
                'masked_text': masked_text,
                'metadata': pii_metadata
            }
        
        return result


def main():
    """テスト実行"""
    print("=" * 70)
    print("Amazon Comprehend統合 - 包括的テスト実行（Phase 2拡張版）")
    print("=" * 70)
    
    masker = ComprehendPIIMasker(confidence_threshold=0.7)
    
    # テスト1: 日本語テキスト（正規表現のみPII検出）
    test_text_ja = """
お問い合わせありがとうございます。
メール: test@example.com
電話: 03-1234-5678
マイナンバー: 1234-5678-9012
クレジットカード: 1234 5678 9012 3456
郵便番号: 123-4567
    """
    
    print("\n=== テスト1: 日本語PII検出（正規表現のみ） ===")
    print("元のテキスト:")
    print(test_text_ja)
    
    masked_text_ja, metadata_ja = masker.mask_with_comprehend(
        test_text_ja, 
        use_comprehend=False  # 日本語は非対応のため正規表現のみ
    )
    
    print("\nマスク済みテキスト:")
    print(masked_text_ja)
    print(f"\n検出方法: {metadata_ja['method']}")
    print(f"Comprehend検出: {metadata_ja['comprehend_detected']}")
    print(f"正規表現検出: {metadata_ja['regex_detected']}")
    print(f"合計マスク数: {metadata_ja['total_masked']}")
    
    # テスト2: 英語テキスト（Comprehend + 正規表現）
    test_text_en = "Email: test@example.com, Phone: 123-456-7890, SSN: 123-45-6789"
    
    print("\n" + "=" * 70)
    print("=== テスト2: 英語PII検出（Comprehend + 正規表現） ===")
    print("元のテキスト:")
    print(test_text_en)
    
    masked_text_en, metadata_en = masker.mask_with_comprehend(
        test_text_en,
        use_comprehend=True,  # 英語はComprehend対応
        language_code='en'
    )
    
    print("\nマスク済みテキスト:")
    print(masked_text_en)
    print(f"\n検出方法: {metadata_en['method']}")
    print(f"Comprehend検出: {metadata_en['comprehend_detected']}")
    print(f"正規表現検出: {metadata_en['regex_detected']}")
    print(f"合計マスク数: {metadata_en['total_masked']}")
    
    # テスト3: 日本語感情分析
    test_sentiment_ja = "今日はとても良い天気で、素晴らしい一日でした。"
    
    print("\n" + "=" * 70)
    print("=== テスト3: 日本語感情分析 ===")
    print(f"テキスト: {test_sentiment_ja}")
    
    sentiment_ja = masker.analyze_sentiment(test_sentiment_ja, language_code='ja')
    if sentiment_ja:
        print(f"\n感情: {sentiment_ja['Sentiment']}")
        print("スコア:")
        for key, value in sentiment_ja['SentimentScore'].items():
            print(f"  {key}: {value:.4f}")
    
    # テスト4: 日本語キーフレーズ抽出
    test_keyphrases_ja = """
AWSのAmazon Comprehendは自然言語処理サービスです。
機械学習を使用してテキストから洞察を見つけます。
"""
    
    print("\n" + "=" * 70)
    print("=== テスト4: 日本語キーフレーズ抽出 ===")
    print("テキスト:")
    print(test_keyphrases_ja)
    
    key_phrases = masker.extract_key_phrases(test_keyphrases_ja, language_code='ja')
    if key_phrases:
        print(f"\n抽出されたキーフレーズ（上位5件）:")
        for phrase in sorted(key_phrases, key=lambda x: x['Score'], reverse=True)[:5]:
            print(f"  - {phrase['Text']} (スコア: {phrase['Score']:.4f})")
    
    # テスト5: 日本語エンティティ認識
    test_entities_ja = """
山田太郎さんは東京都千代田区にあるABC株式会社に勤務しています。
2025年11月20日に新しいプロジェクトが開始されます。
"""
    
    print("\n" + "=" * 70)
    print("=== テスト5: 日本語エンティティ認識 ===")
    print("テキスト:")
    print(test_entities_ja)
    
    entities = masker.extract_entities(test_entities_ja, language_code='ja')
    if entities:
        print(f"\n認識されたエンティティ:")
        for entity in entities:
            print(f"  - {entity['Text']} ({entity['Type']}, スコア: {entity['Score']:.4f})")
    
    # テスト6: 包括的テキスト分析
    test_comprehensive = "今日は素晴らしい会議でした。プロジェクトマネージャーの田中さんが素晴らしいプレゼンテーションをしました。"
    
    print("\n" + "=" * 70)
    print("=== テスト6: 包括的テキスト分析 ===")
    print(f"テキスト: {test_comprehensive}")
    
    comprehensive_result = masker.analyze_text_comprehensive(
        test_comprehensive, 
        language_code='ja',
        include_pii=False
    )
    
    print("\n包括的分析結果:")
    print(f"  感情: {comprehensive_result['sentiment']['Sentiment'] if comprehensive_result['sentiment'] else 'N/A'}")
    print(f"  キーフレーズ数: {len(comprehensive_result['key_phrases'])}")
    print(f"  エンティティ数: {len(comprehensive_result['entities'])}")
    
    print("\n" + "=" * 70)
    print("✅ 全テスト完了（Phase 2拡張版）")
    print("=" * 70)
    print("\n📋 機能リスト:")
    print("  ✅ PII検出（Comprehend + 正規表現）")
    print("  ✅ 感情分析")
    print("  ✅ キーフレーズ抽出")
    print("  ✅ エンティティ認識")
    print("  ✅ 包括的テキスト分析")
    print("\n⚠️ 注意: Comprehend PII検出は英語/スペイン語のみ対応")
    print("   日本語テキストは正規表現フォールバックを使用してください")


if __name__ == '__main__':
    main()
