# ========== COPILOT CLI AUDIT WRAPPER ==========
# Copilot CLI の監査ログ・感情分析・キーフレーズ抽出を自動記録
# 
# 機能:
#   - trace_id生成・伝播
#   - PIIマスキング（正規表現ベース）
#   - AWS Comprehend分析（感情分析、キーフレーズ抽出、エンティティ認識）
#   - 監査ログ保存（JSON形式、CloudWatch Logs統合）
#   - 透過的なCopilot CLI実行（すべての引数を透過）
# 
# 使用方法:
#   copilot-audit                              # 対話モード
#   copilot-audit -p "質問"                    # ワンショットモード
#   copilot-audit --model gpt-5 -p "質問"      # モデル指定
# 
# 前提条件:
#   - Copilot CLI インストール済み
#   - audit_utils（PIIマスキング、Comprehend統合）
#   - Python 3.x + boto3 + comprehend_pii.py
# 
# バージョン: 1.0.0 (2025-11-20)
# GitHub: https://github.com/ryuchan-debug/obsidian-ai-scripts
# ================================================

# すべての引数を$argsで受け取る（PowerShellのパラメータ衝突を回避）

# --- 設定 ---
$auditUtilsPath = "C:\Users\kasab\scripts\audit_utils"
$logDir = Join-Path $auditUtilsPath "logs"

# --- trace_id生成 ---
$traceId = $null
if (Test-Path "$auditUtilsPath\Generate-TraceId.ps1") {
    $traceId = & "$auditUtilsPath\Generate-TraceId.ps1"
}

# --- モデル名を検出 ---
$model = "claude-sonnet-4.5"  # デフォルト
$modelIndex = [array]::IndexOf($args, "--model")
if ($modelIndex -ge 0 -and $modelIndex + 1 -lt $args.Count) {
    $model = $args[$modelIndex + 1]
}

# --- プロンプトを検出（-p オプション） ---
$prompt = ""
$promptIndex = [array]::IndexOf($args, "-p")
if ($promptIndex -ge 0 -and $promptIndex + 1 -lt $args.Count) {
    $prompt = $args[$promptIndex + 1]
}

# --- 監査ログ処理（ワンショットモードのみ） ---
$auditResult = $null
if ($prompt -and $traceId) {
    try {
        Write-Host "🔍 Analyzing prompt with Comprehend..." -ForegroundColor Cyan
        
        # 一時ファイルに保存
        $tempDir = Join-Path $env:TEMP "copilot_audit"
        if (-not (Test-Path $tempDir)) {
            New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        }
        
        $uuid = $traceId.Split(':')[0]
        $tempPromptFile = Join-Path $tempDir "prompt_$uuid.txt"
        $tempAuditScript = Join-Path $tempDir "audit_script_$uuid.py"
        
        # プロンプトをUTF-8で保存
        $prompt | Set-Content -Path $tempPromptFile -Encoding UTF8 -NoNewline
        
        # Pythonスクリプトを作成
        $auditScriptContent = @"
import sys
sys.path.append('$($auditUtilsPath.Replace('\', '\\'))')
from comprehend_pii import ComprehendPIIMasker
import json

masker = ComprehendPIIMasker()

# UTF-8でプロンプトを読み込み
with open('$($tempPromptFile.Replace('\', '\\'))', 'r', encoding='utf-8') as f:
    prompt = f.read()

# PIIマスキング
masked_prompt, pii_metadata = masker.mask_with_comprehend(
    prompt,
    use_comprehend=False,
    language_code='ja',
    trace_id='$traceId'
)

# 包括的分析
analysis = masker.analyze_text_comprehensive(
    prompt,
    language_code='ja',
    include_pii=False
)

result = {
    'masked_prompt': masked_prompt,
    'pii_metadata': pii_metadata,
    'sentiment': analysis['sentiment']['Sentiment'] if analysis['sentiment'] else None,
    'sentiment_score': analysis['sentiment']['SentimentScore'] if analysis['sentiment'] else None,
    'key_phrases_count': len(analysis['key_phrases']),
    'entities_count': len(analysis['entities']),
    'top_key_phrases': [kp['Text'] for kp in sorted(analysis['key_phrases'], key=lambda x: x['Score'], reverse=True)[:5]],
    'entities': [{'text': e['Text'], 'type': e['Type'], 'score': e['Score']} for e in analysis['entities']]
}
print(json.dumps(result, ensure_ascii=False))
"@
        
        $auditScriptContent | Set-Content -Path $tempAuditScript -Encoding UTF8
        
        # Pythonスクリプトを実行
        $auditResultJson = py $tempAuditScript 2>&1
        if ($LASTEXITCODE -eq 0) {
            $auditResult = $auditResultJson | ConvertFrom-Json
            Write-Host "✅ Comprehend analysis completed" -ForegroundColor Green
            
            if ($auditResult.pii_metadata.total_masked -gt 0) {
                Write-Host "⚠️  Warning: $($auditResult.pii_metadata.total_masked) PII item(s) detected and masked." -ForegroundColor Yellow
            }
        } else {
            Write-Host "⚠️  Warning: Comprehend analysis failed: $auditResultJson" -ForegroundColor Yellow
        }
        
        # 一時ファイル削除
        Remove-Item $tempPromptFile -Force -ErrorAction SilentlyContinue
        Remove-Item $tempAuditScript -Force -ErrorAction SilentlyContinue
        
    } catch {
        Write-Host "⚠️  Warning: Audit processing failed: $_" -ForegroundColor Yellow
    }
}

# --- Copilot CLI実行 ---
Write-Host ""
Write-Host "🤖 Starting Copilot CLI ($model)..." -ForegroundColor Green
Write-Host ""

try {
    # UTF-8エンコーディング設定
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    
    # Copilot CLIのパスを取得（.cmd版を優先）
    $copilotCmd = Get-Command copilot.cmd -CommandType Application -ErrorAction SilentlyContinue
    if (-not $copilotCmd) {
        $copilotCmd = Get-Command copilot -CommandType Application -ErrorAction SilentlyContinue
    }
    if (-not $copilotCmd) {
        throw "Copilot CLI not found. Please install it first."
    }
    
    # ワンショットモードの場合は応答をキャプチャ
    if ($prompt -and $traceId) {
        # 応答をキャプチャ
        $response = & $copilotCmd.Source @args | Out-String
        Write-Host $response
        
        # 監査ログ保存
        if ($auditResult) {
            try {
                $logEntry = @{
                    trace_id = $traceId
                    timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    request = @{
                        method = "copilot"
                        model = $model
                        body_hash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($prompt))) -Algorithm SHA256).Hash
                        pii_detection = $auditResult.pii_metadata
                        comprehend_analysis = @{
                            sentiment = $auditResult.sentiment
                            sentiment_score = $auditResult.sentiment_score
                            key_phrases_count = $auditResult.key_phrases_count
                            entities_count = $auditResult.entities_count
                            top_key_phrases = $auditResult.top_key_phrases
                            entities = $auditResult.entities
                        }
                    }
                    response = @{
                        status = "success"
                        content_hash = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($response))) -Algorithm SHA256).Hash
                    }
                } | ConvertTo-Json -Depth 10
                
                if (-not (Test-Path $logDir)) {
                    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
                }
                $logFile = Join-Path $logDir "$($traceId.Split(':')[0]).json"
                $logEntry | Out-File -FilePath $logFile -Encoding UTF8
                Write-Host ""
                Write-Host "✅ Audit log saved: $logFile" -ForegroundColor Green
                
                # CloudWatch Logsに送信
                try {
                    $sendAuditLogScript = Join-Path $auditUtilsPath "Send-AuditLog.ps1"
                    if (Test-Path $sendAuditLogScript) {
                        & $sendAuditLogScript -LogEntry $logEntry -ErrorAction Stop
                    } else {
                        Write-Host "⚠️  Warning: Send-AuditLog.ps1 not found, skipping CloudWatch Logs upload" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "⚠️  Warning: Failed to send to CloudWatch Logs: $_" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "⚠️  Warning: Failed to save audit log: $_" -ForegroundColor Yellow
            }
        }
    } else {
        # 対話モードまたはプロンプトなし：透過的に実行
        & $copilotCmd.Source @args
    }
    
} catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
    exit 1
}
