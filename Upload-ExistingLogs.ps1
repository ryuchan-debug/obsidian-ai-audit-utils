# ========== UPLOAD EXISTING LOGS TO CLOUDWATCH ==========
# ローカルに保存された監査ログをCloudWatch Logsにアップロード
# 
# 機能:
#   - logs/ディレクトリ内のすべての.jsonファイルをスキャン
#   - CloudWatch Logsに未送信のログを送信
#   - 送信済みログをprocessedディレクトリに移動（冪等性確保）
#   - 古いログのクリーンアップ（7日保持）
#   - 進捗表示・エラーハンドリング
# 
# 使用方法:
#   .\Upload-ExistingLogs.ps1 [-DryRun]
# 
# パラメータ:
#   -DryRun: ドライランモード（削除せず、削除対象を表示）
# 
# 前提条件:
#   - Send-AuditLog.ps1
#   - Python 3.x + boto3
#   - AWS Profile: obsidian
# 
# バージョン: 2.0.0 (2025-11-21)
# Phase: 3a (P0/P1修正完了版)
# =======================================================

param(
    [switch]$DryRun  # ドライランモード
)

$ErrorActionPreference = "Continue"

# --- 設定 ---
# P0修正: $PSScriptRoot基準の相対パス化（ハードコード削除）
$auditUtilsPath = $PSScriptRoot
$logDir = Join-Path $auditUtilsPath "logs"
$processedDir = Join-Path $logDir "processed"
$sendAuditLogScript = Join-Path $auditUtilsPath "Send-AuditLog.ps1"

# P1設定: ログ保持期間（7日）
$retentionDays = 7

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Uploading Existing Audit Logs to CloudWatch" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "(DRY RUN MODE - No files will be deleted)" -ForegroundColor Yellow
}
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# --- Send-AuditLog.ps1存在確認 ---
if (-not (Test-Path $sendAuditLogScript)) {
    Write-Host "❌ Error: Send-AuditLog.ps1 not found at $sendAuditLogScript" -ForegroundColor Red
    exit 1
}

# --- ログディレクトリ確認 ---
if (-not (Test-Path $logDir)) {
    Write-Host "⚠️  Warning: Log directory not found: $logDir" -ForegroundColor Yellow
    exit 0
}

# --- processedディレクトリ作成 ---
# P0修正: 冪等性確保（送信済みログを移動）
if (-not (Test-Path $processedDir)) {
    New-Item -ItemType Directory -Path $processedDir | Out-Null
    Write-Host "📁 Created processed directory: $processedDir" -ForegroundColor Green
}

# --- ログファイル取得 ---
$logFiles = Get-ChildItem -Path $logDir -Filter "*.json" | Sort-Object LastWriteTime

if ($logFiles.Count -eq 0) {
    Write-Host "ℹ️  No log files found in $logDir" -ForegroundColor Yellow
    exit 0
}

Write-Host "📁 Found $($logFiles.Count) log file(s)" -ForegroundColor Green
Write-Host ""

# --- アップロード処理 ---
$successCount = 0
$failCount = 0
$skipCount = 0

foreach ($logFile in $logFiles) {
    # P1修正: エクスポネンシャルバックオフ実装
    $maxRetries = 3
    $retryCount = 0
    $success = $false
    
    Write-Host "📄 Processing: $($logFile.Name)..." -NoNewline
    
    while (-not $success -and $retryCount -lt $maxRetries) {
        try {
            # ログファイル読み込み
            $logEntry = Get-Content -Path $logFile.FullName -Raw -Encoding UTF8
            
            # CloudWatch Logsに送信
            & $sendAuditLogScript -LogEntry $logEntry -ErrorAction Stop | Out-Null
            
            # P0修正: アップロード成功時にprocessedディレクトリに移動
            $processedPath = Join-Path $processedDir $logFile.Name
            Move-Item -Path $logFile.FullName -Destination $processedPath -Force
            
            Write-Host " ✅ Success (moved to processed)" -ForegroundColor Green
            $successCount++
            $success = $true
            
        } catch {
            $retryCount++
            
            # P1修正: ThrottlingException対応
            if ($_.Exception.Message -match "ThrottlingException|Rate exceeded|TooManyRequestsException") {
                if ($retryCount -lt $maxRetries) {
                    $waitTime = [Math]::Pow(2, $retryCount) * 1000  # エクスポネンシャルバックオフ
                    Write-Host " ⚠️  Rate limit exceeded, retrying in $($waitTime)ms..." -ForegroundColor Yellow
                    Start-Sleep -Milliseconds $waitTime
                } else {
                    Write-Host " ❌ Failed after $maxRetries retries: $_" -ForegroundColor Red
                    $failCount++
                }
            } else {
                Write-Host " ❌ Failed: $_" -ForegroundColor Red
                $failCount++
                break
            }
        }
    }
    
    # P1修正: 基本的なレート制限対策（200ms待機）
    if ($success) {
        Start-Sleep -Milliseconds 200
    }
}

# --- アップロードサマリー表示 ---
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Upload Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ Success: $successCount" -ForegroundColor Green
Write-Host "❌ Failed:  $failCount" -ForegroundColor Red
Write-Host "📁 Total:   $($logFiles.Count)" -ForegroundColor Cyan
Write-Host ""

if ($failCount -eq 0) {
    Write-Host "🎉 All logs uploaded successfully!" -ForegroundColor Green
} else {
    Write-Host "⚠️  Some logs failed to upload. Check errors above." -ForegroundColor Yellow
}

# --- P1修正: 古いログのクリーンアップ（7日保持） ---
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Cleaning Up Old Logs (7-day retention)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$cutoffDate = (Get-Date).AddDays(-$retentionDays)
$deletedCount = 0

if (Test-Path $processedDir) {
    $processedFiles = Get-ChildItem -Path $processedDir -Filter "*.json"
    
    if ($processedFiles.Count -eq 0) {
        Write-Host "ℹ️  No processed logs found" -ForegroundColor Yellow
    } else {
        foreach ($file in $processedFiles) {
            if ($file.CreationTime -lt $cutoffDate) {
                $daysOld = [math]::Round((Get-Date - $file.CreationTime).TotalDays, 1)
                
                if ($DryRun) {
                    Write-Host "🔍 Would delete: $($file.Name) (uploaded $daysOld days ago)" -ForegroundColor Gray
                    $deletedCount++
                } else {
                    Remove-Item $file.FullName -Force
                    Write-Host "🗑️  Deleted: $($file.Name) (uploaded $daysOld days ago)" -ForegroundColor Gray
                    $deletedCount++
                }
            }
        }
        
        if ($deletedCount -eq 0) {
            Write-Host "ℹ️  No old logs to delete (all files are within $retentionDays days)" -ForegroundColor Yellow
        } else {
            if ($DryRun) {
                Write-Host "🔍 Would delete $deletedCount old log(s)" -ForegroundColor Yellow
            } else {
                Write-Host "✅ Deleted $deletedCount old log(s)" -ForegroundColor Green
            }
        }
    }
} else {
    Write-Host "ℹ️  No processed directory found, skipping cleanup" -ForegroundColor Yellow
}

# --- 最終サマリー ---
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Final Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "📤 Uploaded:  $successCount file(s)" -ForegroundColor Green
Write-Host "❌ Failed:    $failCount file(s)" -ForegroundColor Red
Write-Host "🗑️  Cleaned:   $deletedCount old log(s)" -ForegroundColor Gray
Write-Host ""

if ($DryRun) {
    Write-Host "🔍 DRY RUN MODE: No files were actually deleted" -ForegroundColor Yellow
    Write-Host "   Run without -DryRun to perform actual cleanup" -ForegroundColor Yellow
}
