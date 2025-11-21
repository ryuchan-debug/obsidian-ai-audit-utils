<#
.SYNOPSIS
    Send audit log to AWS CloudWatch Logs.

.DESCRIPTION
    Sends JSON audit log entries to CloudWatch Logs for centralized monitoring.
    Uses the 'obsidian' AWS profile and Python boto3.

.PARAMETER LogEntry
    JSON string of audit log entry

.PARAMETER LogGroupName
    CloudWatch Logs group name (default: /obsidian-ai/audit-logs)

.PARAMETER LogStreamName
    CloudWatch Logs stream name (default: phase2-audit)

.EXAMPLE
    $logEntry = Get-Content audit_log.json -Raw
    .\Send-AuditLog.ps1 -LogEntry $logEntry

.NOTES
    Version: 3.0.0
    Phase: 3a (P0 Security Fix - Temporary File ACL)
    Requirements: Python 3.x + boto3, AWS_PROFILE=obsidian
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$LogEntry,
    
    [string]$LogGroupName = "/obsidian-ai/audit-logs",
    
    [string]$LogStreamName = "phase2-audit",
    
    [string]$Region = "ap-northeast-1",
    
    [string]$Profile = "obsidian"
)

function Send-AuditLog {
    param(
        [string]$LogEntry,
        [string]$LogGroupName,
        [string]$LogStreamName,
        [string]$Region,
        [string]$Profile
    )
    
    try {
        # 一時ファイルに保存（UTF-8）
        $tempLogFile = Join-Path $env:TEMP "audit_log_$([Guid]::NewGuid().ToString()).json"
        $LogEntry | Set-Content -Path $tempLogFile -Encoding UTF8 -NoNewline
        
        # P0修正: 一時ファイルのACL設定（実行ユーザーのみ読み書き可能）
        try {
            $acl = Get-Acl $tempLogFile
            $acl.SetAccessRuleProtection($true, $false)  # 継承を無効化
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            $fileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, $fileSystemRights, $type)
            $acl.SetAccessRule($fileSystemAccessRule)
            Set-Acl -Path $tempLogFile -AclObject $acl
        } catch {
            Write-Warning "Failed to set ACL on temporary log file: $_"
        }
        
        # Pythonスクリプトを作成（boto3でCloudWatch Logs送信）
        $tempPyScript = Join-Path $env:TEMP "send_to_cloudwatch_$([Guid]::NewGuid().ToString()).py"
        $pythonCode = @"
import boto3
import json
import time
import os

# 環境変数設定
os.environ['AWS_PROFILE'] = '$Profile'

# ログエントリを読み込み
with open('$($tempLogFile.Replace('\', '\\'))', 'r', encoding='utf-8') as f:
    log_entry = f.read()

# CloudWatch Logsクライアント作成
client = boto3.client('logs', region_name='$Region')

# タイムスタンプ（ミリ秒）
timestamp = int(time.time() * 1000)

# ログイベント送信
try:
    response = client.put_log_events(
        logGroupName='$LogGroupName',
        logStreamName='$LogStreamName',
        logEvents=[
            {
                'timestamp': timestamp,
                'message': log_entry
            }
        ]
    )
    print('SUCCESS')
except Exception as e:
    print(f'ERROR: {str(e)}')
    raise
"@
        
        $pythonCode | Set-Content -Path $tempPyScript -Encoding UTF8
        
        # P0修正: Pythonスクリプトの一時ファイルにもACL設定
        try {
            $acl = Get-Acl $tempPyScript
            $acl.SetAccessRuleProtection($true, $false)
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::FullControl
            $type = [System.Security.AccessControl.AccessControlType]::Allow
            $fileSystemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, $fileSystemRights, $type)
            $acl.SetAccessRule($fileSystemAccessRule)
            Set-Acl -Path $tempPyScript -AclObject $acl
        } catch {
            Write-Warning "Failed to set ACL on temporary Python script: $_"
        }
        
        try {
            # Pythonスクリプト実行
            $result = py $tempPyScript 2>&1
            
            if ($result -match 'SUCCESS') {
                Write-Host "✅ Audit log sent to CloudWatch Logs" -ForegroundColor Green
                return $result
            } else {
                throw "Python script failed: $result"
            }
        } finally {
            # 一時ファイル削除
            if (Test-Path $tempLogFile) {
                Remove-Item $tempLogFile -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path $tempPyScript) {
                Remove-Item $tempPyScript -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Host "❌ Failed to send audit log: $_" -ForegroundColor Red
        throw
    }
}

# Execute
Send-AuditLog -LogEntry $LogEntry -LogGroupName $LogGroupName -LogStreamName $LogStreamName -Region $Region -Profile $Profile
