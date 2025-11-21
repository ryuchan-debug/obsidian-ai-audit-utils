<#
.SYNOPSIS
    Generates a unique trace_id for audit logging.

.DESCRIPTION
    Creates a trace_id in the format: UUID_v4 + ":" + ISO8601_timestamp
    Example: 550e8400-e29b-41d4-a716-446655440000:2025-11-20T03:47:14Z

.EXAMPLE
    $traceId = .\Generate-TraceId.ps1
    Write-Host "Generated trace_id: $traceId"

.NOTES
    Version: 1.0.0
    Phase: 2 (Minimum Implementation)
    Security: UUID ensures uniqueness, timestamp enables chronological sorting
#>

function Generate-TraceId {
    # Generate UUID v4
    $uuid = [System.Guid]::NewGuid().ToString()
    
    # Generate ISO8601 timestamp (UTC)
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    # Combine: UUID:Timestamp
    $traceId = "${uuid}:${timestamp}"
    
    return $traceId
}

# Execute and return
Generate-TraceId
