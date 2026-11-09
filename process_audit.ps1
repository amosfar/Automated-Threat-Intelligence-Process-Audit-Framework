param(
    [string]$OutputFile = "process_report.json"
)

Write-Host "Collecting running processes..." 

$processList = Get-Process | ForEach-Object {
    $p = $_
    $hash = "NoHash"
    $path = $null

    
    try {
        $path = $p.Path
    }
    catch {
        $path = $null
    }

    
    if ($path) {
        try {
            $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash
        }
        catch {
            $hash = "AccessDenied"
        }
    }

    # Custom Object Building
    [PSCustomObject]@{
        Name      = $p.ProcessName
        PID       = $p.Id
        CPU       = $p.CPU
        MemoryMB  = [math]::Round($p.WorkingSet / 1MB, 2)
        Path      = $path
        Hash      = $hash
        StartTime = $p.StartTime
    }
}

$processList |
    Sort-Object MemoryMB -Descending |
    ConvertTo-Json -Depth 5 |
    Out-File $OutputFile

Write-Host "Process collection complete. Saved to $OutputFile" 
