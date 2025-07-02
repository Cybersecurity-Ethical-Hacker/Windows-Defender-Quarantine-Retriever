<#
.SYNOPSIS
    Recovers Windows Defender quarantine files related to specific threats.
.DESCRIPTION
    Searches for and recovers files from Windows Defender quarantine that match
    a specific keyword and were detected within a specified time window.
    Recovered files may be malicious - handle with extreme caution.

.PARAMETER searchKeyword
    The keyword to search for in threat resources (default: "lsass")

.PARAMETER outputFolder
    Output directory for recovered files (default: "RecoveredResourceData" in current directory)

.PARAMETER timeWindowMinutes
    Time window around detection time to search for files (default: 2 minutes)

.EXAMPLE
    .\RecoverDefenderQuarantine.ps1 -searchKeyword "mimikatz" -timeWindowMinutes 5

.EXAMPLE
    .\RecoverDefenderQuarantine.ps1 -outputFolder "C:\Forensics\DefenderQuarantine"

.NOTES
    Security Warning: Recovered files may contain active malware. Always analyze in a secure,
    isolated environment with proper protections.
#>

param (
    [string]$searchKeyword = "lsass",
    [string]$outputFolder = (Join-Path (Get-Location) "RecoveredResourceData"),
    [int]$timeWindowMinutes = 2
)

Write-Host "==============================================================" -ForegroundColor Cyan
Write-Host "  Windows Defender Quarantine Retriever v1.0                  " -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------" -ForegroundColor Cyan
Write-Host " Author     : Dimitris Chatzidimitris                         " -ForegroundColor Cyan
Write-Host " Purpose    : Recover files from Windows Defender quarantine" -ForegroundColor Cyan
Write-Host "              based on keyword and detection time window   " -ForegroundColor Cyan
Write-Host " Usage      : .\RecoverDefenderQuarantine.ps1 [parameters]  " -ForegroundColor Cyan
Write-Host " Parameters :                                               " -ForegroundColor Cyan
Write-Host "  -searchKeyword     Keyword to filter threats (default: lsass)" -ForegroundColor Cyan
Write-Host "  -outputFolder      Output directory (default: ./RecoveredResourceData)" -ForegroundColor Cyan
Write-Host "  -timeWindowMinutes Time window (minutes) around detection (default: 2)" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""
Write-Host " Script starting...       " -ForegroundColor Yellow
Write-Host ""

function Get-ResourceFilenames($resources) {
    $fileNames = @()
    foreach ($res in $resources) {
        if ($res -match 'file:_([^}]+)') {
            $fullPath = $matches[1]
            $fileName = [System.IO.Path]::GetFileName($fullPath)
            $fileNames += $fileName
        }
    }
    return $fileNames
}

function Get-DefenderQuarantinePath {
    $quarantinePath = $null

    # Expanded list of possible registry keys Defender might use for quarantine path
    $possibleRegKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Quarantine",
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan",
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\DetectionHistory",
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features",
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Threats"
    )

    foreach ($regKey in $possibleRegKeys) {
        try {
            $regProps = Get-ItemProperty -Path $regKey -ErrorAction Stop
            foreach ($propName in $regProps.PSObject.Properties.Name) {
                $value = $regProps.$propName
                if ($value -and ($value -is [string]) -and ($value -match 'ResourceData')) {
                    if (Test-Path $value) {
                        $quarantinePath = $value
                        Write-Host "[+] Defender quarantine folder detected via registry:`n    Path  : $quarantinePath`n    Registry Key: $regKey`n    Property: $propName"
                        return $quarantinePath
                    }
                }
            }
        }
        catch {
            # Ignore missing keys and continue
            Write-Debug "Registry key not found or inaccessible: $regKey"
        }
    }

    # Fallback: Hardcoded default path based on ProgramData
    $programData = [Environment]::GetFolderPath("CommonApplicationData")
    $defaultPath = Join-Path $programData "Microsoft\Windows Defender\Quarantine\ResourceData"
    if (Test-Path $defaultPath) {
        $quarantinePath = $defaultPath
        Write-Host "[+] Defender quarantine folder detected:`n    Path  : $quarantinePath`n    Method: Fallback: Hardcoded default path"
    }
    else {
        Write-Warning "Defender quarantine folder not found in default location: $defaultPath"
        $quarantinePath = $null
    }

    return $quarantinePath
}

# Create output folder if missing
try {
    if (-not (Test-Path $outputFolder)) {
        New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
        Write-Host "[+] Created output directory: $outputFolder"
    }
}
catch {
    Write-Error "Failed to create output directory: $_"
    exit 1
}

# Get Defender detections matching keyword in resource filenames
function Get-DefenderThreatsByKeyword($keyword) {
    try {
        $threats = Get-MpThreatDetection | Where-Object {
            $files = Get-ResourceFilenames $_.Resources
            foreach ($f in $files) {
                if ($f -like "*$keyword*") { return $true }
            }
            return $false
        }
        return $threats
    }
    catch {
        Write-Error "Failed to retrieve Defender threats: $_"
        return $null
    }
}

$quarantineRoot = Get-DefenderQuarantinePath
if (-not $quarantineRoot) {
    Write-Error "No valid Defender quarantine folder path found. Exiting."
    exit 1
}

try {
    $threats = Get-DefenderThreatsByKeyword $searchKeyword
    if (-not $threats) {
        Write-Warning "No Defender threats found matching keyword '$searchKeyword'. Exiting."
        exit
    }
}
catch {
    Write-Error "Failed to process Defender threats: $_"
    exit 1
}

$totalFilesCopied = 0
$totalThreatsProcessed = 0

foreach ($threat in $threats) {
    $totalThreatsProcessed++
    $detectionTime = $threat.InitialDetectionTime
    $detectionTimeString = $detectionTime.ToString("yyyy-MM-dd HH:mm:ss")

    $resourceFiles = Get-ResourceFilenames $threat.Resources
    $matchedFiles = $resourceFiles | Where-Object { $_ -like "*$searchKeyword*" }

    # Create threat-specific output folder
    $threatOutputFolder = Join-Path $outputFolder "ThreatID_$($threat.ThreatID)_$($detectionTime.ToString('yyyyMMdd_HHmmss'))"
    try {
        New-Item -ItemType Directory -Path $threatOutputFolder -Force | Out-Null
    }
    catch {
        Write-Warning "Failed to create threat-specific output directory: $_"
        continue
    }

    Write-Host "[+] Processing ThreatID $($threat.ThreatID) detected at $detectionTimeString"
    Write-Host "[+] Matching file(s) in Resources: $($matchedFiles -join ', ')"

    $startTime = $detectionTime.AddMinutes(-$timeWindowMinutes)
    $endTime = $detectionTime.AddMinutes($timeWindowMinutes)
    $startTimeString = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
    $endTimeString = $endTime.ToString("yyyy-MM-dd HH:mm:ss")

    Write-Host "[+] Searching ResourceData files modified between $startTimeString and $endTimeString"

    # Find files modified in time window
    try {
        $files = Get-ChildItem $quarantineRoot -Recurse -File | Where-Object {
            ($_.LastWriteTime -ge $startTime) -and ($_.LastWriteTime -le $endTime)
        }

        if ($files.Count -eq 0) {
            Write-Warning "No files found in ResourceData during time window."
            continue
        }

        # Output filenames found
        $fileNames = $files.Name -join ", "
        Write-Host "[+] Files found: $fileNames"
        Write-Host "[+] Found $($files.Count) file(s) to copy."

        foreach ($file in $files) {
            $relativePath = $file.FullName.Substring($quarantineRoot.Length).TrimStart('\')
            $destPath = Join-Path $threatOutputFolder $relativePath
            $destDir = Split-Path $destPath
            
            try {
                if (-not (Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }

                Copy-Item -Path $file.FullName -Destination $destPath -Force
                
                # Calculate file hash
                try {
                    $hash = (Get-FileHash $destPath -Algorithm SHA256).Hash
                    Write-Host "[+] Copied from: $($file.FullName)"
                    Write-Host "[+] Copied to: $destPath"
                    Write-Host "[+] SHA256 Hash: $hash"
                    $totalFilesCopied++
                }
                catch {
                    Write-Warning ("Failed to calculate hash for " + $destPath + ": " + $_)
                }
            }
            catch {
                Write-Warning ("Failed to copy " + $file.FullName + ": " + $_)
            }
        }
    }
    catch {
        Write-Warning "Failed to search quarantine folder: $_"
        continue
    }
}

Write-Host "[+] Script completed. Total threats processed: $totalThreatsProcessed, total files copied: $totalFilesCopied."
Write-Host ""
Write-Host "[+] Output folder: $outputFolder"
Write-Host ""
Write-Host "REMINDER: All recovered files should be treated as potentially malicious and handled with extreme caution in a secure environment." -ForegroundColor Yellow
Write-Host "`n"