param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $ManageArgs
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$candidatePaths = @()

if ($env:THREATFOUNDRY_PYTHON) {
    $candidatePaths += $env:THREATFOUNDRY_PYTHON
}

$candidatePaths += Join-Path $repoRoot ".venv\Scripts\python.exe"
$candidatePaths += Join-Path $repoRoot "venv\Scripts\python.exe"
$candidatePaths += Join-Path $env:LOCALAPPDATA "Python\pythoncore-3.14-64\python.exe"
$candidatePaths += Join-Path $env:LOCALAPPDATA "Python\pythoncore-3.12-64\python.exe"
$candidatePaths += Join-Path $env:LOCALAPPDATA "Python\bin\python.exe"

$pythonPath = $null
foreach ($candidate in $candidatePaths) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
        try {
            & $candidate -c "import django, sys; print(sys.executable)" *> $null
            if ($LASTEXITCODE -eq 0) {
                $pythonPath = $candidate
                break
            }
        } catch {
            continue
        }
    }
}

if (-not $pythonPath) {
    throw "No usable Python executable with Django installed was found. Set THREATFOUNDRY_PYTHON to an absolute python.exe path, install requirements into .venv, or run .\.venv\Scripts\python.exe -m pip install -r requirements.txt."
}

Write-Host "Using Python: $pythonPath"
& $pythonPath (Join-Path $repoRoot "manage.py") @ManageArgs
exit $LASTEXITCODE
