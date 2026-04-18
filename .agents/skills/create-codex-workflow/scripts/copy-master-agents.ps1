[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetRepoPath,

    [string]$MasterAgentsPath = "C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents",

    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Resolve-FullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $executionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Test-ExcludedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $excludedNames = @(
        ".git",
        ".pytest_cache",
        "__pycache__",
        "node_modules",
        ".DS_Store",
        "Thumbs.db"
    )

    $parts = $Path -split "[\\/]+"
    foreach ($name in $excludedNames) {
        if ($parts -contains $name) {
            return $true
        }
    }

    return $false
}

$source = Resolve-FullPath $MasterAgentsPath
$targetRepo = Resolve-FullPath $TargetRepoPath
$targetAgents = Join-Path $targetRepo ".agents"

Write-Host "Master .agents source: $source"
Write-Host "Target repository: $targetRepo"
Write-Host "Destination .agents path: $targetAgents"

if (-not (Test-Path -LiteralPath $source -PathType Container)) {
    throw "Master .agents source path does not exist: $source"
}

if (-not (Test-Path -LiteralPath (Join-Path $source "AGENTS.md") -PathType Leaf)) {
    throw "Master .agents source is missing AGENTS.md: $source"
}

if (-not (Test-Path -LiteralPath (Join-Path $source "skills") -PathType Container)) {
    throw "Master .agents source is missing skills directory: $source"
}

if (-not (Test-Path -LiteralPath $targetRepo -PathType Container)) {
    Write-Host "Creating target repository folder..."
    New-Item -ItemType Directory -Path $targetRepo -Force | Out-Null
}

if ((Test-Path -LiteralPath $targetAgents) -and -not $Force) {
    throw "Destination .agents already exists. Re-run with -Force to merge and overwrite matching files: $targetAgents"
}

if (-not (Test-Path -LiteralPath $targetAgents -PathType Container)) {
    New-Item -ItemType Directory -Path $targetAgents | Out-Null
}

$sourceRootLength = $source.TrimEnd("\").Length
$items = Get-ChildItem -LiteralPath $source -Recurse -Force
$copiedFiles = 0
$createdDirs = 0
$skippedItems = 0

foreach ($item in $items) {
    if (Test-ExcludedPath $item.FullName) {
        $skippedItems++
        continue
    }

    $relativePath = $item.FullName.Substring($sourceRootLength).TrimStart("\")
    $destination = Join-Path $targetAgents $relativePath

    if ($item.PSIsContainer) {
        if (-not (Test-Path -LiteralPath $destination -PathType Container)) {
            if ($PSCmdlet.ShouldProcess($destination, "Create directory")) {
                New-Item -ItemType Directory -Path $destination | Out-Null
                $createdDirs++
            }
        }
        continue
    }

    $destinationParent = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $destinationParent -PathType Container)) {
        New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
        $createdDirs++
    }

    if ((Test-Path -LiteralPath $destination -PathType Leaf) -and -not $Force) {
        $skippedItems++
        Write-Host "Skipping existing file: $destination"
        continue
    }

    if ($PSCmdlet.ShouldProcess($destination, "Copy file")) {
        Copy-Item -LiteralPath $item.FullName -Destination $destination -Force:$Force
        $copiedFiles++
    }
}

$requiredAgentsFile = Join-Path $targetAgents "AGENTS.md"
$requiredSkillsDir = Join-Path $targetAgents "skills"

if (-not (Test-Path -LiteralPath $requiredAgentsFile -PathType Leaf)) {
    throw "Copy validation failed. Missing: $requiredAgentsFile"
}

if (-not (Test-Path -LiteralPath $requiredSkillsDir -PathType Container)) {
    throw "Copy validation failed. Missing: $requiredSkillsDir"
}

Write-Host "Copy complete."
Write-Host "Directories created: $createdDirs"
Write-Host "Files copied: $copiedFiles"
Write-Host "Items skipped: $skippedItems"
Write-Host "Verified: $requiredAgentsFile"
Write-Host "Verified: $requiredSkillsDir"
