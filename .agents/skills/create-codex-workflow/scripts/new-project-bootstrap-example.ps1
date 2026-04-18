[CmdletBinding()]
param(
    [string]$TargetRepoPath = "C:\Users\ghbub\OneDrive\Desktop\new-codex-project",
    [string]$ProjectName = "new-codex-project",
    [string]$ProjectType = "generic"
)

$ErrorActionPreference = "Stop"

$masterAgentsPath = "C:\Users\ghbub\OneDrive\Desktop\coding-repo\.agents"
$skillScriptPath = Join-Path $masterAgentsPath "skills\create-codex-workflow\scripts\copy-master-agents.ps1"
$targetRepo = $executionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TargetRepoPath)

Write-Host "Creating project: $ProjectName"
Write-Host "Project type: $ProjectType"
Write-Host "Target path: $targetRepo"

if (-not (Test-Path -LiteralPath $targetRepo -PathType Container)) {
    New-Item -ItemType Directory -Path $targetRepo -Force | Out-Null
}

$starterDirs = @("src", "docs", "scripts", "tests", "prompts")

foreach ($dir in $starterDirs) {
    $path = Join-Path $targetRepo $dir
    if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        New-Item -ItemType Directory -Path $path | Out-Null
        Write-Host "Created: $path"
    }
    else {
        Write-Host "Already exists: $path"
    }
}

& $skillScriptPath -TargetRepoPath $targetRepo -MasterAgentsPath $masterAgentsPath

Write-Host "Bootstrap complete for $ProjectName."
Write-Host "Next checks:"
Write-Host "  Test-Path `"$targetRepo\.agents\AGENTS.md`""
Write-Host "  Test-Path `"$targetRepo\.agents\skills`""
