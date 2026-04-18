param(
    [string]$WorkflowPath = ".\workflow.json"
)

if (-not (Test-Path $WorkflowPath)) {
    Write-Error "Workflow file not found: $WorkflowPath"
    exit 1
}

try {
    $json = Get-Content $WorkflowPath -Raw | ConvertFrom-Json
} catch {
    Write-Error "Invalid JSON in workflow file."
    exit 1
}

if (-not $json.nodes) {
    Write-Error "Workflow JSON does not contain a nodes array."
    exit 1
}

Write-Host "Workflow JSON loaded successfully."
Write-Host ("Node count: " + $json.nodes.Count)

foreach ($node in $json.nodes) {
    if (-not $node.name) {
        Write-Warning "A node is missing a name."
    }
    if (-not $node.type) {
        Write-Warning ("Node '" + $node.name + "' is missing a type.")
    }
}

Write-Host "Basic validation complete."
