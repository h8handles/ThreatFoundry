param(
    [string]$BaseUrl = "http://localhost:5679",
    [string]$ApiKey = $env:N8N_API_KEY,
    [string]$WorkflowPath = "n8n/workflows/threatfoundry_analyst_chat.workflow.json",
    [switch]$Activate
)

if (-not $ApiKey) {
    throw "N8N API key is required. Set N8N_API_KEY or pass -ApiKey."
}

if (-not (Test-Path -LiteralPath $WorkflowPath)) {
    throw "Workflow file not found: $WorkflowPath"
}

$rawWorkflow = Get-Content -LiteralPath $WorkflowPath -Raw
$workflow = $rawWorkflow | ConvertFrom-Json -Depth 100
$headers = @{
    "X-N8N-API-KEY" = $ApiKey
    "Content-Type"  = "application/json"
}

$base = $BaseUrl.TrimEnd("/")
$listUri = "$base/api/v1/workflows?limit=250"
$listResponse = Invoke-RestMethod -Method Get -Uri $listUri -Headers $headers
$existing = @($listResponse.data) | Where-Object { $_.name -eq $workflow.name } | Select-Object -First 1

$body = @{
    name        = $workflow.name
    nodes       = $workflow.nodes
    connections = $workflow.connections
    settings    = $workflow.settings
} | ConvertTo-Json -Depth 100

if ($existing) {
    $workflowId = $existing.id
    $updateUri = "$base/api/v1/workflows/$workflowId"
    $result = Invoke-RestMethod -Method Put -Uri $updateUri -Headers $headers -Body $body
    Write-Host "Updated workflow: $($result.name) (id=$workflowId)"
}
else {
    $createUri = "$base/api/v1/workflows"
    $result = Invoke-RestMethod -Method Post -Uri $createUri -Headers $headers -Body $body
    $workflowId = $result.id
    Write-Host "Created workflow: $($result.name) (id=$workflowId)"
}

if ($Activate) {
    $activateBody = @{ active = $true } | ConvertTo-Json
    $activateUri = "$base/api/v1/workflows/$workflowId"
    $activated = Invoke-RestMethod -Method Patch -Uri $activateUri -Headers $headers -Body $activateBody
    Write-Host "Activated workflow: $($activated.name) (active=$($activated.active))"
}

$webhookUrl = "$base/webhook/threatfoundry-analyst-chat"
Write-Host "Set INTEL_CHAT_N8N_WEBHOOK_URL=$webhookUrl"
