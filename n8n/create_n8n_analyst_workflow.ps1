param(
    [string]$BaseUrl = "http://localhost:5678",
    [string]$ApiKey = $env:N8N_API_KEY,
    [string]$WorkflowFile = ".\threatfoundry_analyst_chat.workflow.json",
    [switch]$Activate,
    [switch]$ForceCreate
)

$ErrorActionPreference = "Stop"

function Get-ErrorResponseBody {
    param([System.Exception]$Exception)

    try {
        if ($Exception.Response -and $Exception.Response.GetResponseStream()) {
            $reader = New-Object System.IO.StreamReader($Exception.Response.GetResponseStream())
            return $reader.ReadToEnd()
        }
    }
    catch {
    }

    return $null
}

function ConvertFrom-JsonCompat {
    param([string]$JsonText)

    $hasDepth = (Get-Command ConvertFrom-Json).Parameters.ContainsKey("Depth")
    if ($hasDepth) {
        return ($JsonText | ConvertFrom-Json -Depth 100)
    }

    return ($JsonText | ConvertFrom-Json)
}

function New-WorkflowBody {
    param($Workflow)

    return @{
        name        = $Workflow.name
        nodes       = $Workflow.nodes
        connections = $Workflow.connections
        settings    = if ($null -ne $Workflow.settings) { $Workflow.settings } else { @{} }
    }
}

if (-not $ApiKey) {
    throw "N8N API key is required. Set N8N_API_KEY or pass -ApiKey."
}

if (-not (Test-Path -LiteralPath $WorkflowFile)) {
    throw "Workflow file not found: $WorkflowFile"
}

$rawWorkflow = Get-Content -LiteralPath $WorkflowFile -Raw

try {
    $workflow = ConvertFrom-JsonCompat -JsonText $rawWorkflow
}
catch {
    throw "Failed to parse workflow JSON from '$WorkflowFile'. $($_.Exception.Message)"
}

if (-not $workflow.name) {
    throw "Workflow JSON is missing required property: name"
}

if (-not $workflow.nodes) {
    throw "Workflow JSON is missing required property: nodes"
}

if (-not $workflow.connections) {
    throw "Workflow JSON is missing required property: connections"
}

$headers = @{
    "X-N8N-API-KEY" = $ApiKey
    "Content-Type"  = "application/json"
    "Accept"        = "application/json"
}

$base = $BaseUrl.TrimEnd("/")
$baseUri = [Uri]$base

$port = if ($baseUri.IsDefaultPort) {
    if ($baseUri.Scheme -eq "https") { 443 } else { 80 }
}
else {
    $baseUri.Port
}

$reachability = Test-NetConnection -ComputerName $baseUri.Host -Port $port -WarningAction SilentlyContinue
if (-not $reachability.TcpTestSucceeded) {
    throw "Unable to connect to n8n at $base (host=$($baseUri.Host), port=$port)."
}

$listUri = "$base/api/v1/workflows?limit=250"

try {
    $listResponse = Invoke-RestMethod -Method Get -Uri $listUri -Headers $headers
}
catch {
    $errorBody = Get-ErrorResponseBody -Exception $_.Exception
    throw "Failed calling n8n API at $listUri. $($_.Exception.Message)`n$errorBody"
}

$existing = $null
if (-not $ForceCreate) {
    $existing = @($listResponse.data) | Where-Object { $_.name -eq $workflow.name } | Select-Object -First 1
}

$bodyObject = New-WorkflowBody -Workflow $workflow
$body = $bodyObject | ConvertTo-Json -Depth 100

$workflowId = $null
$didUpdate = $false

if ($existing) {
    $workflowId = $existing.id
    $updateUri = "$base/api/v1/workflows/$workflowId"

    try {
        $result = Invoke-RestMethod -Method Put -Uri $updateUri -Headers $headers -Body $body
        $didUpdate = $true
        Write-Host "Updated workflow: $($result.name) (id=$workflowId)"
    }
    catch {
        $errorBody = Get-ErrorResponseBody -Exception $_.Exception
        Write-Warning "Update failed for workflow id '$workflowId'. Falling back to create."
        if ($errorBody) {
            Write-Warning $errorBody
        }

        $createUri = "$base/api/v1/workflows"
        try {
            $result = Invoke-RestMethod -Method Post -Uri $createUri -Headers $headers -Body $body
            $workflowId = $result.id
            if (-not $workflowId) {
                throw "n8n create response did not include a workflow id."
            }
            Write-Host "Created workflow after update fallback: $($result.name) (id=$workflowId)"
        }
        catch {
            $createErrorBody = Get-ErrorResponseBody -Exception $_.Exception
            throw "Update failed and create fallback also failed for workflow '$($workflow.name)'. $($_.Exception.Message)`nResponse body:`n$createErrorBody"
        }
    }
}
else {
    $createUri = "$base/api/v1/workflows"

    try {
        $result = Invoke-RestMethod -Method Post -Uri $createUri -Headers $headers -Body $body
        $workflowId = $result.id
        if (-not $workflowId) {
            throw "n8n create response did not include a workflow id."
        }
        Write-Host "Created workflow: $($result.name) (id=$workflowId)"
    }
    catch {
        $errorBody = Get-ErrorResponseBody -Exception $_.Exception
        throw "Failed to create workflow '$($workflow.name)' at $createUri. $($_.Exception.Message)`nResponse body:`n$errorBody"
    }
}

if ($Activate -and $workflowId) {
    $activateUri = "$base/api/v1/workflows/$workflowId/activate"

    try {
        Invoke-RestMethod -Method Post -Uri $activateUri -Headers $headers | Out-Null
        Write-Host "Activated workflow: $workflowId"
    }
    catch {
        $errorBody = Get-ErrorResponseBody -Exception $_.Exception
        Write-Warning "Dedicated activate endpoint failed."
        if ($errorBody) {
            Write-Warning $errorBody
        }

        try {
            $patchUri = "$base/api/v1/workflows/$workflowId"
            $patchBody = @{ active = $true } | ConvertTo-Json -Depth 10
            $activated = Invoke-RestMethod -Method Patch -Uri $patchUri -Headers $headers -Body $patchBody
            Write-Host "Activated workflow via PATCH: $($activated.name)"
        }
        catch {
            $fallbackErrorBody = Get-ErrorResponseBody -Exception $_.Exception
            throw "Failed to activate workflow '$workflowId'. $($_.Exception.Message)`nResponse body:`n$fallbackErrorBody"
        }
    }
}

$webhookUrl = "$base/webhook/threatfoundry-analyst-chat"
Write-Host "Set INTEL_CHAT_N8N_WEBHOOK_URL=$webhookUrl"