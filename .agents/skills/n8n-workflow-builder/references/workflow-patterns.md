# Workflow Patterns

## Common Patterns

### Webhook Intake to Queue
Webhook -> Normalize -> Validate -> Store Job -> Return Acknowledgement

### Queue Runner
Scheduled Trigger -> Fetch Queued Job -> Claim Job -> Execute Runner -> Store Result -> Mark Complete

### Agent Review Loop
Trigger -> Build Prompt -> Execute Agent -> Store Output -> Human Review -> Next Step or Close

### Local Execution Bridge
Queue Job -> Format Local Command -> Run PowerShell or Python -> Capture Output -> Persist Result
