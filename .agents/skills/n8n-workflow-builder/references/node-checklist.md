# Node Checklist

Use this checklist when reviewing an n8n workflow:

- Trigger node is correct for the intended entry path
- Incoming fields are normalized before branching
- Node names are descriptive
- Expressions reference real fields
- Conditional logic handles missing data
- Queue writes include status fields
- Runner steps log or return useful results
- Error paths do not silently swallow failures
- Workflow can be explained from trigger to final action
