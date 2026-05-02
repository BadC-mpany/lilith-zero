// Automatically generated Cedar policy for Bot: 77236ced-1146-f111-bec6-7ced8d71fac9
// Only includes actual Tools (Actions/Connectors), excluding system topics.

// Tool: Work IQ Copilot (Preview)
permit(
    principal,
    action in [Action::"tools/call", Action::"resources/read", Action::"resources/write"],
    resource
) when {
    resource == Resource::"Work IQ Copilot (Preview)" || resource == Resource::"Work-IQ-Copilot-(Preview)" || resource == Resource::"WorkIQCopilot(Preview)" || resource == Resource::"WorkIQCopilotPreview" || resource == Resource::"mcp_m365copilot" || resource == Resource::"template-content.action.WorkIQCopilotPreview"
};

// Tool: Work IQ User (Preview)
permit(
    principal,
    action in [Action::"tools/call", Action::"resources/read", Action::"resources/write"],
    resource
) when {
    resource == Resource::"Work IQ User (Preview)" || resource == Resource::"Work-IQ-User-(Preview)" || resource == Resource::"WorkIQUser(Preview)" || resource == Resource::"WorkIQUserPreview" || resource == Resource::"mcp_MeServer" || resource == Resource::"template-content.action.WorkIQUserPreview"
};

// Tool: Add a row into a table
permit(
    principal,
    action in [Action::"tools/call", Action::"resources/read", Action::"resources/write"],
    resource
) when {
    resource == Resource::"Add a row into a table" || resource == Resource::"Add-a-row-into-a-table" || resource == Resource::"AddRowV2" || resource == Resource::"Addarowintoatable" || resource == Resource::"ExcelOnlineBusinessAddarowintoatable" || resource == Resource::"template-content.action.ExcelOnlineBusinessAddarowintoatable"
};

