// Automatically generated Cedar policy for Bot: 5be3e14e-2e46-f111-bec6-7c1e52344333
// Only includes actual Tools (Actions/Connectors), excluding system topics.

// Tool: Microsoft Dataverse MCP Server (Preview)
permit(
    principal,
    action in [Action::"tools/call", Action::"resources/read", Action::"resources/write"],
    resource
) when {
    resource == Resource::"InvokeMCPPreview" || resource == Resource::"Microsoft Dataverse MCP Server (Preview)" || resource == Resource::"Microsoft-Dataverse-MCP-Server-(Preview)" || resource == Resource::"MicrosoftDataverseMCPServer(Preview)" || resource == Resource::"MicrosoftDataverseMicrosoftDataverseMCPServerPreview" || resource == Resource::"template-content.action.MicrosoftDataverseMicrosoftDataverseMCPServerPreview"
};

// Tool: Create table
permit(
    principal,
    action in [Action::"tools/call", Action::"resources/read", Action::"resources/write"],
    resource
) when {
    resource == Resource::"Create table" || resource == Resource::"Create-table" || resource == Resource::"CreateTable" || resource == Resource::"Createtable" || resource == Resource::"ExcelOnlineBusinessCreatetable" || resource == Resource::"template-content.action.ExcelOnlineBusinessCreatetable"
};

// Tool: Get tables
permit(
    principal,
    action in [Action::"tools/call", Action::"resources/read", Action::"resources/write"],
    resource
) when {
    resource == Resource::"ExcelOnlineBusinessGettables" || resource == Resource::"Get tables" || resource == Resource::"Get-tables" || resource == Resource::"GetTables" || resource == Resource::"Gettables" || resource == Resource::"template-content.action.ExcelOnlineBusinessGettables"
};

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

