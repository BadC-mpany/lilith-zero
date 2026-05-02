// Automatically generated Cedar policy for Bot: 77236ced-1146-f111-bec6-7ced8d71fac9
// Allows all extracted tools by default

// Tool: Forecasting
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Forecasting"
};

// Tool: Greeting
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Greeting"
};

// Tool: Advice seeking
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Adviceseeking"
};

// Tool: Reset conversation
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Resetconversation"
};

// Tool: Sign in 
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Signin"
};

// Tool: End of conversation
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Endofconversation"
};

// Tool: Start over
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Startover"
};

// Tool: Goodbye
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Goodbye"
};

// Tool: Query your repository
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Queryyourrepository"
};

// Tool: Work IQ Copilot (Preview)
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.action.WorkIQCopilotPreview"
};

// Tool: Advice or forecasting detected
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Adviceorforecastingdetected"
};

// Tool: Conversational boosting
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Conversationalboosting"
};

// Tool: Non financial
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Nonfinancial"
};

// Tool: On error
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Onerror"
};

// Tool: Work IQ User (Preview)
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.action.WorkIQUserPreview"
};

// Tool: Excel Online (Business) - Add a row into a table
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.action.ExcelOnlineBusinessAddarowintoatable"
};

// Tool: Add a row into a table
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"AddRowV2"
};

// Tool: Conversation start
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Conversationstart"
};

// Tool: Thank you
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"template-content.topic.Thankyou"
};

