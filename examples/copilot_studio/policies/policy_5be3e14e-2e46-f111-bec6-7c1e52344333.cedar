// Automatically generated Cedar policy for Bot: 5be3e14e-2e46-f111-bec6-7c1e52344333
// Only includes actual Tools (Actions/Connectors), excluding system topics.

// Default permit for resources to allow tool arguments (subject, to, etc.) to pass through.
permit(
    principal,
    action in [Action::"resources/read", Action::"resources/write"],
    resource
);

// Tool: Mock Actions API 3 - Mock Actions API 3
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"Cra65-Otpdemo-Action-Mock-Actions-Ap-I3-Mock-Actions-Ap-I3" || resource == Resource::"Cra65OtpdemoActionMockActionsApI3MockActionsApI3" || resource == Resource::"Mock Actions API 3 - Mock Actions API 3" || resource == Resource::"Mock-Actions-API-3---Mock-Actions-API-3" || resource == Resource::"Mock-Actions-Api-3-Mock-Actions-Api-3" || resource == Resource::"MockActionsAPI3-MockActionsAPI3" || resource == Resource::"MockActionsAPI3MockActionsAPI3" || resource == Resource::"MockActionsApi3MockActionsApi3" || resource == Resource::"Send-Email" || resource == Resource::"SendEmail" || resource == Resource::"Template-Content-Action-Mock-Actions-Ap-I3-Mock-Actions-Ap-I3" || resource == Resource::"Template-Content-Connectionreference-Cra65-Otpdemo-Shared-Cra655fmock20actions20api2035ff1d9155c6c88" || resource == Resource::"TemplateContentActionMockActionsApI3MockActionsApI3" || resource == Resource::"TemplateContentConnectionreferenceCra65OtpdemoSharedCra655fmock20actions20api2035ff1d9155c6c88" || resource == Resource::"cra65-otpdemo-action-mock-actions-ap-i3-mock-actions-ap-i3" || resource == Resource::"cra65-otpdemo.action.MockActionsAPI3-MockActionsAPI3" || resource == Resource::"cra65_otpdemo.action.MockActionsAPI3-MockActionsAPI3" || resource == Resource::"cra65_otpdemo_action_mock_actions_ap_i3_mock_actions_ap_i3" || resource == Resource::"mock-actions-api-3-mock-actions-api-3" || resource == Resource::"mock_actions_api_3_mock_actions_api_3" || resource == Resource::"send-email" || resource == Resource::"sendEmail" || resource == Resource::"send_email" || resource == Resource::"shared_cra655fmock20actions20api2035ff1d9155c6c88" || resource == Resource::"template-content-action-mock-actions-ap-i3-mock-actions-ap-i3" || resource == Resource::"template-content-connectionreference-cra65-otpdemo-shared-cra655fmock20actions20api2035ff1d9155c6c88" || resource == Resource::"template-content.action.MockActionsAPI3MockActionsAPI3" || resource == Resource::"template-content.connectionreference.cra65-otpdemo.shared-cra655fmock20actions20api2035ff1d9155c6c88" || resource == Resource::"template-content.connectionreference.cra65_otpdemo.shared_cra655fmock20actions20api2035ff1d9155c6c88" || resource == Resource::"template_content_action_mock_actions_ap_i3_mock_actions_ap_i3" || resource == Resource::"template_content_connectionreference_cra65_otpdemo_shared_cra655fmock20actions20api2035ff1d9155c6c88"
};

