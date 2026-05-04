// Automatically generated Cedar policy for Bot: 5be3e14e-2e46-f111-bec6-7c1e52344333
// Only includes actual Tools (Actions/Connectors), excluding system topics.

// Default permit for resources to allow tool arguments (subject, to, etc.) to pass through.
permit(
    principal,
    action in [Action::"resources/read", Action::"resources/write"],
    resource
);

// Tool: Enterprise Integration Service - Enterprise Integration Service
permit(
    principal,
    action == Action::"tools/call",
    resource
) when {
    resource == Resource::"Cra65-Otpdemo-Action-Enterprise-Integration-Service-Enterprise-Integration-Service" || resource == Resource::"Cra65OtpdemoActionEnterpriseIntegrationServiceEnterpriseIntegrationService" || resource == Resource::"Delete-Database-Row" || resource == Resource::"DeleteDatabaseRow" || resource == Resource::"Enterprise Integration Service - Enterprise Integration Service" || resource == Resource::"Enterprise-Integration-Service---Enterprise-Integration-Service" || resource == Resource::"Enterprise-Integration-Service-Enterprise-Integration-Service" || resource == Resource::"EnterpriseIntegrationService-EnterpriseIntegrationService" || resource == Resource::"EnterpriseIntegrationServiceEnterpriseIntegrationService" || resource == Resource::"Template-Content-Action-Enterprise-Integration-Service-Enterprise-Integration-Service" || resource == Resource::"Template-Content-Connectionreference-Cra65-Otpdemo-Shared-Cra655fenterprise20integration20service5ff" || resource == Resource::"TemplateContentActionEnterpriseIntegrationServiceEnterpriseIntegrationService" || resource == Resource::"TemplateContentConnectionreferenceCra65OtpdemoSharedCra655fenterprise20integration20service5ff" || resource == Resource::"cra65-otpdemo-action-enterprise-integration-service-enterprise-integration-service" || resource == Resource::"cra65-otpdemo.action.EnterpriseIntegrationService-EnterpriseIntegrationService" || resource == Resource::"cra65_otpdemo.action.EnterpriseIntegrationService-EnterpriseIntegrationService" || resource == Resource::"cra65_otpdemo_action_enterprise_integration_service_enterprise_integration_service" || resource == Resource::"delete-database-row" || resource == Resource::"deleteDatabaseRow" || resource == Resource::"delete_database_row" || resource == Resource::"enterprise-integration-service-enterprise-integration-service" || resource == Resource::"enterprise_integration_service_enterprise_integration_service" || resource == Resource::"shared_cra655fenterprise20integration20service5ff" || resource == Resource::"template-content-action-enterprise-integration-service-enterprise-integration-service" || resource == Resource::"template-content-connectionreference-cra65-otpdemo-shared-cra655fenterprise20integration20service5ff" || resource == Resource::"template-content.action.EnterpriseIntegrationServiceEnterpriseIntegrationService" || resource == Resource::"template-content.connectionreference.cra65-otpdemo.shared-cra655fenterprise20integration20service5ff" || resource == Resource::"template-content.connectionreference.cra65_otpdemo.shared_cra655fenterprise20integration20service5ff" || resource == Resource::"template_content_action_enterprise_integration_service_enterprise_integration_service" || resource == Resource::"template_content_connectionreference_cra65_otpdemo_shared_cra655fenterprise20integration20service5ff"
};

