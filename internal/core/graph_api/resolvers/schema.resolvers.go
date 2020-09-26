// nolint:lll
package resolvers

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.

import (
	"context"
	"fmt"

	"github.com/panther-labs/panther/internal/core/graph_api/generated"
	"github.com/panther-labs/panther/internal/core/graph_api/models"
)

func (r *mutationResolver) AddDestination(ctx context.Context, input models.DestinationInput) (*models.Destination, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) AddComplianceIntegration(ctx context.Context, input models.AddComplianceIntegrationInput) (*models.ComplianceIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) AddS3LogIntegration(ctx context.Context, input models.AddS3LogIntegrationInput) (*models.S3LogIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) AddSqsLogIntegration(ctx context.Context, input models.AddSqsLogIntegrationInput) (*models.SqsLogSourceIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) AddPolicy(ctx context.Context, input models.AddPolicyInput) (*models.PolicyDetails, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) AddRule(ctx context.Context, input models.AddRuleInput) (*models.RuleDetails, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) AddGlobalPythonModule(ctx context.Context, input models.AddGlobalPythonModuleInput) (*models.GlobalPythonModule, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeleteDestination(ctx context.Context, id string) (*bool, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeleteComplianceIntegration(ctx context.Context, id string) (*bool, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeleteLogIntegration(ctx context.Context, id string) (*bool, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeletePolicy(ctx context.Context, input models.DeletePolicyInput) (*bool, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeleteRule(ctx context.Context, input models.DeleteRuleInput) (*bool, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeleteGlobalPythonModule(ctx context.Context, input models.DeleteGlobalPythonModuleInput) (*bool, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeleteUser(ctx context.Context, id string) (*bool, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) InviteUser(ctx context.Context, input *models.InviteUserInput) (*models.User, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) RemediateResource(ctx context.Context, input models.RemediateResourceInput) (*bool, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) DeliverAlert(ctx context.Context, input models.DeliverAlertInput) (*models.AlertSummary, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) ResetUserPassword(ctx context.Context, id string) (*models.User, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) SuppressPolicies(ctx context.Context, input models.SuppressPoliciesInput) (*bool, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) TestPolicy(ctx context.Context, input *models.TestPolicyInput) (*models.TestPolicyResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateAlertStatus(ctx context.Context, input models.UpdateAlertStatusInput) (*models.AlertSummary, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateDestination(ctx context.Context, input models.DestinationInput) (*models.Destination, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateComplianceIntegration(ctx context.Context, input models.UpdateComplianceIntegrationInput) (*models.ComplianceIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateS3LogIntegration(ctx context.Context, input models.UpdateS3LogIntegrationInput) (*models.S3LogIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateSqsLogIntegration(ctx context.Context, input models.UpdateSqsLogIntegrationInput) (*models.SqsLogSourceIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateGeneralSettings(ctx context.Context, input models.UpdateGeneralSettingsInput) (*models.GeneralSettings, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdatePolicy(ctx context.Context, input models.UpdatePolicyInput) (*models.PolicyDetails, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateRule(ctx context.Context, input models.UpdateRuleInput) (*models.RuleDetails, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateUser(ctx context.Context, input models.UpdateUserInput) (*models.User, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UploadPolicies(ctx context.Context, input models.UploadPoliciesInput) (*models.UploadPoliciesResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *mutationResolver) UpdateGlobalPythonlModule(ctx context.Context, input models.ModifyGlobalPythonModuleInput) (*models.GlobalPythonModule, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Alert(ctx context.Context, input models.GetAlertInput) (*models.AlertDetails, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Alerts(ctx context.Context, input *models.ListAlertsInput) (*models.ListAlertsResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) SendTestAlert(ctx context.Context, input models.SendTestAlertInput) ([]*models.DeliveryResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Destination(ctx context.Context, id string) (*models.Destination, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Destinations(ctx context.Context) ([]*models.Destination, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) GeneralSettings(ctx context.Context) (*models.GeneralSettings, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) GetComplianceIntegration(ctx context.Context, id string) (*models.ComplianceIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) GetComplianceIntegrationTemplate(ctx context.Context, input models.GetComplianceIntegrationTemplateInput) (*models.IntegrationTemplate, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) GetS3LogIntegration(ctx context.Context, id string) (*models.S3LogIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) GetS3LogIntegrationTemplate(ctx context.Context, input models.GetS3LogIntegrationTemplateInput) (*models.IntegrationTemplate, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) GetSqsLogIntegration(ctx context.Context, id string) (*models.SqsLogSourceIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Remediations(ctx context.Context) (*string, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Resource(ctx context.Context, input models.GetResourceInput) (*models.ResourceDetails, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Resources(ctx context.Context, input *models.ListResourcesInput) (*models.ListResourcesResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) ResourcesForPolicy(ctx context.Context, input models.ResourcesForPolicyInput) (*models.ListComplianceItemsResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) GetGlobalPythonModule(ctx context.Context, input models.GetGlobalPythonModuleInput) (*models.GlobalPythonModule, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Policy(ctx context.Context, input models.GetPolicyInput) (*models.PolicyDetails, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Policies(ctx context.Context, input *models.ListPoliciesInput) (*models.ListPoliciesResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) PoliciesForResource(ctx context.Context, input *models.PoliciesForResourceInput) (*models.ListComplianceItemsResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) ListAvailableLogTypes(ctx context.Context) (*models.ListAvailableLogTypesResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) ListComplianceIntegrations(ctx context.Context) ([]*models.ComplianceIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) ListLogIntegrations(ctx context.Context) ([]models.LogIntegration, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) OrganizationStats(ctx context.Context, input *models.OrganizationStatsInput) (*models.OrganizationStatsResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) GetLogAnalysisMetrics(ctx context.Context, input models.LogAnalysisMetricsInput) (*models.LogAnalysisMetricsResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Rule(ctx context.Context, input models.GetRuleInput) (*models.RuleDetails, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Rules(ctx context.Context, input *models.ListRulesInput) (*models.ListRulesResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) ListGlobalPythonModules(ctx context.Context, input models.ListGlobalPythonModuleInput) (*models.ListGlobalPythonModulesResponse, error) {
	panic(fmt.Errorf("not implemented"))
}

func (r *queryResolver) Users(ctx context.Context) ([]*models.User, error) {
	panic(fmt.Errorf("not implemented"))
}

// Mutation returns generated.MutationResolver implementation.
func (r *Resolver) Mutation() generated.MutationResolver { return &mutationResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
