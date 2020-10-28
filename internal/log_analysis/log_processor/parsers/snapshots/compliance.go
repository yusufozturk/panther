package snapshots

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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"github.com/aws/aws-sdk-go/aws/arn"
	jsoniter "github.com/json-iterator/go"

	pollerutils "github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeCompliance = "Snapshot.ComplianceHistory"

type ComplianceHistoryParser struct{}

func NewComplianceParser() *ComplianceHistoryParser {
	return &ComplianceHistoryParser{}
}

func (p *ComplianceHistoryParser) New() parsers.LogParser {
	return p
}
func (p *ComplianceHistoryParser) LogType() string {
	return TypeCompliance
}
func (p *ComplianceHistoryParser) Parse(log string) ([]*parsers.PantherLog, error) {
	complianceState := Compliance{}
	if err := jsoniter.UnmarshalFromString(log, &complianceState); err != nil {
		return nil, err
	}
	complianceState.updatePantherFields(&complianceState.PantherLog)
	if err := parsers.Validator.Struct(&complianceState); err != nil {
		return nil, err
	}
	return complianceState.Logs(), nil
}

// nolint:lll
type Compliance struct {
	ChangeType       string            `json:"changeType" validate:"required,oneof=created deleted modified sync" description:"The type of change that initiated this snapshot creation."`
	IntegrationID    string            `json:"integrationId" validate:"required" description:"The unique source ID of the account this resource lives in."`
	IntegrationLabel string            `json:"integrationLabel" validate:"required" description:"The friendly source name of the account this resource lives in."`
	LastUpdated      timestamp.RFC3339 `json:"lastUpdated" validate:"required" description:"The time this snapshot occurred."`
	PolicyID         string            `json:"policyId" validate:"required" description:"The unique ID of the policy evaluating the resource."`
	PolicySeverity   string            `json:"policySeverity" validate:"required" description:"The severity of the policy evaluating the resource."`
	ResourceID       string            `json:"resourceId" validate:"required" description:"The unique Panther ID of the resource being evaluated."`
	ResourceType     string            `json:"resourceType" validate:"required" description:"The type of resource being evaluated."`
	Status           string            `json:"status" validate:"required,oneof=PASS FAIL ERROR" description:"Whether this resource is passing, failing, or erroring on this policy."`
	Suppressed       *bool             `json:"suppressed" validate:"required" description:"Whether this resource is being ignored for the purpose of reports."`

	awslogs.AWSPantherLog
}

func (e *Compliance) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeCompliance, &e.LastUpdated, e)
	// This is usually (but not always) an ARN. If it's not an ARN, it's in a format we define in
	// the snapshot-poller function
	parsedARN, err := arn.Parse(e.ResourceID)
	if err != nil {
		pantherID := pollerutils.ParseResourceID(e.ResourceID)
		if pantherID != nil && pantherID.AccountID != "" {
			e.AppendAnyAWSAccountIds(pantherID.AccountID)
		}
		return
	}
	e.AppendAnyAWSARNs(e.ResourceID)
	e.AppendAnyAWSAccountIds(parsedARN.AccountID)
}
