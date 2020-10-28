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
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeResource = "Snapshot.ResourceHistory"

type ResourceHistoryParser struct{}

func NewResourceParser() *ResourceHistoryParser {
	return &ResourceHistoryParser{}
}

func (p *ResourceHistoryParser) New() parsers.LogParser {
	return p
}
func (p *ResourceHistoryParser) LogType() string {
	return TypeResource
}
func (p *ResourceHistoryParser) Parse(log string) ([]*parsers.PantherLog, error) {
	resource := Resource{}
	if err := jsoniter.UnmarshalFromString(log, &resource); err != nil {
		return nil, err
	}
	if err := jsoniter.UnmarshalFromString(resource.Resource, &resource.NormalizedFields); err != nil {
		return nil, err
	}
	resource.updatePantherFields(&resource.PantherLog)
	if err := parsers.Validator.Struct(&resource); err != nil {
		return nil, err
	}
	return resource.Logs(), nil
}

// nolint:lll
type Resource struct {
	ChangeType       string                         `json:"changeType" validate:"required,oneof=created deleted modified sync" description:"The type of change that initiated this snapshot creation."`
	Changes          map[string]jsoniter.RawMessage `json:"changes,omitempty" description:"The changes, if any, from the prior snapshot to this one."`
	IntegrationID    string                         `json:"integrationId" validate:"required" description:"The unique source ID of the account this resource lives in."`
	IntegrationLabel string                         `json:"integrationLabel" validate:"required" description:"The friendly source name of the account this resource lives in."`
	LastUpdated      timestamp.RFC3339              `json:"lastUpdated" validate:"required" description:"The time this snapshot occurred."`
	Resource         string                         `json:"resource,omitempty" description:"This object represents the state of the resource."`
	NormalizedFields SnapshotNormalizedFields       `json:"normalizedFields,omitempty" description:"This object represents normalized fields extracted by the scanner."`

	awslogs.AWSPantherLog
}

type SnapshotNormalizedFields struct {
	// Embedded from internal/compliance/snapshot_poller/models/aws/types.go
	ResourceID   string            `json:"ResourceId" description:"A panther wide unique identifier of the resource."`
	ResourceType string            `json:"ResourceType" description:"A panther defined resource type for the resource."`
	TimeCreated  timestamp.RFC3339 `json:"TimeCreated" description:"When this resource was created."`
	AccountID    string            `json:"AccountId" description:"The ID of the AWS Account the resource resides in."`
	Region       string            `json:"Region" description:"The region the resource exists in."`
	ARN          string            `json:"Arn,omitempty" description:"The Amazon Resource Name (ARN) of the resource."`
	ID           string            `json:"Id,omitempty" description:"The AWS resource identifier of the resource."`
	Name         string            `json:"Name,omitempty" description:"The AWS resource name of the resource."`
	Tags         map[string]string `json:"Tags,omitempty" description:"A standardized format for AWS key/value resource tags."`
}

func (e *Resource) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeResource, &e.LastUpdated, e)

	e.AppendAnyAWSARNs(e.NormalizedFields.ARN)
	e.AppendAnyAWSAccountIds(e.NormalizedFields.AccountID)

	if e.NormalizedFields.Tags != nil {
		tags := make([]string, 0, len(e.NormalizedFields.Tags))
		for key, value := range e.NormalizedFields.Tags {
			tags = append(tags, key+":"+value)
		}
		e.AppendAnyAWSTags(tags...)
	}
}
