package forwarder

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

import (
	"errors"

	"github.com/aws/aws-lambda-go/events"
)

type ComplianceChange struct {
	ChangeType       string
	IntegrationID    string
	IntegrationLabel string
	LastUpdated      string
	PolicyID         string
	PolicySeverity   string
	ResourceID       string
	ResourceType     string
	Status           string
	Suppressed       bool
}

func (sh StreamHandler) processComplianceSnapshot(record events.DynamoDBEventRecord) (*ComplianceChange, error) {
	var newComplianceStatus *ComplianceChange
	var err error

	switch record.EventName {
	case string(events.DynamoDBOperationTypeInsert):
		newComplianceStatus, err = dynamoRecordToCompliance(record.Change.NewImage)
		if err != nil {
			return nil, err
		}
		newComplianceStatus.ChangeType = ChangeTypeCreate
	case string(events.DynamoDBOperationTypeRemove):
		newComplianceStatus, err = dynamoRecordToCompliance(record.Change.OldImage)
		if err != nil {
			return nil, err
		}
		newComplianceStatus.ChangeType = ChangeTypeDelete
	case string(events.DynamoDBOperationTypeModify):
		newComplianceStatus, err = dynamoRecordToCompliance(record.Change.NewImage)
		if err != nil {
			return nil, err
		}
		newComplianceStatus.ChangeType = ChangeTypeModify
		oldStatus, err := dynamoRecordToCompliance(record.Change.OldImage)
		if err != nil {
			return nil, err
		}
		// If the status didn't change and the suppression didn't change, no need to report anything
		if newComplianceStatus.ChangeType == oldStatus.Status && newComplianceStatus.Suppressed == oldStatus.Suppressed {
			return nil, nil
		}
	}

	newComplianceStatus.IntegrationLabel, err = sh.getIntegrationLabel(newComplianceStatus.IntegrationID)
	return newComplianceStatus, err
}

func dynamoRecordToCompliance(image map[string]events.DynamoDBAttributeValue) (*ComplianceChange, error) {
	if !validateDynamoRecordAsCompliance(image) {
		return nil, errors.New("unexpected compliance record image format")
	}

	return &ComplianceChange{
		IntegrationID:  image["integrationId"].String(),
		LastUpdated:    image["lastUpdated"].String(),
		PolicyID:       image["policyId"].String(),
		PolicySeverity: image["policySeverity"].String(),
		ResourceID:     image["resourceId"].String(),
		ResourceType:   image["resourceType"].String(),
		Status:         image["status"].String(),
		Suppressed:     image["suppressed"].Boolean(),
	}, nil
}

func validateDynamoRecordAsCompliance(image map[string]events.DynamoDBAttributeValue) bool {
	return image != nil &&
		image["integrationId"].DataType() == events.DataTypeString &&
		image["lastUpdated"].DataType() == events.DataTypeString &&
		image["policyId"].DataType() == events.DataTypeString &&
		image["policySeverity"].DataType() == events.DataTypeString &&
		image["resourceId"].DataType() == events.DataTypeString &&
		image["resourceType"].DataType() == events.DataTypeString &&
		image["status"].DataType() == events.DataTypeString &&
		image["suppressed"].DataType() == events.DataTypeBoolean
}
