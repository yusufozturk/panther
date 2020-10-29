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
	"github.com/aws/aws-lambda-go/events"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/compliance/datalake_forwarder/utils"
	"github.com/panther-labs/panther/pkg/awsevents"
)

type CloudSecuritySnapshotChange struct {
	ChangeType       string
	Changes          map[string]utils.Diff
	IntegrationID    string
	IntegrationLabel string
	LastUpdated      string
	Resource         string
}

func (sh StreamHandler) processResourceSnapshotDiff(record events.DynamoDBEventRecord) (*CloudSecuritySnapshotChange, error) {
	if record.Change.NewImage == nil || record.Change.OldImage == nil {
		return nil, errors.New("expected Change.NewImage and Change.OldImage to not be nil when processing resource diff")
	}
	if _, ok := record.Change.OldImage["attributes"]; !ok {
		return nil, errors.New("resources-table record old image did include top level key attributes")
	}
	if _, ok := record.Change.NewImage["attributes"]; !ok {
		return nil, errors.New("resources-table record new image did include top level key attributes")
	}

	// First convert the old & new image from the useless dynamodb stream format into a JSON string
	newImageJSON, err := awsevents.DynamoAttributeToJSON("", "", record.Change.NewImage["attributes"])
	if err != nil {
		return nil, errors.WithMessage(err, "error parsing new resource snapshot")
	}
	oldImageJSON, err := awsevents.DynamoAttributeToJSON("", "", record.Change.OldImage["attributes"])
	if err != nil {
		return nil, errors.WithMessage(err, "error parsing old resource snapshot")
	}

	// Do a very rudimentary JSON diff to determine which top level fields have changed
	changes, err := utils.CompJsons(oldImageJSON, newImageJSON)
	if err != nil {
		return nil, errors.WithMessage(err, "error comparing old resource snapshot with new resource snapshot")
	}
	zap.L().Debug(
		"processing resource record",
		zap.Any("record.EventName", record.EventName),
		zap.Any("newImage", newImageJSON),
		zap.Any("changes", changes),
		zap.Error(err),
	)

	// If nothing changed, no need to report it
	if changes == nil {
		return nil, nil
	}

	return sh.appendResourceMetaData(record.Change.NewImage, &CloudSecuritySnapshotChange{
		Resource:   newImageJSON,
		Changes:    changes,
		ChangeType: ChangeTypeModify,
	})
}

func (sh StreamHandler) processResourceSnapshot(record events.DynamoDBEventRecord) (*CloudSecuritySnapshotChange, error) {
	var image map[string]events.DynamoDBAttributeValue
	var changeType string
	if record.EventName == string(events.DynamoDBOperationTypeInsert) {
		image = record.Change.NewImage
		changeType = ChangeTypeCreate
	}
	if record.EventName == string(events.DynamoDBOperationTypeRemove) {
		image = record.Change.OldImage
		changeType = ChangeTypeDelete
	}
	if image == nil {
		return nil, errors.New("expected Image to not be nil when processing resource diff")
	}

	if _, ok := image["attributes"]; !ok {
		return nil, errors.New("resources-table record image did include top level key attributes")
	}
	parsedImage, err := awsevents.DynamoAttributeToJSON("", "", image["attributes"])
	if err != nil {
		return nil, err
	}
	return sh.appendResourceMetaData(image, &CloudSecuritySnapshotChange{
		Resource:   parsedImage,
		ChangeType: changeType,
	})
}

func (sh StreamHandler) appendResourceMetaData(
	image map[string]events.DynamoDBAttributeValue,
	snapshot *CloudSecuritySnapshotChange) (*CloudSecuritySnapshotChange, error) {

	lastModified, ok := image["lastModified"]
	if !ok || lastModified.DataType() != events.DataTypeString {
		return nil, errors.New("could not extract lastModified as string from resource image")
	}
	integrationID, ok := image["integrationId"]
	if !ok || integrationID.DataType() != events.DataTypeString {
		return nil, errors.New("could not extract integrationId as string from resource image")
	}

	snapshot.LastUpdated = lastModified.String()
	snapshot.IntegrationID = integrationID.String()
	var err error
	snapshot.IntegrationLabel, err = sh.getIntegrationLabel(snapshot.IntegrationID)
	return snapshot, err
}
