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
	"context"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/firehose"
	"github.com/aws/aws-sdk-go/service/firehose/firehoseiface"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/kelseyhightower/envconfig"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/pkg/awsbatch/firehosebatch"
	"github.com/panther-labs/panther/pkg/awsretry"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/oplog"
)

const (
	ChangeTypeCreate = "created"
	ChangeTypeDelete = "deleted"
	ChangeTypeModify = "modified"
	// TODO add daily syncs
	// ChangeTypeSync   = "sync"

	maxRetries      = 10
	recordDelimiter = '\n'
)

type EnvConfig struct {
	StreamName string `required:"true" split_words:"true"`
}

type StreamHandler struct {
	firehoseClient firehoseiface.FirehoseAPI
	lambdaClient   lambdaiface.LambdaAPI
	config         EnvConfig
}

func NewStreamhandler() StreamHandler {
	var sh StreamHandler

	envconfig.MustProcess("", &sh.config)
	awsSession := session.Must(session.NewSession(request.WithRetryer(aws.NewConfig().WithMaxRetries(maxRetries),
		awsretry.NewConnectionErrRetryer(maxRetries))))
	sh.firehoseClient = firehose.New(awsSession)
	sh.lambdaClient = lambda.New(awsSession)
	return sh
}

// Run is the entry point for the datalake-forwarder lambda
func (sh StreamHandler) Run(ctx context.Context, event events.DynamoDBEvent) (err error) {
	lc, _ := lambdalogger.ConfigureGlobal(ctx, nil)
	operation := oplog.NewManager("cloudsec", "datalake_forwarder").Start(lc.InvokedFunctionArn).WithMemUsed(lambdacontext.MemoryLimitInMB)
	defer func() {
		operation.Stop().Log(err, zap.Int("numEvents", len(event.Records)))
	}()

	firehoseRecords := make([]*firehose.Record, 0, len(event.Records))
	for _, record := range event.Records {
		byteChanges := sh.getChanges(record)
		if byteChanges == nil {
			continue
		}
		byteChanges = append(byteChanges, recordDelimiter)
		firehoseRecords = append(firehoseRecords, &firehose.Record{Data: byteChanges})
	}

	if len(firehoseRecords) == 0 {
		zap.L().Debug("no records to process")
		return nil
	}

	// Maximum Kinesis Firehose batch put request is 4MB, but we may be processing much more than
	// that so we have to send in batches
	firehoseInput := firehose.PutRecordBatchInput{
		Records:            firehoseRecords,
		DeliveryStreamName: &sh.config.StreamName,
	}
	bigMessages, err := firehosebatch.BatchSend(ctx, sh.firehoseClient, firehoseInput, maxRetries)
	if len(bigMessages) > 0 {
		zap.L().Error("unable to send some records as they are too large", zap.Int("numRecords", len(bigMessages)))
	}
	return err
}

// getChanges routes stream records from the compliance-table and the resources-table to the correct
// handler
//
// This function does not return errors, because any error it encounters would not be retryable.
func (sh StreamHandler) getChanges(record events.DynamoDBEventRecord) []byte {
	// Figure out where this record came from
	parsedSource, err := arn.Parse(record.EventSourceArn)
	if err != nil {
		zap.L().Error("unable to parse event source ARN", zap.String("EventSourceArn", record.EventSourceArn))
		return nil
	}

	// If it came from the compliance-table, it is a compliance status change
	if strings.HasPrefix(parsedSource.Resource, "table/panther-compliance") {
		return sh.getComplianceChanges(record)
	}
	// Otherwise, it must have come from the resource-table
	return sh.getResourceChanges(record)
}

// getComplianceChanges processes a record from the compliance-table dynamoDB stream
//
// This function does not return errors, because any error it encounters would not be retryable
func (sh StreamHandler) getComplianceChanges(record events.DynamoDBEventRecord) []byte {
	changes, err := sh.processComplianceSnapshot(record)
	if err != nil {
		zap.L().Error("error processing compliance change", zap.Error(err))
		return nil
	}
	if changes == nil {
		return nil
	}
	byteChanges, err := jsoniter.Marshal(changes)
	if err != nil {
		zap.L().Error("error marshalling compliance changes to bytes", zap.Error(err))
		return nil
	}
	return byteChanges
}

// getResourceChanges processes a record from the resources-table dynamoDB stream,
//
// This function does not return errors, because any error it encounters would not be retryable
func (sh StreamHandler) getResourceChanges(record events.DynamoDBEventRecord) []byte {
	var snapshot *CloudSecuritySnapshotChange
	var err error
	// For INSERT and REMOVE events, we don't need to calculate a diff
	if record.EventName == string(events.DynamoDBOperationTypeInsert) || record.EventName == string(events.DynamoDBOperationTypeRemove) {
		snapshot, err = sh.processResourceSnapshot(record)
	} else {
		snapshot, err = sh.processResourceSnapshotDiff(record)
	}

	if err != nil {
		zap.L().Error("unable to process resource snapshot",
			zap.Error(err),
			zap.String("EventName", record.EventName),
		)
		zap.L().Debug("verbose error info",
			zap.Any("NewImage", record.Change.NewImage),
			zap.Any("OldImage", record.Change.OldImage))
		return nil
	}
	if snapshot == nil {
		return nil
	}

	byteChanges, err := jsoniter.Marshal(snapshot)
	if err != nil {
		zap.L().Error("error marshalling resource changes to bytes", zap.Error(err))
		return nil
	}
	return byteChanges
}
