package datacatalog

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
	"context"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
	"github.com/panther-labs/panther/pkg/lambdalogger"
	"github.com/panther-labs/panther/pkg/stringset"
)

func (h *LambdaHandler) HandleS3Event(ctx context.Context, event *events.S3Event) (err error) {
	logger := lambdalogger.FromContext(ctx)
	// At the end of processing the messages ensure any notifications are sent to the compactor
	defer func() {
		partitions := h.resetBatchS3Partitions()
		if sendErr := sendCompactorBatch(ctx, h.SQSClient, h.CompactorQueueURL, partitions); sendErr != nil {
			logger.Error("failed to send compactor notifications",
				zap.Error(err),
				zap.String("queueURL", h.CompactorQueueURL),
				zap.Strings("partitions", partitions),
			)
			// Make sure any error sending the compactor notification is reported as well
			err = multierr.Append(err, sendErr)
		}
	}()
	if len(event.Records) == 0 { // indications of a bug someplace
		logger.Warn("no s3 event notifications in message", zap.Any("message", &event))
		return
	}
	for i := range event.Records {
		s3Event := &event.Records[i]
		if e := h.HandleS3EventRecord(ctx, s3Event); e != nil {
			err = multierr.Append(err, e)
		}
	}
	return
}

func (h *LambdaHandler) HandleS3EventRecord(ctx context.Context, event *events.S3EventRecord) error {
	bucketName := event.S3.Bucket.Name
	objectKey := event.S3.Object.Key
	partition, err := awsglue.GetPartitionFromS3(bucketName, objectKey)
	if err != nil {
		lambdalogger.FromContext(ctx).Warn("invalid S3 event", zap.Any("event", event))
		return nil
	}
	partitionURL := partition.GetPartitionLocation()
	if _, created := h.partitionsCreated[partitionURL]; created {
		h.addBatchS3Partition(partitionURL)
		return nil
	}
	partitionTime := partition.GetTime()
	tableMeta := partition.GetGlueTableMetadata()
	if _, err := tableMeta.CreateJSONPartition(h.GlueClient, partitionTime); err != nil {
		return err
	}
	// Store partition in cache as successfully created
	if h.partitionsCreated == nil {
		h.partitionsCreated = make(map[string]string)
	}
	h.partitionsCreated[partitionURL] = partitionURL

	// Store partition URL to notify compactor
	h.addBatchS3Partition(partitionURL)
	return nil
}

func (h *LambdaHandler) addBatchS3Partition(partition string) {
	h.batchS3Partitions = stringset.Append(h.batchS3Partitions, partition)
}
func (h *LambdaHandler) resetBatchS3Partitions() (partitions []string) {
	partitions, h.batchS3Partitions = h.batchS3Partitions, h.batchS3Partitions[:0]
	return
}

func sendCompactorBatch(_ context.Context, sqsAPI sqsiface.SQSAPI, queueURL string, partitions []string) error {
	if len(partitions) == 0 {
		return nil
	}
	batch := newCompactorBatch(queueURL, partitions...)
	_, err := sqsbatch.SendMessageBatch(sqsAPI, time.Minute, batch)
	if err != nil {
		return errors.Wrap(err, "failed to send compactor notifications")
	}
	return nil
}

func newCompactorBatch(queueURL string, partitions ...string) *sqs.SendMessageBatchInput {
	batch := sqs.SendMessageBatchInput{
		QueueUrl: aws.String(queueURL),
	}
	groupID := aws.String("partitions")
	for i, partitionURL := range partitions {
		batch.Entries = append(batch.Entries, &sqs.SendMessageBatchRequestEntry{
			Id:             aws.String(strconv.Itoa(i)),
			MessageBody:    aws.String(partitionURL),
			MessageGroupId: groupID,
		})
	}
	return &batch
}
