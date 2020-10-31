package processor

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
	"runtime"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/destinations"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/sources"
	"github.com/panther-labs/panther/pkg/awsbatch/sqsbatch"
)

const (
	// Limit this so there is time to delete from the queue at the end.
	processingMaxFilesLimit = 5000

	// The processing runtime should be shorter than lambda timeout to make room to flush buffers ad the end of the cycle.
	processingTimeLimitDivisor = 2

	// The max messages per read for SQS (can't find an sqs constant to refer to).
	sqsMaxBatchSize = 10
)

/*
StreamEvents acts as an interface to aggregate sqs messages to avoid many small S3 files being created under load.
The function will attempt to read more messages from the queue when the queue has messages. Under load
the lambda will continue to read events and maximally aggregate data to produce fewer, bigger files.
Fewer, bigger files makes Athena queries much faster.
*/
func StreamEvents(
	ctx context.Context,
	sqsClient sqsiface.SQSAPI,
	lambdaClient lambdaiface.LambdaAPI,
	resolver logtypes.Resolver,
	deadlineTime time.Time,
) (sqsMessageCount int, err error) {

	newProcessor := NewFactory(resolver)
	process := func(streams <-chan *common.DataStream, dest destinations.Destination) error {
		return Process(streams, dest, newProcessor)
	}
	return streamEvents(ctx, sqsClient, lambdaClient, deadlineTime, process, sources.ReadSnsMessages)
}

// entry point for unit testing, pass in read/process functions
func streamEvents(
	ctx context.Context,
	sqsClient sqsiface.SQSAPI,
	lambdaClient lambdaiface.LambdaAPI,
	deadlineTime time.Time,
	processFunc ProcessFunc,
	generateDataStreamsFunc func(string) ([]*common.DataStream, error)) (int, error) {

	streamChan := make(chan *common.DataStream, 2*sqsMaxBatchSize) // use small buffer to pipeline events
	processingDeadlineTime := processingDeadlineTime(deadlineTime)

	var accumulatedMessageReceipts []*string // accumulate message receipts for delete at the end
	group, _ := errgroup.WithContext(ctx)
	group.Go(func() error {
		ctx, cancel := context.WithCancel(ctx)
		// runs periodically during processing making scaling decisions
		scalingDecisions(ctx, sqsClient, lambdaClient)
		defer func() {
			cancel() // cancel scaling Decisions
			close(streamChan) // done reading messages, this will cause processFunc() to return
		}()

		// continue to read until either there are no sqs messages or we have exceeded the processing time/file limit
		highMemoryCounter := 0
		for isProcessingTimeRemaining(processingDeadlineTime) && len(accumulatedMessageReceipts) < processingMaxFilesLimit {
			// if we push too fast we can oom
			if heapUsedMB, memAvailableMB, isHigh := highMemoryUsage(); isHigh {
				if highMemoryCounter%100 == 0 { // limit logging
					zap.L().Warn("high memory usage",
						zap.Float32("heapUsedDB", heapUsedMB),
						zap.Float32("memAvailableDB", memAvailableMB),
						zap.Int("sqsMessagesRead", len(accumulatedMessageReceipts)))
				}
				time.Sleep(time.Second)
				highMemoryCounter++
				continue
			}

			// under no load we do not read from the sqs queue and just exit
			totalQueuedMessages, err := queueDepth(ctx, sqsClient) // this includes queued and delayed messages
			if err != nil {
				return err
			}
			if totalQueuedMessages == 0 {
				break
			}

			// keep reading from SQS to maximize output aggregation
			messages, err := sqsbatch.ReceiveMessage(sqsClient, common.Config.SqsQueueURL, 0)
			if err != nil {
				return err
			}

			if len(messages) == 0 { // no work to do but maybe more later OR reached the max sqs messages allowed in flight, either way need to break
				break
			}

			for _, msg := range messages {
				accumulatedMessageReceipts = append(accumulatedMessageReceipts, msg.ReceiptHandle)
				dataStreams, err := generateDataStreamsFunc(*msg.Body)
				if err != nil {
					return err
				}
				for _, dataStream := range dataStreams {
					streamChan <- dataStream
				}
			}
		}
		return nil
	})

	// Use a properly configured JSON API for Athena quirks
	jsonAPI := common.BuildJSON()
	// process streamChan until closed (blocks)
	dest := destinations.CreateS3Destination(jsonAPI)
	if err := processFunc(streamChan, dest); err != nil {
		return 0, err
	}
	if err := group.Wait(); err != nil {
		return 0, err
	}

	// delete messages from sqs q on success (best effort)
	sqsbatch.DeleteMessageBatch(sqsClient, common.Config.SqsQueueURL, accumulatedMessageReceipts)
	return len(accumulatedMessageReceipts), nil
}

// processingDeadlineTime calcs a time less than the deadllineTime to allow time for buffers to flush
func processingDeadlineTime(deadlineTime time.Time) time.Time {
	// NOTE: time.Since(deadlineTime) will be negative since the deadline is in the future!
	return deadlineTime.Add(time.Since(deadlineTime) / processingTimeLimitDivisor)
}

func isProcessingTimeRemaining(deadline time.Time) bool {
	return time.Since(deadline) < 0 // deadline is in future, will be positive once passed
}

func queueDepth(ctx context.Context, sqsClient sqsiface.SQSAPI) (totalQueuedMessages int, err error) {
	getQueueAttributesInput := &sqs.GetQueueAttributesInput{
		AttributeNames: []*string{
			aws.String(sqs.QueueAttributeNameApproximateNumberOfMessages), // tells us there is waiting events now
		},
		QueueUrl: &common.Config.SqsQueueURL,
	}
	getQueueAttributesOutput, err := sqsClient.GetQueueAttributesWithContext(ctx, getQueueAttributesInput)
	if err != nil {
		err = errors.Wrapf(err, "failure getting message count from %s", common.Config.SqsQueueURL)
		return 0, err
	}
	// number of messages
	numberOfQueuedMessages, err := getQueueIntegerAttribute(getQueueAttributesOutput.Attributes,
		sqs.QueueAttributeNameApproximateNumberOfMessages)
	if err != nil {
		return 0, err
	}

	return numberOfQueuedMessages, err
}

func getQueueIntegerAttribute(attrs map[string]*string, attr string) (count int, err error) {
	intAsStringPtr := attrs[attr]
	if intAsStringPtr == nil {
		err = errors.Errorf("failure getting %s count from %s", attr, common.Config.SqsQueueURL)
		return 0, err
	}
	count, err = strconv.Atoi(*intAsStringPtr)
	if err != nil {
		err = errors.Wrapf(err, "failure reading %s (%s) count from %s", attr, *intAsStringPtr, common.Config.SqsQueueURL)
		return 0, err
	}
	return count, err
}

func highMemoryUsage() (heapUsedMB, memAvailableMB float32, isHigh bool) {
	const (
		threshold  = 0.8
		bytesPerMB = 1024 * 1024
	)
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	// NOTE: HeapAlloc is used because it tracks memory release better/faster than Sys
	heapUsedMB = float32(memStats.HeapAlloc / bytesPerMB)
	memAvailableMB = float32(common.Config.AwsLambdaFunctionMemorySize)
	return heapUsedMB, memAvailableMB, heapUsedMB/memAvailableMB > threshold
}
