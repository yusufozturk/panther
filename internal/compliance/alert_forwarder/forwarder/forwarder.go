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
	"crypto/md5"
	"encoding/hex"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/delivery/models"
)

var (
	alertQueueURL                 = os.Getenv("ALERTING_QUEUE_URL")
	awsSession                    = session.Must(session.NewSession())
	sqsClient     sqsiface.SQSAPI = sqs.New(awsSession)
)

// Handle forwards an alert to the alert delivery SQS queue
func Handle(event *models.Alert) error {
	// First, store the event
	if err := storeNewAlert(event); err != nil {
		return errors.Wrap(err, "failed to store new alert in DDB")
	}
	zap.L().Info("received alert", zap.Stringp("AlertID", event.AlertID))                         // null
	zap.L().Info("received alert", zap.String("AnalysisID", event.AnalysisID))                    // AWS.S3.Bucket.SecureAccess
	zap.L().Info("received alert", zap.Stringp("AnalysisDescription", event.AnalysisDescription)) //Ensures access to S3 buckets is forced to use a secure (HTTPS) connection.
	zap.L().Info("received alert", zap.Stringp("AnalysisName", event.AnalysisName))               // AWS S3 Bucket Secure Access
	zap.L().Info("received alert", zap.Time("CreatedAt", event.CreatedAt))                        //1603556219.8417847
	zap.L().Info("received alert", zap.Bool("IsResent", event.IsResent))                          // false
	zap.L().Info("received alert", zap.Bool("IsTest", event.IsTest))                              // false
	zap.L().Info("received alert", zap.Any("LogTypes", event.LogTypes))                           // []
	zap.L().Info("received alert", zap.Any("OutputIds", event.OutputIds))                         // []
	zap.L().Info("received alert", zap.Int("RetryCount", event.RetryCount))                       // 0
	zap.L().Info("received alert", zap.Stringp("Runbook", event.Runbook))                         // https://docs.runpanther.io/cloud-security/built-in-policy-runbooks/aws-s3-bucket-policy-enforces-secure-access
	zap.L().Info("received alert", zap.String("Severity", event.Severity))                        // LOW
	zap.L().Info("received alert", zap.Any("Tags", event.Tags))                                   // ["AWS","Security Control"]
	zap.L().Info("received alert", zap.Stringp("Title", event.Title))                             // null
	zap.L().Info("received alert", zap.Any("Type", event.Type))                                   // POLICY
	zap.L().Info("received alert", zap.Stringp("Version", event.Version))                         // G7uiAqlQ400sIfX5Vko2VKss9k36S483

	// {
	// 	id: 'AWS.S3.Bucket.SecureAccess',
	// 	createdAt: '2020-10-24T16:16:59.841784856Z',
	// 	severity: 'LOW',
	// 	type: 'POLICY',
	// 	link: 'https://web-129425591.us-west-2.elb.amazonaws.com/cloud-security/policies/AWS.S3.Bucket.SecureAccess',
	// 	title: 'Policy Failure: AWS S3 Bucket Secure Access',
	// 	name: 'AWS S3 Bucket Secure Access',
	// 	alertId: null,
	// 	description: 'Ensures access to S3 buckets is forced to use a secure (HTTPS) connection.\n',
	// 	runbook: 'https://docs.runpanther.io/cloud-security/built-in-policy-runbooks/aws-s3-bucket-policy-enforces-secure-access\n',
	// 	tags: [ 'AWS', 'Security Control' ],
	// 	version: 'G7uiAqlQ400sIfX5Vko2VKss9k36S483'
	// }

	msgBody, err := jsoniter.Marshal(event)
	if err != nil {
		return err
	}
	input := &sqs.SendMessageInput{
		QueueUrl:    aws.String(alertQueueURL),
		MessageBody: aws.String(string(msgBody)),
	}
	_, err = sqsClient.SendMessage(input)
	if err != nil {
		zap.L().Warn("failed to send message to remediation", zap.Error(err))
		return err
	}
	zap.L().Info("successfully triggered alert action")

	return nil
}

func storeNewAlert(event *models.Alert) error {
	// Make a shallow copy to mutate, we only need to genereate the AlertID
	alert := event
	alert.AlertID = aws.String(generateAlertID(event))

	marshaledAlert, err := dynamodbattribute.MarshalMap(alert)
	if err != nil {
		return errors.Wrap(err, "failed to marshal alert")
	}
	putItemRequest := &dynamodb.PutItemInput{
		Item:      marshaledAlert,
		TableName: &h.AlertTable,
	}
	_, err = h.DdbClient.PutItem(putItemRequest)
	if err != nil {
		return errors.Wrap(err, "failed to store alert")
	}

	return nil
}

func generateAlertID(event *models.Alert) string {
	key := event.AnalysisID + ":" + event.CreatedAt.String()
	keyHash := md5.Sum([]byte(key)) // nolint(gosec)
	return hex.EncodeToString(keyHash[:])
}
