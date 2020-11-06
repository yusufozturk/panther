package common

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
	"io"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/lambda/lambdaiface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/sns/snsiface"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/kelseyhightower/envconfig"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/awsretry"
)

const (
	MaxRetries     = 13 // ~7'
	EventDelimiter = '\n'
)

var (
	// Session and clients that can be used by components of the log processor
	// FIXME: these should be removed as globals
	Session      *session.Session
	LambdaClient lambdaiface.LambdaAPI
	S3Uploader   s3manageriface.UploaderAPI
	SqsClient    sqsiface.SQSAPI
	SnsClient    snsiface.SNSAPI

	Config EnvConfig
)

type EnvConfig struct {
	AwsLambdaFunctionMemorySize int    `required:"true" split_words:"true"`
	ProcessedDataBucket         string `required:"true" split_words:"true"`
	SqsQueueURL                 string `required:"true" split_words:"true"`
	SnsTopicARN                 string `required:"true" split_words:"true"`
}

func Setup() {
	Session = session.Must(session.NewSession()) // use default retries for fetching creds, avoids hangs!
	clientsSession := Session.Copy(request.WithRetryer(aws.NewConfig().WithMaxRetries(MaxRetries),
		awsretry.NewConnectionErrRetryer(MaxRetries)))
	LambdaClient = lambda.New(clientsSession)
	S3Uploader = s3manager.NewUploader(clientsSession)
	SqsClient = sqs.New(clientsSession)
	SnsClient = sns.New(clientsSession)

	err := envconfig.Process("", &Config)
	if err != nil {
		panic(err)
	}
}

// DataStream represents a data stream that read by the processor
type DataStream struct {
	Reader      io.Reader
	Source      *models.SourceIntegration
	S3ObjectKey string
	S3Bucket    string
}
