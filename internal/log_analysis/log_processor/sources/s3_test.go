package sources

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
	"bufio"
	"bytes"
	"compress/gzip"
	"io/ioutil"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/common"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestParseCloudTrailNotification(t *testing.T) {
	notification := "{\"s3Bucket\": \"testbucket\", \"s3ObjectKey\": [\"key1\",\"key2\"]}"
	expectedOutput := []*S3ObjectInfo{
		{
			S3Bucket:    "testbucket",
			S3ObjectKey: "key1",
		},
		{
			S3Bucket:    "testbucket",
			S3ObjectKey: "key2",
		},
	}
	s3Objects, err := ParseNotification(notification)
	require.NoError(t, err)
	require.Equal(t, expectedOutput, s3Objects)
}

func TestParseS3Notification(t *testing.T) {
	//nolint:lll
	notification := "{\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"us-west-2\",\"eventTime\":\"1970-01-01T00:00:00.000Z\"," +
		"\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"AIDAJDPLRKLG7UEXAMPLE\"},\"requestParameters\":{\"sourceIPAddress\":\"127.0.0.1\"}," +
		"\"responseElements\":{\"x-amz-request-id\":\"C3D13FE58DE4C810\",\"x-amz-id-2\":\"FMyUVURIY8/IgAtTv8xRjskZQpcIZ9KG4V5Wp6S7S/JRWeUWerMUE5JgHvANOjpD\"}," +
		"\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"testConfigRule\"," +
		"\"bucket\":{\"name\":\"mybucket\",\"ownerIdentity\":{\"principalId\":\"A3NL1KOZZKExample\"},\"arn\":\"arn:aws:s3:::mybucket\"},\"object\":{\"key\":\"year%3D2020/key1\",\"size\":1024," +
		"\"eTag\":\"d41d8cd98f00b204e9800998ecf8427e\",\"versionId\":\"096fKKXTRTtl3on89fVO.nfljtsv6qko\",\"sequencer\":\"0055AED6DCD90281E5\"}}}]}"
	expectedOutput := []*S3ObjectInfo{
		{
			S3Bucket:    "mybucket",
			S3ObjectKey: "year=2020/key1",
		},
	}
	s3Objects, err := ParseNotification(notification)
	require.NoError(t, err)
	require.Equal(t, expectedOutput, s3Objects)
}

func TestParseTestS3Notification(t *testing.T) {
	//nolint:lll
	notification := "{\"Service\":\"Amazon S3\",\"Event\":\"s3:TestEvent\",\"Time\":\"2020-01-21T14:17:54.420Z\",\"Bucket\":\"test-bucket\"," +
		"\"RequestId\":\"0D79B9C057838DEA\",\"HostId\":\"6HTLml3u1UbsYgjuzueCQApRHOfpRM5yJ+nTZCveOMejyM7iB4Pg8RESbVAU5nHjduW+QoeK+UA=\"}"

	s3Objects, err := ParseNotification(notification)
	require.NoError(t, err)
	require.Equal(t, 0, len(s3Objects))
}

func TestParseCloudTrailValidationMessage(t *testing.T) {
	notification := "CloudTrail validation message."

	s3Objects, err := ParseNotification(notification)
	require.NoError(t, err)
	require.Equal(t, 0, len(s3Objects))
}

func TestParseUnknownMessage(t *testing.T) {
	notification := "Unknown message"

	_, err := ParseNotification(notification)
	require.Error(t, err)
}

func TestHandleUnsupportedFileType(t *testing.T) {
	resetCaches()
	// if we encounter an unsupported file type, we should just skip the object
	lambdaMock := &testutils.LambdaMock{}
	common.LambdaClient = lambdaMock

	s3Mock := &testutils.S3Mock{}
	newS3ClientFunc = func(region *string, creds *credentials.Credentials) (result s3iface.S3API) {
		return s3Mock
	}

	//nolint:lll
	s3Event := "{\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"us-west-2\",\"eventTime\":\"1970-01-01T00:00:00.000Z\"," +
		"\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"AIDAJDPLRKLG7UEXAMPLE\"},\"requestParameters\":{\"sourceIPAddress\":\"127.0.0.1\"}," +
		"\"responseElements\":{\"x-amz-request-id\":\"C3D13FE58DE4C810\",\"x-amz-id-2\":\"FMyUVURIY8/IgAtTv8xRjskZQpcIZ9KG4V5Wp6S7S/JRWeUWerMUE5JgHvANOjpD\"}," +
		"\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"testConfigRule\"," +
		"\"bucket\":{\"name\":\"mybucket\",\"ownerIdentity\":{\"principalId\":\"A3NL1KOZZKExample\"},\"arn\":\"arn:aws:s3:::mybucket\"},\"object\":{\"key\":\"test\",\"size\":1024," +
		"\"eTag\":\"d41d8cd98f00b204e9800998ecf8427e\",\"versionId\":\"096fKKXTRTtl3on89fVO.nfljtsv6qko\",\"sequencer\":\"0055AED6DCD90281E5\"}}}]}"

	notification := SnsNotification{}
	notification.Type = "Notification"
	notification.Message = s3Event
	marshaledNotification, err := jsoniter.MarshalToString(notification)
	require.NoError(t, err)

	integration = &models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			AWSAccountID:      "1234567890123",
			S3Bucket:          "mybucket",
			IntegrationType:   models.IntegrationTypeAWS3,
			LogProcessingRole: "arn:aws:iam::123456789012:role/PantherLogProcessingRole-suffix",
			IntegrationID:     "3e4b1734-e678-4581-b291-4b8a17621999",
		},
	}

	marshaledResult, err := jsoniter.Marshal([]*models.SourceIntegration{integration})
	require.NoError(t, err)
	lambdaOutput := &lambda.InvokeOutput{
		Payload: marshaledResult,
	}

	// First invocation should be to get the list of available sources
	lambdaMock.On("Invoke", mock.Anything).Return(lambdaOutput, nil).Once()
	// Second invocation would be to update the status
	lambdaMock.On("Invoke", mock.Anything).Return(&lambda.InvokeOutput{}, nil).Once()
	s3Mock.On("GetBucketLocation", mock.Anything).Return(
		&s3.GetBucketLocationOutput{LocationConstraint: aws.String("us-west-2")}, nil).Once()

	newCredentialsFunc = func(roleArn string) *credentials.Credentials {
		return &credentials.Credentials{}
	}

	objectData := []byte(`<?xml version="1.0" encoding="UTF-8" standalone="no" ?>`)
	getObjectOutput := &s3.GetObjectOutput{Body: ioutil.NopCloser(bytes.NewReader(objectData))}
	s3Mock.On("GetObject", mock.Anything).Return(getObjectOutput, nil)

	dataStreams, err := ReadSnsMessages([]string{marshaledNotification})
	// Method shouldn't return error
	require.NoError(t, err)
	// Method should not return data stream
	require.Equal(t, 0, len(dataStreams))
	lambdaMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
}

func TestHandleS3Folder(t *testing.T) {
	resetCaches()

	//nolint:lll
	s3Event := "{\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"us-west-2\",\"eventTime\":\"1970-01-01T00:00:00.000Z\"," +
		"\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"AIDAJDPLRKLG7UEXAMPLE\"},\"requestParameters\":{\"sourceIPAddress\":\"127.0.0.1\"}," +
		"\"responseElements\":{\"x-amz-request-id\":\"C3D13FE58DE4C810\",\"x-amz-id-2\":\"FMyUVURIY8/IgAtTv8xRjskZQpcIZ9KG4V5Wp6S7S/JRWeUWerMUE5JgHvANOjpD\"}," +
		"\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"testConfigRule\"," +
		"\"bucket\":{\"name\":\"mybucket\",\"ownerIdentity\":{\"principalId\":\"A3NL1KOZZKExample\"},\"arn\":\"arn:aws:s3:::mybucket\"},\"object\":{\"key\":\"test-folder/\",\"size\":1024," +
		"\"eTag\":\"d41d8cd98f00b204e9800998ecf8427e\",\"versionId\":\"096fKKXTRTtl3on89fVO.nfljtsv6qko\",\"sequencer\":\"0055AED6DCD90281E5\"}}}]}"

	notification := SnsNotification{}
	notification.Type = "Notification"
	notification.Message = s3Event
	marshaledNotification, err := jsoniter.MarshalToString(notification)
	require.NoError(t, err)

	dataStreams, err := ReadSnsMessages([]string{marshaledNotification})
	// Method shouldn't return error
	require.NoError(t, err)
	// Method should not return data stream
	require.Equal(t, 0, len(dataStreams))
}

func TestHandleUnregisteredSource(t *testing.T) {
	resetCaches()
	// if we encounter an unsupported file type, we should just skip the object
	lambdaMock := &testutils.LambdaMock{}
	common.LambdaClient = lambdaMock

	s3Mock := &testutils.S3Mock{}

	//nolint:lll
	s3Event := "{\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"us-west-2\",\"eventTime\":\"1970-01-01T00:00:00.000Z\"," +
		"\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"AIDAJDPLRKLG7UEXAMPLE\"},\"requestParameters\":{\"sourceIPAddress\":\"127.0.0.1\"}," +
		"\"responseElements\":{\"x-amz-request-id\":\"C3D13FE58DE4C810\",\"x-amz-id-2\":\"FMyUVURIY8/IgAtTv8xRjskZQpcIZ9KG4V5Wp6S7S/JRWeUWerMUE5JgHvANOjpD\"}," +
		"\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"testConfigRule\"," +
		"\"bucket\":{\"name\":\"mybucket\",\"ownerIdentity\":{\"principalId\":\"A3NL1KOZZKExample\"},\"arn\":\"arn:aws:s3:::mybucket\"},\"object\":{\"unregistered/key\":\"test\",\"size\":1024," +
		"\"eTag\":\"d41d8cd98f00b204e9800998ecf8427e\",\"versionId\":\"096fKKXTRTtl3on89fVO.nfljtsv6qko\",\"sequencer\":\"0055AED6DCD90281E5\"}}}]}"

	notification := SnsNotification{}
	notification.Type = "Notification"
	notification.Message = s3Event
	marshaledNotification, err := jsoniter.MarshalToString(notification)
	require.NoError(t, err)

	marshaledResult, err := jsoniter.Marshal([]*models.SourceIntegration{})
	require.NoError(t, err)
	lambdaOutput := &lambda.InvokeOutput{
		Payload: marshaledResult,
	}

	// Getting the list of available sources
	lambdaMock.On("Invoke", mock.Anything).Return(lambdaOutput, nil).Once()

	dataStreams, err := ReadSnsMessages([]string{marshaledNotification})
	// Method shouldn't return error
	require.NoError(t, err)
	// Method should not return data stream
	require.Equal(t, 0, len(dataStreams))
	lambdaMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
}

func Test_detectContentType_gzip(t *testing.T) {
	//nolint:lll
	data := []byte("Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.")
	var buf []byte
	gzippedBuf := bytes.NewBuffer(buf)
	gzipWriter := gzip.NewWriter(gzippedBuf)
	defer gzipWriter.Close()
	_, err := gzipWriter.Write(data)
	require.NoError(t, err)
	err = gzipWriter.Flush()
	require.NoError(t, err)

	br := bufio.NewReader(gzippedBuf)
	ct, err := detectContentType(br)

	require.NoError(t, err)
	require.Equal(t, "application/x-gzip", ct)
}
