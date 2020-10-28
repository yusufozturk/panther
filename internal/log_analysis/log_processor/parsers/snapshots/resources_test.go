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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/awslogs"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/panther-labs/panther/pkg/box"
)

func TestResourceSnapshot(t *testing.T) {
	// nolint:lll
	input := `{
    "ChangeType": "created",
    "Changes": null,
    "IntegrationID": "d3be8d06-3e30-4908-9c07-6640b4b5b3dc",
    "IntegrationLabel": "panther-account",
    "LastUpdated": "2020-10-15T06:29:00.498108265Z",
    "Resource": "{\"ResourceType\":\"AWS.CloudWatch.LogGroup\",\"Tags\":{\"PantherVersion\":\"v1.10.1-dirty\",\"Application\":\"Panther\",\"Stack\":\"panther-log-analysis\",\"PantherEdition\":\"Enterprise\"},\"StoredBytes\":109,\"AccountId\":\"123456789012\",\"ResourceId\":\"arn:aws:logs:us-west-1:123456789012:log-group:/aws/apigateway/welcome:*\",\"Region\":\"us-west-1\",\"MetricFilterCount\":0,\"RetentionInDays\":null,\"KmsKeyId\":null,\"Arn\":\"arn:aws:logs:us-west-1:123456789012:log-group:/aws/apigateway/welcome:*\",\"TimeCreated\":\"2020-01-30T23:24:25.000Z\",\"Name\":\"/aws/apigateway/welcome\"}"
}`

	expectedEventTime, err := time.Parse(time.RFC3339, "2020-10-15T06:29:00.498108265Z")
	require.NoError(t, err)
	rfcEventTime := timestamp.RFC3339(expectedEventTime)

	expectedCreateTime, err := time.Parse(time.RFC3339, "2020-01-30T23:24:25.000Z")
	require.NoError(t, err)
	rfcCreateTime := timestamp.RFC3339(expectedCreateTime)

	arns := parsers.NewPantherAnyString()
	parsers.AppendAnyString(arns, "arn:aws:logs:us-west-1:123456789012:log-group:/aws/apigateway/welcome:*")
	accountIds := parsers.NewPantherAnyString()
	parsers.AppendAnyString(accountIds, "123456789012")
	tags := parsers.NewPantherAnyString()
	parsers.AppendAnyString(tags,
		"PantherVersion:v1.10.1-dirty",
		"Application:Panther",
		"Stack:panther-log-analysis",
		"PantherEdition:Enterprise",
	)

	expectedEvent := &Resource{
		ChangeType:       "created",
		Changes:          nil,
		IntegrationID:    "d3be8d06-3e30-4908-9c07-6640b4b5b3dc",
		IntegrationLabel: "panther-account",
		LastUpdated:      rfcEventTime,
		// nolint:lll
		Resource: "{\"ResourceType\":\"AWS.CloudWatch.LogGroup\",\"Tags\":{\"PantherVersion\":\"v1.10.1-dirty\",\"Application\":\"Panther\",\"Stack\":\"panther-log-analysis\",\"PantherEdition\":\"Enterprise\"},\"StoredBytes\":109,\"AccountId\":\"123456789012\",\"ResourceId\":\"arn:aws:logs:us-west-1:123456789012:log-group:/aws/apigateway/welcome:*\",\"Region\":\"us-west-1\",\"MetricFilterCount\":0,\"RetentionInDays\":null,\"KmsKeyId\":null,\"Arn\":\"arn:aws:logs:us-west-1:123456789012:log-group:/aws/apigateway/welcome:*\",\"TimeCreated\":\"2020-01-30T23:24:25.000Z\",\"Name\":\"/aws/apigateway/welcome\"}",
		NormalizedFields: SnapshotNormalizedFields{
			ResourceID:   "arn:aws:logs:us-west-1:123456789012:log-group:/aws/apigateway/welcome:*",
			ResourceType: "AWS.CloudWatch.LogGroup",
			TimeCreated:  rfcCreateTime,
			AccountID:    "123456789012",
			Region:       "us-west-1",
			ARN:          "arn:aws:logs:us-west-1:123456789012:log-group:/aws/apigateway/welcome:*",
			Name:         "/aws/apigateway/welcome",
			Tags: map[string]string{
				"PantherVersion": "v1.10.1-dirty",
				"Application":    "Panther",
				"Stack":          "panther-log-analysis",
				"PantherEdition": "Enterprise",
			},
		},
		AWSPantherLog: awslogs.AWSPantherLog{
			PantherLog: parsers.PantherLog{
				PantherLogType:   box.String(TypeResource),
				PantherEventTime: &rfcEventTime,
			},
			PantherAnyAWSARNs:       arns,
			PantherAnyAWSAccountIds: accountIds,
			PantherAnyAWSTags:       tags,
		},
	}
	parser := (&ResourceHistoryParser{}).New()
	expectedEvent.SetEvent(expectedEvent)
	testutil.CheckPantherParser(t, input, parser, expectedEvent.Log())
}
