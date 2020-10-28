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

func TestComplianceSnapshot(t *testing.T) {
	// nolint:lll
	input := `{"ChangeType":"modified","IntegrationID":"00763118-329a-4939-9641-c1953e892c9a","IntegrationLabel":"panther-cloudsec-setup","LastUpdated":"2020-10-23T21:10:30.814384032Z","PolicyID":"AWS.AccessKeys.AccountCreation","PolicySeverity":"LOW","ResourceID":"arn:aws:iam::123456789012:user/BobJoe","ResourceType":"AWS.IAM.User","Status":"FAIL","Suppressed":false}`

	expectedEventTime, err := time.Parse(time.RFC3339, "2020-10-23T21:10:30.814384032Z")
	require.NoError(t, err)
	rfcEventTime := timestamp.RFC3339(expectedEventTime)

	arns := parsers.NewPantherAnyString()
	parsers.AppendAnyString(arns, "arn:aws:iam::123456789012:user/BobJoe")
	accountIds := parsers.NewPantherAnyString()
	parsers.AppendAnyString(accountIds, "123456789012")
	expectedEvent := &Compliance{
		ChangeType:       "modified",
		IntegrationID:    "00763118-329a-4939-9641-c1953e892c9a",
		IntegrationLabel: "panther-cloudsec-setup",
		PolicyID:         "AWS.AccessKeys.AccountCreation",
		PolicySeverity:   "LOW",
		ResourceID:       "arn:aws:iam::123456789012:user/BobJoe",
		ResourceType:     "AWS.IAM.User",
		Status:           "FAIL",
		Suppressed:       box.Bool(false),
		LastUpdated:      rfcEventTime,
		AWSPantherLog: awslogs.AWSPantherLog{
			PantherLog: parsers.PantherLog{
				PantherLogType:   box.String(TypeCompliance),
				PantherEventTime: &rfcEventTime,
			},
			PantherAnyAWSARNs:       arns,
			PantherAnyAWSAccountIds: accountIds,
		},
	}
	parser := (&ComplianceHistoryParser{}).New()
	expectedEvent.SetEvent(expectedEvent)
	testutil.CheckPantherParser(t, input, parser, expectedEvent.Log())
}
