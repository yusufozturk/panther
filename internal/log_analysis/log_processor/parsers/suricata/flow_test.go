package suricatalogs

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestFlow(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	log := `{
		"timestamp": "2016-09-14T18:19:04.752237+0300",
		"flow_id": 1472623664406443,
		"event_type": "flow",
		"src_ip": "10.1.1.1",
		"src_port": 53455,
		"dest_ip": "10.1.1.2",
		"dest_port": 80,
		"proto": "TCP",
		"flow": {
			"pkts_toserver": 7,
			"pkts_toclient": 4,
			"bytes_toserver": 3242,
			"bytes_toclient": 5081,
			"start": "2016-09-14T18:19:03.696235+0300",
			"end": "2016-09-14T18:19:04.752237+0300",
			"age": 1,
			"state": "new",
			"reason": "shutdown"
		},
		"tcp": {
			"tcp_flags": "13",
			"tcp_flags_ts": "13",
			"tcp_flags_tc": "00",
			"syn": true,
			"fin": true,
			"ack": true,
			"state": "syn_sent"
		}
	}`

	expectedTime, _ := timestamp.Parse(time.RFC3339Nano, "2016-09-14T18:19:04.752237+0300")

	expectedEvent := &Flow{
		Timestamp: aws.String("2016-09-14T18:19:04.752237+0300"),
		FlowID:    aws.Int(1472623664406443),
		EventType: aws.String("flow"),
		SrcIP:     aws.String("10.1.1.1"),
		SrcPort:   aws.Int(53455),
		DestIP:    aws.String("10.1.1.2"),
		DestPort:  aws.Int(80),
		Proto:     aws.String("TCP"),
		Flow: &FlowDetails{
			PktsToserver:  aws.Int(7),
			PktsToclient:  aws.Int(4),
			BytesToserver: aws.Int(3242),
			BytesToclient: aws.Int(5081),
			Start:         aws.String("2016-09-14T18:19:03.696235+0300"),
			End:           aws.String("2016-09-14T18:19:04.752237+0300"),
			Age:           aws.Int(1),
			State:         aws.String("new"),
			Reason:        aws.String("shutdown"),
		},
		TCP: &FlowTCP{
			TCPFlags:   aws.String("13"),
			TCPFlagsTs: aws.String("13"),
			TCPFlagsTc: aws.String("00"),
			Syn:        aws.Bool(true),
			Fin:        aws.Bool(true),
			Ack:        aws.Bool(true),
			State:      aws.String("syn_sent"),
		},
	}

	expectedEvent.AppendAnyIPAddresses("10.1.1.1", "10.1.1.2")
	// panther fields
	expectedEvent.PantherLogType = aws.String("Suricata.Flow")
	expectedEvent.PantherEventTime = &expectedTime

	checkFlow(t, log, expectedEvent)
}

func TestFlowType(t *testing.T) {
	parser := &FlowParser{}
	require.Equal(t, "Suricata.Flow", parser.LogType())
}

func checkFlow(t *testing.T, log string, expectedEvent *Flow) {
	parser := &FlowParser{}
	events := parser.Parse(log)
	require.Equal(t, 1, len(events))
	event := events[0].(*Flow)

	// rowid changes each time
	require.Greater(t, len(*event.PantherRowID), 0) // ensure something is there.
	expectedEvent.PantherRowID = event.PantherRowID

	// PantherParseTime is set to time.Now().UTC(). Require not nil
	require.NotNil(t, event.PantherParseTime)
	expectedEvent.PantherParseTime = event.PantherParseTime

	require.Equal(t, expectedEvent, event)
}
