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

func TestAlert(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	//nolint:lll
	log := `{
		"timestamp": "2009-10-05T06:06:09.957250+0000",
		"flow_id": 1745769129251478,
		"pcap_cnt": 18,
		"event_type": "alert",
		"src_ip": "10.10.1.4",
		"src_port": 1470,
		"dest_ip": "74.53.140.153",
		"dest_port": 25,
		"proto": "006",
		"metadata": {
		  "flowints": {
			"applayer.anomaly.count": 1
		  }
		},
		"community_id": "1:gr+OgB+EqGk3Rt+VUVWX92tFJxU=",
		"alert": {
		  "action": "allowed",
		  "gid": 1,
		  "signature_id": 103,
		  "rev": 0,
		  "signature": "FOO SMTP",
		  "category": "",
		  "severity": 3
		},
		"smtp": {
		  "helo": "GP",
		  "mail_from": "<acme@example.com>"
		},
		"app_proto": "smtp",
		"app_proto_tc": "failed",
		"flow": {
		  "pkts_toserver": 8,
		  "pkts_toclient": 8,
		  "bytes_toserver": 584,
		  "bytes_toclient": 838,
		  "start": "2009-10-05T06:06:07.529046+0000"
		},
		"payload": "ABCD",
		"payload_printable": "RCPT TO: acme@example.com>\r\n",
		"stream": 0,
		"packet": "ANCD",
		"packet_info": {
		  "linktype": 1
		},
		"pcap_filename": "/pcaps/smtp.pcap"
	  }`

	expectedTime, _ := timestamp.Parse(time.RFC3339Nano, "2009-10-05T06:06:09.957250+0000")

	expectedEvent := &Alert{
		Timestamp: aws.String("2009-10-05T06:06:09.957250+0000"),
		FlowID:    aws.Int(1745769129251478),
		PcapCnt:   aws.Int(18),
		EventType: aws.String("alert"),
		Alert: &AlertDetails{
			Action:      aws.String("allowed"),
			GID:         aws.Int(1),
			SignatureID: aws.Int(103),
			Rev:         aws.Int(0),
			Signature:   aws.String("FOO SMTP"),
			Category:    aws.String(""),
			Severity:    aws.Int(3),
		},
		DestIP:   aws.String("74.53.140.153"),
		DestPort: aws.Int(25),
		Packet:   aws.String("ANCD"),
		PacketInfo: &AlertPacketInfo{
			Linktype: aws.Int(1),
		},
		PcapFilename: aws.String("/pcaps/smtp.pcap"),
		Proto:        aws.String("006"),
		SrcIP:        aws.String("10.10.1.4"),
		SrcPort:      aws.Int(1470),
		Stream:       aws.Int(0),
		Metadata: &AlertMetadata{
			Flowints: &AlertMetadataFlowints{
				ApplayerAnomalyCount: aws.Int(1),
			},
		},
		CommunityID: aws.String("1:gr+OgB+EqGk3Rt+VUVWX92tFJxU="),
		SMTP: &AlertSMTP{
			Helo:     aws.String("GP"),
			MailFrom: aws.String("<acme@example.com>"),
		},
		AppProto:   aws.String("smtp"),
		AppProtoTc: aws.String("failed"),
		Flow: &AlertFlow{
			PktsToserver:  aws.Int(8),
			PktsToclient:  aws.Int(8),
			BytesToserver: aws.Int(584),
			BytesToclient: aws.Int(838),
			Start:         aws.String("2009-10-05T06:06:07.529046+0000"),
		},
		Payload:          aws.String("ABCD"),
		PayloadPrintable: aws.String("RCPT TO: acme@example.com>\r\n"),
	}

	expectedEvent.AppendAnyIPAddresses("10.10.1.4", "74.53.140.153")
	// panther fields
	expectedEvent.PantherLogType = aws.String("Suricata.Alert")
	expectedEvent.PantherEventTime = &expectedTime

	checkAlert(t, log, expectedEvent)
}

func TestAlertType(t *testing.T) {
	parser := &AlertParser{}
	require.Equal(t, "Suricata.Alert", parser.LogType())
}

func checkAlert(t *testing.T, log string, expectedEvent *Alert) {
	parser := &AlertParser{}
	events := parser.Parse(log)
	require.Equal(t, 1, len(events))
	event := events[0].(*Alert)

	// rowid changes each time
	require.Greater(t, len(*event.PantherRowID), 0) // ensure something is there.
	expectedEvent.PantherRowID = event.PantherRowID

	// PantherParseTime is set to time.Now().UTC(). Require not nil
	require.NotNil(t, event.PantherParseTime)
	expectedEvent.PantherParseTime = event.PantherParseTime

	require.Equal(t, expectedEvent, event)
}
