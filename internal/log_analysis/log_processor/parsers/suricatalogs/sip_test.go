package suricatalogs

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
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

//nolint:lll
func TestSIP(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2016-11-26T15:05:12.558382+0000", "flow_id": 36836398626518, "pcap_cnt": 2603, "event_type": "sip", "src_ip": "10.0.2.20", "src_port": 5060, "dest_ip": "10.0.2.15", "dest_port": 5060, "proto": "017", "community_id": "1:UYL3rljsU0EQl2q7H87xQm2kVvE=", "sip": {"method": "ACK", "uri": "sip:test@10.0.2.15:5060", "version": "SIP/2.0", "request_line": "ACK sip:test@10.0.2.15:5060 SIP/2.0"}, "pcap_filename": "/pcaps/sip-rtp-g726.pcap"}`,
		`{"timestamp": "2016-11-26T14:52:59.666545+0000", "flow_id": 1524273722895129, "pcap_cnt": 2, "event_type": "sip", "src_ip": "10.0.2.15", "src_port": 5060, "dest_ip": "10.0.2.20", "dest_port": 5060, "proto": "017", "community_id": "1:UYL3rljsU0EQl2q7H87xQm2kVvE=", "sip": {"version": "SIP/2.0", "code": "100", "reason": "Trying", "response_line": "SIP/2.0 100 Trying"}, "pcap_filename": "/pcaps/sip-rtp-g711.pcap"}`,
		`{"timestamp": "2008-12-05T09:22:38.718407+0000", "flow_id": 2092971702748952, "pcap_cnt": 30, "event_type": "sip", "src_ip": "192.168.100.219", "src_port": 5060, "dest_ip": "138.132.169.101", "dest_port": 5060, "proto": "017", "community_id": "1:HI8jaNDuezBE6XMcyIi4Bae0X2E=", "sip": {"version": "SIP/2.0", "code": "100", "reason": "Trying", "response_line": "SIP/2.0 100 Trying"}, "pcap_filename": "/pcaps/FAX-Call-t38-CA-TDM-SIP-FB-1.pcap"}`,
		`{"timestamp": "2007-01-05T16:20:45.425275+0000", "flow_id": 689556913129518, "pcap_cnt": 66, "event_type": "sip", "src_ip": "83.166.68.46", "src_port": 5060, "dest_ip": "83.166.68.63", "dest_port": 5060, "proto": "017", "community_id": "1:4PYmPM/QhNtG1rgzvx6dHw1xCgQ=", "sip": {"method": "INVITE", "uri": "sip:442088205173@kestral:5060", "version": "SIP/2.0", "request_line": "INVITE sip:442088205173@kestral:5060 SIP/2.0"}, "pcap_filename": "/pcaps/h223-over-rtp.pcap"}`,
		`{"timestamp": "2016-11-26T14:52:59.666393+0000", "flow_id": 1524273722895129, "pcap_cnt": 1, "event_type": "sip", "src_ip": "10.0.2.20", "src_port": 5060, "dest_ip": "10.0.2.15", "dest_port": 5060, "proto": "017", "community_id": "1:UYL3rljsU0EQl2q7H87xQm2kVvE=", "sip": {"method": "INVITE", "uri": "sip:test@10.0.2.15:5060", "version": "SIP/2.0", "request_line": "INVITE sip:test@10.0.2.15:5060 SIP/2.0"}, "pcap_filename": "/pcaps/sip-rtp-g711.pcap"}`,
		`{"timestamp": "2016-11-26T14:53:08.286340+0000", "flow_id": 1524273722895129, "pcap_cnt": 435, "event_type": "sip", "src_ip": "10.0.2.15", "src_port": 5060, "dest_ip": "10.0.2.20", "dest_port": 5060, "proto": "017", "community_id": "1:UYL3rljsU0EQl2q7H87xQm2kVvE=", "sip": {"version": "SIP/2.0", "code": "100", "reason": "Trying", "response_line": "SIP/2.0 100 Trying"}, "pcap_filename": "/pcaps/sip-rtp-g711.pcap"}`,
		`{"timestamp": "2016-11-26T14:52:59.670837+0000", "flow_id": 1524273722895129, "pcap_cnt": 5, "event_type": "sip", "src_ip": "10.0.2.20", "src_port": 5060, "dest_ip": "10.0.2.15", "dest_port": 5060, "proto": "017", "community_id": "1:UYL3rljsU0EQl2q7H87xQm2kVvE=", "sip": {"method": "ACK", "uri": "sip:test@10.0.2.15:5060", "version": "SIP/2.0", "request_line": "ACK sip:test@10.0.2.15:5060 SIP/2.0"}, "pcap_filename": "/pcaps/sip-rtp-g711.pcap"}`,
		`{"timestamp": "2016-11-26T14:53:08.286194+0000", "flow_id": 1524273722895129, "pcap_cnt": 434, "event_type": "sip", "src_ip": "10.0.2.20", "src_port": 5060, "dest_ip": "10.0.2.15", "dest_port": 5060, "proto": "017", "community_id": "1:UYL3rljsU0EQl2q7H87xQm2kVvE=", "sip": {"method": "INVITE", "uri": "sip:test@10.0.2.15:5060", "version": "SIP/2.0", "request_line": "INVITE sip:test@10.0.2.15:5060 SIP/2.0"}, "pcap_filename": "/pcaps/sip-rtp-g711.pcap"}`,
		`{"timestamp": "2005-07-04T09:47:36.286438+0000", "flow_id": 101591047004633, "pcap_cnt": 422, "event_type": "sip", "src_ip": "212.242.33.35", "src_port": 5060, "dest_ip": "192.168.1.2", "dest_port": 5060, "proto": "017", "community_id": "1:evLOgLrWvHxi41WU/zzTuiqjuuk=", "sip": {"version": "SIP/2.0", "code": "401", "reason": "Unauthorized", "response_line": "SIP/2.0 401 Unauthorized"}, "pcap_filename": "/pcaps/aaa.pcap"}`,
		`{"timestamp": "2016-11-26T15:03:08.982128+0000", "flow_id": 1707153469778272, "pcap_cnt": 434, "event_type": "sip", "src_ip": "10.0.2.20", "src_port": 5060, "dest_ip": "10.0.2.15", "dest_port": 5060, "proto": "017", "community_id": "1:UYL3rljsU0EQl2q7H87xQm2kVvE=", "sip": {"method": "INVITE", "uri": "sip:test@10.0.2.15:5060", "version": "SIP/2.0", "request_line": "INVITE sip:test@10.0.2.15:5060 SIP/2.0"}, "pcap_filename": "/pcaps/sip-rtp-l16.pcap"}`,
	}

	parser := &SIPParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestSIPType(t *testing.T) {
	parser := &SIPParser{}
	require.Equal(t, "Suricata.SIP", parser.LogType())
}
