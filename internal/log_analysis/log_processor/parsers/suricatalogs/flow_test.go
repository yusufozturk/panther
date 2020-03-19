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

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

//nolint:lll
func TestFlow(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 1905477948906999, "event_type": "flow", "src_ip": "192.168.2.137", "src_port": 34156, "dest_ip": "192.168.88.50", "dest_port": 11956, "proto": "006", "flow": {"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 74, "bytes_toclient": 60, "start": "2015-10-22T09:11:33.826871+0000", "end": "2015-10-22T09:11:33.851401+0000", "age": 0, "state": "new", "reason": "timeout", "alerted": false}, "community_id": "1:1ws8mm8iYMcup3eU4JR1O6h4HX4=", "tcp": {"tcp_flags": "00", "tcp_flags_ts": "00", "tcp_flags_tc": "00"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2009-11-06T22:10:31.638923+0000", "flow_id": 600632170427365, "event_type": "flow", "src_ip": "192.168.1.107", "src_port": 59020, "dest_ip": "224.0.0.252", "dest_port": 5355, "proto": "017", "app_proto": "failed", "flow": {"pkts_toserver": 2, "pkts_toclient": 0, "bytes_toserver": 136, "bytes_toclient": 0, "start": "2009-11-06T21:20:40.504805+0000", "end": "2009-11-06T21:20:40.611525+0000", "age": 0, "state": "new", "reason": "timeout", "alerted": false}, "community_id": "1:undCrYtZvZnDTKaSNSi/iVaDZPs=", "pcap_filename": "/pcaps/tridium-jace2.pcap"}`,
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 1020448399250096, "event_type": "flow", "src_ip": "192.168.2.137", "src_port": 44597, "dest_ip": "192.168.88.50", "dest_port": 7712, "proto": "006", "flow": {"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 74, "bytes_toclient": 60, "start": "2015-10-22T09:11:53.545456+0000", "end": "2015-10-22T09:11:53.561089+0000", "age": 0, "state": "new", "reason": "timeout", "alerted": false}, "community_id": "1:mssRfFesT1wt53KEVfD/jyQRcXk=", "tcp": {"tcp_flags": "00", "tcp_flags_ts": "00", "tcp_flags_tc": "00"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T08:16:58.135131+0000", "flow_id": 888459491375461, "event_type": "flow", "src_ip": "192.168.2.199", "src_port": 52011, "dest_ip": "192.168.88.60", "dest_port": 8080, "proto": "006", "flow": {"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 62, "bytes_toclient": 60, "start": "2015-10-22T08:03:45.227685+0000", "end": "2015-10-22T08:03:45.228431+0000", "age": 0, "state": "closed", "reason": "timeout", "alerted": false}, "community_id": "1:DQ3wofjR7ro+N9MYWFoUeq9YyGc=", "tcp": {"tcp_flags": "16", "tcp_flags_ts": "02", "tcp_flags_tc": "14", "syn": true, "rst": true, "ack": true, "state": "closed"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 1162865690934997, "event_type": "flow", "src_ip": "192.168.2.22", "src_port": 59050, "dest_ip": "192.168.88.30", "dest_port": 44469, "proto": "006", "flow": {"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 62, "bytes_toclient": 60, "start": "2015-10-22T11:11:41.982741+0000", "end": "2015-10-22T11:11:41.986783+0000", "age": 0, "emergency": true, "state": "new", "reason": "timeout", "alerted": false}, "community_id": "1:2LpjuxD/vVA6JN8QefobzSHIcjw=", "tcp": {"tcp_flags": "00", "tcp_flags_ts": "00", "tcp_flags_tc": "00"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T11:03:02.998812+0000", "flow_id": 368344055814729, "event_type": "flow", "src_ip": "192.168.2.22", "src_port": 59051, "dest_ip": "192.168.88.15", "dest_port": 64013, "proto": "006", "flow": {"pkts_toserver": 1, "pkts_toclient": 0, "bytes_toserver": 62, "bytes_toclient": 0, "start": "2015-10-22T11:29:30.268873+0000", "end": "2015-10-22T11:29:30.268873+0000", "age": 0, "emergency": true, "state": "new", "reason": "forced", "alerted": false}, "community_id": "1:jyjYw3nZdggqGNtdgeiX0F7s4UM=", "tcp": {"tcp_flags": "02", "tcp_flags_ts": "02", "tcp_flags_tc": "00", "syn": true, "state": "syn_sent"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-21T22:09:52.107821+0000", "flow_id": 149077576842900, "event_type": "flow", "src_ip": "192.168.89.2", "src_port": 8542, "dest_ip": "8.8.8.8", "dest_port": 53, "proto": "017", "app_proto": "dns", "flow": {"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 69, "bytes_toclient": 97, "start": "2015-10-21T18:05:54.851604+0000", "end": "2015-10-21T18:05:54.851720+0000", "age": 0, "state": "new", "reason": "timeout", "alerted": false}, "community_id": "1:WFOQ9WN6jRc/71Th9cWPmY55YMo=", "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 498421249620391, "event_type": "flow", "src_ip": "192.168.2.22", "src_port": 59050, "dest_ip": "192.168.88.51", "dest_port": 57794, "proto": "006", "flow": {"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 62, "bytes_toclient": 60, "start": "2015-10-22T10:42:16.014759+0000", "end": "2015-10-22T10:42:16.014914+0000", "age": 0, "emergency": true, "state": "new", "reason": "timeout", "alerted": false}, "community_id": "1:k1q0dKUs4/Rg+nze3pY50GZlwI4=", "tcp": {"tcp_flags": "00", "tcp_flags_ts": "00", "tcp_flags_tc": "00"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 279940124245810, "event_type": "flow", "src_ip": "192.168.2.199", "src_port": 53005, "dest_ip": "192.168.88.75", "dest_port": 65288, "proto": "006", "flow": {"pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 62, "bytes_toclient": 60, "start": "2015-10-22T08:51:53.261938+0000", "end": "2015-10-22T08:51:53.262655+0000", "age": 0, "state": "closed", "reason": "timeout", "alerted": false}, "community_id": "1:SokBqv6ab/+F9690bOgdSnFHnUc=", "tcp": {"tcp_flags": "16", "tcp_flags_ts": "02", "tcp_flags_tc": "14", "syn": true, "rst": true, "ack": true, "state": "closed"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T08:16:58.081398+0000", "flow_id": 1152724549216732, "event_type": "flow", "src_ip": "192.168.2.199", "src_port": 48382, "dest_ip": "192.168.88.130", "dest_port": 46436, "proto": "006", "flow": {"pkts_toserver": 1, "pkts_toclient": 0, "bytes_toserver": 62, "bytes_toclient": 0, "start": "2015-10-22T08:07:35.698844+0000", "end": "2015-10-22T08:07:35.698844+0000", "age": 0, "state": "new", "reason": "timeout", "alerted": false}, "community_id": "1:oA7q/7LwqziP79ug9yH2yib3z6Y=", "tcp": {"tcp_flags": "02", "tcp_flags_ts": "02", "tcp_flags_tc": "00", "syn": true, "state": "syn_sent"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
	}

	parser := &FlowParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestFlowType(t *testing.T) {
	parser := &FlowParser{}
	require.Equal(t, "Suricata.Flow", parser.LogType())
}
