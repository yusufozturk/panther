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
func TestAnomaly(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2015-10-22T11:17:43.787396+0000", "flow_id": 1736252438606144, "pcap_cnt": 1803045, "event_type": "anomaly", "src_ip": "192.168.88.25", "src_port": 32483, "dest_ip": "192.168.2.22", "dest_port": 59050, "proto": "006", "community_id": "1:N83Uv4ioTSH1OQtnSJxvUaj9jpc=", "packet": "AAd8GmGDANDJpcktCABFAAAoWqcAAEAGRKnAqFgZwKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.rst_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T10:45:05.613522+0000", "flow_id": 1973566433221645, "pcap_cnt": 1551932, "event_type": "anomaly", "src_ip": "192.168.88.51", "src_port": 5264, "dest_ip": "192.168.2.22", "dest_port": 59050, "proto": "006", "community_id": "1:pbl4gqPyqa+wmREJisGJvAy1OvM=", "packet": "AAd8GmGDANDJvS5XCABFAAAoRkwAAIAGGOrAqFgzwKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.rst_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T09:11:46.453157+0000", "flow_id": 1350078548836736, "pcap_cnt": 1200560, "event_type": "anomaly", "src_ip": "192.168.88.50", "src_port": 9463, "dest_ip": "192.168.2.137", "dest_port": 49001, "proto": "006", "community_id": "1:ek/l9I6uUWdSBgPN5EQHO3kRaLo=", "packet": "AAd8GmGDAAXkASTTCABFAAAop6EAAIAGtyLAqFgywKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.rst_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-21T12:36:49.761994+0000", "flow_id": 941549288528045, "pcap_cnt": 797829, "event_type": "anomaly", "src_ip": "192.168.2.111", "src_port": 33323, "dest_ip": "192.168.88.115", "dest_port": 7007, "proto": "006", "community_id": "1:+WZkQuEa/NWMEHmVQzJhVwoeKr8=", "packet": "AECdKO4NAAd8GmGDCABFAAA0dV5AAD4G6zLAqAJvwKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.pkt_invalid_timestamp"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-22T11:00:10.494577+0000", "flow_id": 1942251885988584, "pcap_cnt": 1675376, "event_type": "anomaly", "src_ip": "192.168.88.49", "src_port": 54125, "dest_ip": "192.168.2.22", "dest_port": 59051, "proto": "006", "community_id": "1:D0hf/spPh+fwBVdBqWbUuvQ0QfA=", "packet": "AAd8GmGDAECMfwu8CABFAAAoPpxAAEAGIJzAqFgxwKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.rst_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T09:01:11.671791+0000", "flow_id": 1359153773100568, "pcap_cnt": 1086933, "event_type": "anomaly", "src_ip": "192.168.88.75", "src_port": 35984, "dest_ip": "192.168.2.199", "dest_port": 53007, "proto": "006", "community_id": "1:PjKaWeE4vucUwuUQmCCj70Q88HU=", "packet": "AAd8GmGDAIBjtba7CABFAAAo1awAAP8GCcDAqFhLwKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.rst_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T09:01:09.887534+0000", "flow_id": 301676990134496, "pcap_cnt": 1086338, "event_type": "anomaly", "src_ip": "192.168.88.25", "src_port": 33, "dest_ip": "192.168.2.199", "dest_port": 65065, "proto": "006", "community_id": "1:ePUa/Br2C51NNDPZBoarH8gXwTM=", "packet": "AAd8GmGDANDJpcktCABFAAAoE2gAAEAGizfAqFgZwKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.rst_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T09:12:16.939767+0000", "flow_id": 547396407848514, "pcap_cnt": 1243913, "event_type": "anomaly", "src_ip": "192.168.88.50", "src_port": 9341, "dest_ip": "192.168.2.137", "dest_port": 53877, "proto": "006", "community_id": "1:Wz75lNXkc31Ppj3TKTMpFbT9tHY=", "packet": "AAd8GmGDAAXkASTTCABFAAAo+pIAAIAGZDHAqFgywKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.rst_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T10:34:54.112200+0000", "flow_id": 1729547826219408, "pcap_cnt": 1369480, "event_type": "anomaly", "src_ip": "192.168.88.49", "src_port": 21, "dest_ip": "192.168.2.22", "dest_port": 58995, "proto": "006", "community_id": "1:EuCLWyupxgkPjnBvKV+s2Z2VFTY=", "packet": "AAd8GmGDAECMfwu8CABFAAA0SwVAAEAGFCfAqFgxwKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.fin_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T09:10:54.139890+0000", "flow_id": 163336131902049, "pcap_cnt": 1126179, "event_type": "anomaly", "src_ip": "192.168.88.50", "src_port": 5391, "dest_ip": "192.168.2.137", "dest_port": 49984, "proto": "006", "community_id": "1:4TkkQkySeTGqJqczLPX0lInRg/Q=", "packet": "AAd8GmGDAAXkASTTCABFAAAoGVEAAIAGRXPAqFgywKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.rst_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
	}

	parser := &AnomalyParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestAnomalyType(t *testing.T) {
	parser := &AnomalyParser{}
	require.Equal(t, "Suricata.Anomaly", parser.LogType())
}
