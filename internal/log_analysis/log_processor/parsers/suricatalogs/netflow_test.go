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
func TestNetflow(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 1303263735079730, "event_type": "netflow", "src_ip": "192.168.2.137", "src_port": 63064, "dest_ip": "192.168.88.60", "dest_port": 41160, "proto": "006", "netflow": {"pkts": 1, "bytes": 78, "start": "2015-10-22T10:35:38.156466+0000", "end": "2015-10-22T10:35:38.159235+0000", "age": 0, "min_ttl": 62, "max_ttl": 62}, "tcp": {"tcp_flags": "02", "syn": true}, "community_id": "1:whoh7owhVjo5nNI9hJLMPs9Cm2E=", "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 448599195068117, "event_type": "netflow", "src_ip": "192.168.2.199", "src_port": 48381, "dest_ip": "192.168.88.130", "dest_port": 45634, "proto": "006", "netflow": {"pkts": 1, "bytes": 62, "start": "2015-10-22T08:51:55.009941+0000", "end": "2015-10-22T08:51:55.009941+0000", "age": 0, "min_ttl": 51, "max_ttl": 51}, "tcp": {"tcp_flags": "02", "syn": true}, "community_id": "1:m9qG6T+fxLfGSXyQRZxbTnepD+E=", "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 1014920706635936, "event_type": "netflow", "src_ip": "192.168.2.199", "src_port": 40001, "dest_ip": "192.168.88.85", "dest_port": 40103, "proto": "006", "netflow": {"pkts": 1, "bytes": 62, "start": "2015-10-22T08:54:09.243872+0000", "end": "2015-10-22T08:54:09.243872+0000", "age": 0, "min_ttl": 52, "max_ttl": 52}, "tcp": {"tcp_flags": "02", "syn": true}, "community_id": "1:VPbBD2DPf7BVsmfYeRgPbSJUkSU=", "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T10:36:06.440792+0000", "flow_id": 475481844603963, "event_type": "netflow", "src_ip": "192.168.2.22", "src_port": 59051, "dest_ip": "192.168.88.50", "dest_port": 34180, "proto": "006", "netflow": {"pkts": 1, "bytes": 62, "start": "2015-10-22T10:46:09.711739+0000", "end": "2015-10-22T10:46:09.713058+0000", "age": 0, "min_ttl": 51, "max_ttl": 51}, "tcp": {"tcp_flags": "00"}, "community_id": "1:jJggUwZDDDYVKPjlD1ujp7+dK68=", "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 710549657553084, "event_type": "netflow", "src_ip": "192.168.88.60", "src_port": 12309, "dest_ip": "192.168.2.137", "dest_port": 63864, "proto": "006", "netflow": {"pkts": 1, "bytes": 60, "start": "2015-10-22T10:35:27.985276+0000", "end": "2015-10-22T10:35:27.988168+0000", "age": 0, "min_ttl": 64, "max_ttl": 64}, "tcp": {"tcp_flags": "14", "rst": true, "ack": true}, "community_id": "1:5ZZOdboNryeEOCKK8xsRm+yT0bo=", "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2002-02-28T03:55:07.770585+0000", "flow_id": 429637004797503, "event_type": "netflow", "src_ip": "192.168.0.2", "src_port": 4415, "dest_ip": "192.168.0.1", "dest_port": 389, "proto": "006", "app_proto": "failed", "netflow": {"pkts": 5, "bytes": 333, "start": "2002-02-28T03:50:37.960063+0000", "end": "2002-02-28T03:50:38.150543+0000", "age": 1, "min_ttl": 64, "max_ttl": 255}, "tcp": {"tcp_flags": "1f", "syn": true, "fin": true, "rst": true, "psh": true, "ack": true}, "community_id": "1:2BXAMlW6mJM1gAOkVehsAZnODrs=", "pcap_filename": "/pcaps/c06-ldapv3-app-r1.pcap"}`,
		`{"timestamp": "2015-10-22T08:16:58.066972+0000", "flow_id": 21752285327176, "event_type": "netflow", "src_ip": "192.168.88.50", "src_port": 48009, "dest_ip": "192.168.2.199", "dest_port": 43861, "proto": "006", "netflow": {"pkts": 1, "bytes": 60, "start": "2015-10-22T08:07:25.159560+0000", "end": "2015-10-22T08:07:25.160912+0000", "age": 0, "min_ttl": 128, "max_ttl": 128}, "tcp": {"tcp_flags": "14", "rst": true, "ack": true}, "community_id": "1:Uz11BJnTojADayp4iQwptq93ZGk=", "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2002-02-28T03:55:07.770585+0000", "flow_id": 1136678815951563, "event_type": "netflow", "src_ip": "192.168.0.1", "src_port": 389, "dest_ip": "192.168.0.2", "dest_port": 4346, "proto": "006", "app_proto": "failed", "netflow": {"pkts": 3, "bytes": 188, "start": "2002-02-28T03:50:36.420555+0000", "end": "2002-02-28T03:50:36.499436+0000", "age": 0, "min_ttl": 64, "max_ttl": 64}, "tcp": {"tcp_flags": "1a", "syn": true, "psh": true, "ack": true}, "community_id": "1:Ms889O9dWUQuV+9sUb5tZDFbZkI=", "pcap_filename": "/pcaps/c06-ldapv3-app-r1.pcap"}`,
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 2246000068791487, "event_type": "netflow", "src_ip": "192.168.2.199", "src_port": 40002, "dest_ip": "192.168.88.85", "dest_port": 47636, "proto": "006", "netflow": {"pkts": 1, "bytes": 62, "start": "2015-10-22T08:54:28.527551+0000", "end": "2015-10-22T08:54:28.527551+0000", "age": 0, "min_ttl": 57, "max_ttl": 57}, "tcp": {"tcp_flags": "02", "syn": true}, "community_id": "1:PehaMf5mufmqA+SxEDiUakUNxPg=", "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T13:16:57.972898+0000", "flow_id": 724267402392375, "event_type": "netflow", "src_ip": "192.168.2.199", "src_port": 53006, "dest_ip": "192.168.88.75", "dest_port": 43705, "proto": "006", "netflow": {"pkts": 1, "bytes": 62, "start": "2015-10-22T08:58:37.848695+0000", "end": "2015-10-22T08:58:37.849228+0000", "age": 0, "min_ttl": 50, "max_ttl": 50}, "tcp": {"tcp_flags": "00"}, "community_id": "1:2BQ/bMU/icfFPexzGUDMA46rSKA=", "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
	}

	parser := &NetflowParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestNetflowType(t *testing.T) {
	parser := &NetflowParser{}
	require.Equal(t, "Suricata.Netflow", parser.LogType())
}
