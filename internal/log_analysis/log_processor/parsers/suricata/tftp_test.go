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
func TestTFTP(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2018-04-09T15:15:20.687486+0000", "flow_id": 1072249381914981, "pcap_cnt": 302, "event_type": "tftp", "src_ip": "fc0c:0000:0000:0000:0000:0000:0000:0094", "src_port": 1024, "dest_ip": "fc0c:0000:0000:0000:0000:0000:0000:0008", "dest_port": 69, "proto": "017", "tftp": {"packet": "read", "file": "bin8068S-header", "mode": "octet"}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2018-04-09T15:17:43.563742+0000", "flow_id": 1072249381914981, "pcap_cnt": 1194, "event_type": "tftp", "src_ip": "fc0c:0000:0000:0000:0000:0000:0000:0094", "src_port": 1024, "dest_ip": "fc0c:0000:0000:0000:0000:0000:0000:0008", "dest_port": 69, "proto": "017", "tftp": {"packet": "read", "file": "lanpbx.cfg", "mode": "octet"}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2018-04-09T15:15:27.231811+0000", "flow_id": 1072249381914981, "pcap_cnt": 357, "event_type": "tftp", "src_ip": "fc0c:0000:0000:0000:0000:0000:0000:0094", "src_port": 1024, "dest_ip": "fc0c:0000:0000:0000:0000:0000:0000:0008", "dest_port": 69, "proto": "017", "tftp": {"packet": "read", "file": "startnoes-aabb73000450", "mode": "octet"}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2018-04-09T15:17:52.330358+0000", "flow_id": 1072249381914981, "pcap_cnt": 1235, "event_type": "tftp", "src_ip": "fc0c:0000:0000:0000:0000:0000:0000:0094", "src_port": 1024, "dest_ip": "fc0c:0000:0000:0000:0000:0000:0000:0008", "dest_port": 69, "proto": "017", "tftp": {"packet": "read", "file": "bin8068S-header", "mode": "octet"}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2018-04-09T15:15:24.594453+0000", "flow_id": 1072249381914981, "pcap_cnt": 336, "event_type": "tftp", "src_ip": "fc0c:0000:0000:0000:0000:0000:0000:0094", "src_port": 1024, "dest_ip": "fc0c:0000:0000:0000:0000:0000:0000:0008", "dest_port": 69, "proto": "017", "tftp": {"packet": "read", "file": "noe8068S-header", "mode": "octet"}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2018-04-09T15:20:44.273361+0000", "flow_id": 1742612193881041, "pcap_cnt": 2445, "event_type": "tftp", "src_ip": "172.19.115.110", "src_port": 10040, "dest_ip": "172.19.115.10", "dest_port": 69, "proto": "017", "tftp": {"packet": "read", "file": "startnoes-aabb73000450", "mode": "octet"}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2013-04-27T09:07:59.452740+0000", "flow_id": 1739313938163844, "pcap_cnt": 1, "event_type": "tftp", "src_ip": "192.168.0.1", "src_port": 57509, "dest_ip": "192.168.0.13", "dest_port": 69, "proto": "017", "tftp": {"packet": "write", "file": "rfc1350.txt", "mode": "octet"}, "pcap_filename": "/pcaps/tftp_wrq.pcap"}`,
		`{"timestamp": "2018-04-09T15:15:17.592229+0000", "flow_id": 1072249381914981, "pcap_cnt": 271, "event_type": "tftp", "src_ip": "fc0c:0000:0000:0000:0000:0000:0000:0094", "src_port": 1024, "dest_ip": "fc0c:0000:0000:0000:0000:0000:0000:0008", "dest_port": 69, "proto": "017", "tftp": {"packet": "read", "file": "lanpbx.cfg", "mode": "octet"}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2018-04-09T15:15:27.256010+0000", "flow_id": 744075226507274, "pcap_cnt": 358, "event_type": "tftp", "src_ip": "172.19.115.110", "src_port": 10141, "dest_ip": "172.19.115.10", "dest_port": 69, "proto": "017", "tftp": {"packet": "read", "file": "startnoes-aabb73000450", "mode": "octet"}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2018-04-09T15:18:05.665493+0000", "flow_id": 1072249381914981, "pcap_cnt": 1317, "event_type": "tftp", "src_ip": "fc0c:0000:0000:0000:0000:0000:0000:0094", "src_port": 1024, "dest_ip": "fc0c:0000:0000:0000:0000:0000:0000:0008", "dest_port": 69, "proto": "017", "tftp": {"packet": "read", "file": "startnoes-aabb73000450", "mode": "octet"}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
	}

	parser := &TFTPParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestTFTPType(t *testing.T) {
	parser := &TFTPParser{}
	require.Equal(t, "Suricata.TFTP", parser.LogType())
}
