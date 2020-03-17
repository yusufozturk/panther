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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestSSH(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	//nolint:lll
	logs := `{"timestamp": "2019-01-02T05:21:26.613816", "flow_id": 43508416, "in_iface": "eth0", "event_type": "ssh", "src_ip": "8.42.77.171", "src_port": 61310, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
{"timestamp": "2019-01-02T05:21:26.823883", "flow_id": 43508752, "in_iface": "eth0", "event_type": "ssh", "src_ip": "8.42.77.171", "src_port": 61311, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
{"timestamp": "2019-01-02T05:30:01.650883", "flow_id": 43515136, "in_iface": "eth0", "event_type": "ssh", "src_ip": "5.101.40.81", "src_port": 33427, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "2.0", "software_version": "OpenSSH_7.3"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
{"timestamp": "2019-01-02T06:52:19.179354", "flow_id": 43597120, "in_iface": "eth0", "event_type": "ssh", "src_ip": "8.42.77.171", "src_port": 62161, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "2.0", "software_version": "OpenSSH_7.7"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
{"timestamp": "2019-01-02T05:21:26.392373", "flow_id": 43508080, "in_iface": "eth0", "event_type": "ssh", "src_ip": "8.42.77.171", "src_port": 61309, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
{"timestamp": "2019-01-02T05:39:44.059838", "flow_id": 43526224, "in_iface": "eth0", "event_type": "ssh", "src_ip": "8.42.77.171", "src_port": 61518, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "2.0", "software_version": "OpenSSH_7.7"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
{"timestamp": "2019-01-02T05:21:26.279908", "flow_id": 43507744, "in_iface": "eth0", "event_type": "ssh", "src_ip": "8.42.77.171", "src_port": 61308, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
{"timestamp": "2019-01-02T05:21:27.048885", "flow_id": 43509424, "in_iface": "eth0", "event_type": "ssh", "src_ip": "8.42.77.171", "src_port": 61313, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
{"timestamp": "2019-01-02T05:34:42.131736", "flow_id": 43521184, "in_iface": "eth0", "event_type": "ssh", "src_ip": "51.254.47.198", "src_port": 47210, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "2.0", "software_version": "libssh2_1.7.0"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
{"timestamp": "2019-01-02T05:21:26.172843", "flow_id": 43507408, "in_iface": "eth0", "event_type": "ssh", "src_ip": "8.42.77.171", "src_port": 61307, "dest_ip": "138.68.3.71", "dest_port": 22, "proto": "TCP", "ssh": {"client": {"proto_version": "1.5", "software_version": "NmapNSE_1.0"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_7.2p2 Ubuntu-4ubuntu2.6"}}}
`

	parser := &SSHParser{}
	lines := strings.FieldsFunc(logs, func(r rune) bool { return r == '\n' })
	for _, line := range lines {
		events := parser.Parse(line)
		require.Equal(t, 1, len(events))
	}
}

func TestSSHType(t *testing.T) {
	parser := &SSHParser{}
	require.Equal(t, "Suricata.SSH", parser.LogType())
}
