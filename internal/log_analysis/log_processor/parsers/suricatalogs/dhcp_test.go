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
func TestDHCP(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2004-09-30T15:47:02.007701+0000", "flow_id": 612914020324738, "pcap_cnt": 8, "event_type": "dhcp", "src_ip": "0.0.0.0", "src_port": 68, "dest_ip": "255.255.255.255", "dest_port": 67, "proto": "017", "dhcp": {"type": "request", "id": 4261977109, "client_mac": "00:50:ba:12:47:cb", "assigned_ip": "0.0.0.0", "client_ip": "0.0.0.0", "dhcp_type": "request", "client_id": "00:50:ba:12:47:cb", "requested_ip": "10.20.20.20", "hostname": "academy04", "params": ["subnet_mask", "domain", "router", "dns_server"]}, "pcap_filename": "/pcaps/dhcp-and-dyndns.pcap"}`,
		`{"timestamp": "2019-03-26T19:34:47.168518+0000", "flow_id": 204966557356600, "pcap_cnt": 1151, "event_type": "dhcp", "src_ip": "192.168.1.62", "src_port": 68, "dest_ip": "255.255.255.255", "dest_port": 67, "proto": "017", "dhcp": {"type": "request", "id": 3405464434, "client_mac": "08:00:27:f0:68:53", "assigned_ip": "0.0.0.0", "client_ip": "192.168.1.62", "dhcp_type": "inform", "client_id": "08:00:27:f0:68:53", "hostname": "SnickleFritz", "params": ["subnet_mask", "domain", "router", "dns_server"]}, "pcap_filename": "/pcaps/wmi-service-remote.pcap"}`,
		`{"timestamp": "2005-07-04T09:51:57.078746+0000", "flow_id": 901423554179994, "pcap_cnt": 484, "event_type": "dhcp", "src_ip": "192.168.1.2", "src_port": 68, "dest_ip": "192.168.1.1", "dest_port": 67, "proto": "017", "dhcp": {"type": "request", "id": 107809848, "client_mac": "00:e0:ed:01:6e:bd", "assigned_ip": "0.0.0.0", "client_ip": "192.168.1.2", "dhcp_type": "request", "client_id": "00:e0:ed:01:6e:bd", "hostname": "d002465", "params": ["subnet_mask", "domain", "router", "dns_server"]}, "pcap_filename": "/pcaps/aaa.pcap"}`,
		`{"timestamp": "2018-04-09T15:18:47.207446+0000", "flow_id": 1329462088318932, "pcap_cnt": 1696, "event_type": "dhcp", "src_ip": "0.0.0.0", "src_port": 68, "dest_ip": "255.255.255.255", "dest_port": 67, "proto": "017", "dhcp": {"type": "request", "id": 393321999, "client_mac": "00:0c:29:7f:a9:1d", "assigned_ip": "0.0.0.0", "client_ip": "0.0.0.0", "dhcp_type": "discover", "client_id": "00:0c:29:7f:a9:1d", "params": ["subnet_mask", "router", "domain", "dns_server", "ntp_server"]}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2019-03-26T19:35:49.623568+0000", "flow_id": 204966557356600, "pcap_cnt": 6136, "event_type": "dhcp", "src_ip": "192.168.1.62", "src_port": 68, "dest_ip": "255.255.255.255", "dest_port": 67, "proto": "017", "dhcp": {"type": "request", "id": 223436435, "client_mac": "08:00:27:f0:68:53", "assigned_ip": "0.0.0.0", "client_ip": "192.168.1.62", "dhcp_type": "inform", "client_id": "08:00:27:f0:68:53", "hostname": "SnickleFritz", "params": ["subnet_mask", "domain", "router", "dns_server"]}, "pcap_filename": "/pcaps/wmi-service-remote.pcap"}`,
		`{"timestamp": "2006-10-11T09:34:36.933310+0000", "flow_id": 1027591237287358, "pcap_cnt": 1, "event_type": "dhcp", "src_ip": "0.0.0.0", "src_port": 68, "dest_ip": "255.255.255.255", "dest_port": 67, "proto": "017", "dhcp": {"type": "request", "id": 2888761343, "client_mac": "00:00:6c:82:dc:4e", "assigned_ip": "0.0.0.0", "client_ip": "0.0.0.0", "dhcp_type": "discover", "params": ["subnet_mask", "router"], "lease_time": 3600}, "pcap_filename": "/pcaps/PRIV_bootp-both_overload_empty-no_end.pcap"}`,
		`{"timestamp": "2004-12-05T19:16:24.387484+0000", "flow_id": 1499613039745037, "pcap_cnt": 3, "event_type": "dhcp", "src_ip": "0.0.0.0", "src_port": 68, "dest_ip": "255.255.255.255", "dest_port": 67, "proto": "017", "dhcp": {"type": "request", "id": 15646, "client_mac": "00:0b:82:01:fc:42", "assigned_ip": "0.0.0.0", "client_ip": "0.0.0.0", "dhcp_type": "request", "client_id": "00:0b:82:01:fc:42", "requested_ip": "192.168.0.10", "params": ["subnet_mask", "router", "dns_server", "ntp_server"]}, "pcap_filename": "/pcaps/dhcp-nanosecond.pcap"}`,
		`{"timestamp": "2018-04-09T15:16:29.622262+0000", "flow_id": 1329462088318932, "pcap_cnt": 811, "event_type": "dhcp", "src_ip": "0.0.0.0", "src_port": 68, "dest_ip": "255.255.255.255", "dest_port": 67, "proto": "017", "dhcp": {"type": "request", "id": 359767567, "client_mac": "00:0c:29:7f:a9:1d", "assigned_ip": "0.0.0.0", "client_ip": "0.0.0.0", "dhcp_type": "discover", "client_id": "00:0c:29:7f:a9:1d", "params": ["subnet_mask", "router", "domain", "dns_server", "ntp_server"]}, "pcap_filename": "/pcaps/uaudp_ipv6.pcap"}`,
		`{"timestamp": "2009-11-06T21:31:28.201175+0000", "flow_id": 2098321604449212, "pcap_cnt": 7467, "event_type": "dhcp", "src_ip": "192.168.1.5", "src_port": 67, "dest_ip": "255.255.255.255", "dest_port": 68, "proto": "017", "dhcp": {"type": "reply", "id": 3146297458, "client_mac": "00:00:00:00:00:00", "assigned_ip": "0.0.0.0", "client_ip": "192.168.1.5", "relay_ip": "0.0.0.0", "next_server_ip": "0.0.0.0", "dhcp_type": "ack", "subnet_mask": "0.0.0.0"}, "pcap_filename": "/pcaps/tridium-jace2.pcap"}`,
		`{"timestamp": "2008-11-12T21:30:24.491001+0000", "flow_id": 1649502773191881, "pcap_cnt": 3359, "event_type": "dhcp", "src_ip": "192.168.10.105", "src_port": 67, "dest_ip": "255.255.255.255", "dest_port": 68, "proto": "017", "dhcp": {"type": "reply", "id": 1474050994, "client_mac": "00:00:bc:3e:eb:e4", "assigned_ip": "192.168.10.120", "client_ip": "0.0.0.0", "relay_ip": "0.0.0.0", "next_server_ip": "192.168.10.105", "subnet_mask": "255.255.255.0", "routers": ["192.168.10.1"], "hostname": "ConLgxEIP"}, "pcap_filename": "/pcaps/EIP-IPAddressChangeAttempt.pcap"}`,
	}

	parser := &DHCPParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestDHCPType(t *testing.T) {
	parser := &DHCPParser{}
	require.Equal(t, "Suricata.DHCP", parser.LogType())
}
