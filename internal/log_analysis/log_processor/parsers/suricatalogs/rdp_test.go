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
func TestRdp(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2017-03-01T00:33:05.976411+0000", "flow_id": 1421933056954144, "pcap_cnt": 13, "event_type": "rdp", "src_ip": "192.168.1.46", "src_port": 3389, "dest_ip": "192.168.1.195", "dest_port": 49601, "proto": "006", "rdp": {"tx_id": 0, "event_type": "initial_request", "cookie": "PICKLESWO"}, "pcap_filename": "/pcaps/winreg_query_rdp_netshare_madness.pcap"}`,
		`{"timestamp": "2011-02-12T22:50:41.286739+0000", "flow_id": 663059446191118, "pcap_cnt": 5, "event_type": "rdp", "src_ip": "192.168.1.150", "src_port": 3389, "dest_ip": "192.168.1.200", "dest_port": 49206, "proto": "006", "rdp": {"tx_id": 0, "event_type": "initial_request", "cookie": "AWAKECODI"}, "pcap_filename": "/pcaps/rdp-to-ssl.pcap"}`,
		`{"timestamp": "2015-02-12T15:40:02.102611+0000", "flow_id": 668433432173225, "pcap_cnt": 11, "event_type": "rdp", "src_ip": "192.168.1.1", "src_port": 54990, "dest_ip": "192.168.1.2", "dest_port": 3389, "proto": "006", "rdp": {"tx_id": 1, "event_type": "initial_response", "protocol": "rdp"}, "pcap_filename": "/pcaps/rdp-x509.pcap"}`,
		`{"timestamp": "2017-03-01T00:39:51.198995+0000", "flow_id": 308205114029019, "pcap_cnt": 3255, "event_type": "rdp", "src_ip": "192.168.1.195", "src_port": 49618, "dest_ip": "192.168.1.46", "dest_port": 3389, "proto": "006", "rdp": {"tx_id": 1, "event_type": "initial_response", "server_supports": ["extended_client_data"], "protocol": "hybrid"}, "pcap_filename": "/pcaps/winreg_query_rdp_netshare_madness.pcap"}`,
		`{"timestamp": "2017-03-01T00:33:12.110120+0000", "flow_id": 1421933056954144, "pcap_cnt": 22, "event_type": "rdp", "src_ip": "192.168.1.195", "src_port": 49601, "dest_ip": "192.168.1.46", "dest_port": 3389, "proto": "006", "rdp": {"tx_id": 2, "event_type": "tls_handshake", "x509_serials": ["34196c8c69f3369741a23298235eab16"]}, "pcap_filename": "/pcaps/winreg_query_rdp_netshare_madness.pcap"}`,
		`{"timestamp": "2015-02-12T15:40:05.227945+0000", "flow_id": 668433432173225, "event_type": "rdp", "src_ip": "192.168.1.2", "src_port": 3389, "dest_ip": "192.168.1.1", "dest_port": 54990, "proto": "006", "rdp": {"tx_id": 3, "event_type": "connect_response"}, "pcap_filename": "/pcaps/rdp-x509.pcap"}`,
		`{"timestamp": "2017-03-01T00:39:56.841030+0000", "flow_id": 308205114029019, "pcap_cnt": 3262, "event_type": "rdp", "src_ip": "192.168.1.195", "src_port": 49618, "dest_ip": "192.168.1.46", "dest_port": 3389, "proto": "006", "rdp": {"tx_id": 2, "event_type": "tls_handshake", "x509_serials": ["34196c8c69f3369741a23298235eab16"]}, "pcap_filename": "/pcaps/winreg_query_rdp_netshare_madness.pcap"}`,
		`{"timestamp": "2015-02-12T15:40:02.103119+0000", "flow_id": 668433432173225, "pcap_cnt": 12, "event_type": "rdp", "src_ip": "192.168.1.2", "src_port": 3389, "dest_ip": "192.168.1.1", "dest_port": 54990, "proto": "006", "rdp": {"tx_id": 2, "event_type": "connect_request", "client": {"version": "v5", "desktop_width": 1920, "desktop_height": 1080, "color_depth": 16, "keyboard_layout": "en-US", "build": "Windows 8.1", "client_name": "JOHN-PC-LAPTOP", "keyboard_type": "enhanced", "function_keys": 12, "product_id": 1, "capabilities": ["support_errinfo_pdf", "support_statusinfo_pdu", "strong_asymmetric_keys", "valid_connection_type", "support_netchar_autodetect", "support_dynvc_gfx_protocol", "support_dynamic_time_zone", "support_heartbeat_pdu"], "id": "3c571ed0-3415-474b-ae94-74e151b", "connection_hint": "autodetect"}, "channels": ["rdpdr", "rdpsnd", "cliprdr", "drdynvc"]}, "pcap_filename": "/pcaps/rdp-x509.pcap"}`,
		`{"timestamp": "2016-08-16T20:58:45.138852+0000", "flow_id": 708663136544441, "pcap_cnt": 934, "event_type": "rdp", "src_ip": "192.168.1.46", "src_port": 49205, "dest_ip": "192.168.1.195", "dest_port": 3389, "proto": "006", "rdp": {"tx_id": 1, "event_type": "initial_response", "server_supports": ["extended_client_data"], "protocol": "hybrid"}, "pcap_filename": "/pcaps/windows_miscellany.pcap"}`,
		`{"timestamp": "2016-08-16T20:59:28.436426+0000", "flow_id": 1378675890100280, "pcap_cnt": 1039, "event_type": "rdp", "src_ip": "192.168.1.46", "src_port": 49209, "dest_ip": "192.168.1.195", "dest_port": 3389, "proto": "006", "rdp": {"tx_id": 2, "event_type": "tls_handshake", "x509_serials": ["1d54c00226f077bf4037df142462b8fb"]}, "pcap_filename": "/pcaps/windows_miscellany.pcap"}`,
	}

	parser := &RdpParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestRdpType(t *testing.T) {
	parser := &RdpParser{}
	require.Equal(t, "Suricata.Rdp", parser.LogType())
}
