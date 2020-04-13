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
func TestSnmp(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2002-02-25T03:50:41.214234+0000", "flow_id": 2195109266224935, "pcap_cnt": 4348, "event_type": "snmp", "src_ip": "192.168.0.1", "src_port": 161, "dest_ip": "192.168.0.2", "dest_port": 1040, "proto": "017", "community_id": "1:rsodNZpZl6krPl4TgJlMQpfzB3g=", "snmp": {"version": 1, "pdu_type": "response", "vars": ["1.3.6.1.2.1.1.5.0"], "community": "public"}, "pcap_filename": "/pcaps/c06-snmpv1-req-enc-r1.pcap"}`,
		`{"timestamp": "2002-02-25T03:48:37.967055+0000", "flow_id": 2195109266224935, "pcap_cnt": 460, "event_type": "snmp", "src_ip": "192.168.0.1", "src_port": 161, "dest_ip": "192.168.0.2", "dest_port": 1040, "proto": "017", "community_id": "1:rsodNZpZl6krPl4TgJlMQpfzB3g=", "snmp": {"version": 1, "pdu_type": "response", "vars": ["1.3.6.1.2.1.1.5.0"], "community": "public"}, "pcap_filename": "/pcaps/c06-snmpv1-req-enc-r1.pcap"}`,
		`{"timestamp": "2002-02-25T04:08:47.660083+0000", "flow_id": 1884608947690233, "pcap_cnt": 12276, "event_type": "snmp", "src_ip": "192.168.0.2", "src_port": 1040, "dest_ip": "192.168.0.1", "dest_port": 162, "proto": "017", "community_id": "1:gBANVIRhk61JdkP0mSoqMKpEEP0=", "snmp": {"version": 1, "pdu_type": "trap_v1", "trap_type": "authenticationFailure", "trap_oid": "1.3.6.1.4.1.4.1.2.21", "trap_address": "127.0.0.1", "community": "public"}, "pcap_filename": "/pcaps/c06-snmpv1-trap-app-r1.pcap"}`,
		`{"timestamp": "2002-02-25T03:54:49.188569+0000", "flow_id": 2195109266224935, "pcap_cnt": 12427, "event_type": "snmp", "src_ip": "192.168.0.1", "src_port": 161, "dest_ip": "192.168.0.2", "dest_port": 1040, "proto": "017", "community_id": "1:rsodNZpZl6krPl4TgJlMQpfzB3g=", "snmp": {"version": 1, "pdu_type": "response", "vars": ["1.3.6.1.2.1.1.6.0"], "community": "public"}, "pcap_filename": "/pcaps/c06-snmpv1-req-enc-r1.pcap"}`,
		`{"timestamp": "2002-02-25T03:42:48.363139+0000", "flow_id": 1331812225556695, "pcap_cnt": 787, "event_type": "snmp", "src_ip": "192.168.0.1", "src_port": 161, "dest_ip": "192.168.0.2", "dest_port": 1040, "proto": "017", "community_id": "1:rsodNZpZl6krPl4TgJlMQpfzB3g=", "snmp": {"version": 1, "pdu_type": "response", "vars": ["1.3.6.1.2.1.1.5.0"], "community": "public"}, "pcap_filename": "/pcaps/c06-snmpv1-req-app-r1.pcap"}`,
		`{"timestamp": "2002-02-25T03:43:38.486706+0000", "flow_id": 1331812225556695, "pcap_cnt": 2838, "event_type": "snmp", "src_ip": "192.168.0.2", "src_port": 1040, "dest_ip": "192.168.0.1", "dest_port": 161, "proto": "017", "community_id": "1:rsodNZpZl6krPl4TgJlMQpfzB3g=", "snmp": {"version": 1, "pdu_type": "get_request", "vars": ["1.3.6.1.2.1.1.5.0"], "community": "public@1111111111111111\\x001111111111111111"}, "pcap_filename": "/pcaps/c06-snmpv1-req-app-r1.pcap"}`,
		`{"timestamp": "2002-02-25T04:00:08.034086+0000", "flow_id": 2195109266224935, "pcap_cnt": 21210, "event_type": "snmp", "src_ip": "192.168.0.2", "src_port": 1040, "dest_ip": "192.168.0.1", "dest_port": 161, "proto": "017", "community_id": "1:rsodNZpZl6krPl4TgJlMQpfzB3g=", "snmp": {"version": 1, "pdu_type": "set_request", "vars": ["1.3.6.1.2.1.1.5.0"], "community": "public"}, "pcap_filename": "/pcaps/c06-snmpv1-req-enc-r1.pcap"}`,
		`{"timestamp": "2002-02-25T03:58:16.945343+0000", "flow_id": 2195109266224935, "pcap_cnt": 18446, "event_type": "snmp", "src_ip": "192.168.0.2", "src_port": 1040, "dest_ip": "192.168.0.1", "dest_port": 161, "proto": "017", "community_id": "1:rsodNZpZl6krPl4TgJlMQpfzB3g=", "snmp": {"version": 1, "pdu_type": "set_request", "vars": ["1.3.6.1.2.1.1.5.0"], "community": "public"}, "pcap_filename": "/pcaps/c06-snmpv1-req-enc-r1.pcap"}`,
		`{"timestamp": "2002-02-25T03:44:18.345244+0000", "flow_id": 1331812225556695, "pcap_cnt": 5577, "event_type": "snmp", "src_ip": "192.168.0.1", "src_port": 161, "dest_ip": "192.168.0.2", "dest_port": 1040, "proto": "017", "community_id": "1:rsodNZpZl6krPl4TgJlMQpfzB3g=", "snmp": {"version": 1, "pdu_type": "response", "vars": ["1.3.6.1.2.1.1.5.0"], "community": "public"}, "pcap_filename": "/pcaps/c06-snmpv1-req-app-r1.pcap"}`,
		`{"timestamp": "2008-11-26T20:04:48.988485+0000", "flow_id": 274111991387014, "pcap_cnt": 2, "event_type": "snmp", "src_ip": "127.0.0.1", "src_port": 161, "dest_ip": "127.0.0.1", "dest_port": 54211, "proto": "017", "community_id": "1:WT53xusRFy+5Yn4MtcENcXEADyI=", "snmp": {"version": 3, "pdu_type": "report", "vars": ["1.3.6.1.6.3.15.1.1.0"], "usm": ""}, "pcap_filename": "/pcaps/snmpv3_get_next.pcap"}`,
	}

	parser := &SnmpParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestSnmpType(t *testing.T) {
	parser := &SnmpParser{}
	require.Equal(t, "Suricata.Snmp", parser.LogType())
}
