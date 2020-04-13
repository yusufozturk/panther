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
func TestDNS(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2015-10-22T06:31:06.520370+0000", "flow_id": 188564141437106, "pcap_cnt": 229108, "event_type": "dns", "src_ip": "192.168.89.2", "src_port": 27864, "dest_ip": "8.8.8.8", "dest_port": 53, "proto": "017", "community_id": "1:2lDamoPjfWU3FGYJXWeXwZwtza4=", "dns": {"type": "query", "id": 62705, "rrname": "localhost", "rrtype": "A", "tx_id": 0}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T06:33:45.364388+0000", "flow_id": 1650515353776555, "pcap_cnt": 230388, "event_type": "dns", "src_ip": "192.168.88.1", "src_port": 53, "dest_ip": "192.168.88.61", "dest_port": 949, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"version": 2, "type": "answer", "id": 48966, "flags": "8185", "qr": true, "rd": true, "ra": true, "rrname": "time.nist.gov", "rrtype": "A", "rcode": "REFUSED"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-20T15:29:24.333602+0000", "flow_id": 1586708448149926, "pcap_cnt": 1211, "event_type": "dns", "src_ip": "192.168.88.1", "src_port": 53, "dest_ip": "192.168.88.61", "dest_port": 949, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"version": 2, "type": "answer", "id": 44377, "flags": "8185", "qr": true, "rd": true, "ra": true, "rrname": "time.nist.gov", "rrtype": "A", "rcode": "REFUSED"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151020.pcap"}`,
		`{"timestamp": "2015-10-20T15:15:23.465263+0000", "flow_id": 1586708448149926, "pcap_cnt": 421, "event_type": "dns", "src_ip": "192.168.88.61", "src_port": 949, "dest_ip": "192.168.88.1", "dest_port": 53, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"type": "query", "id": 43958, "rrname": "time.nist.gov", "rrtype": "A", "tx_id": 288}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151020.pcap"}`,
		`{"timestamp": "2015-10-22T03:04:33.993357+0000", "flow_id": 1650515353776555, "pcap_cnt": 134467, "event_type": "dns", "src_ip": "192.168.88.61", "src_port": 949, "dest_ip": "192.168.88.1", "dest_port": 53, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"type": "query", "id": 42708, "rrname": "time.nist.gov", "rrtype": "A", "tx_id": 17584}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T05:40:57.074600+0000", "flow_id": 334917102281576, "pcap_cnt": 206164, "event_type": "dns", "src_ip": "192.168.89.2", "src_port": 52240, "dest_ip": "8.8.8.8", "dest_port": 53, "proto": "017", "community_id": "1:hjfX/0Tzbpv6sThOSkREyEhJJ8g=", "dns": {"type": "query", "id": 53025, "rrname": "localhost", "rrtype": "A", "tx_id": 0}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-20T15:41:28.832299+0000", "flow_id": 1586708448149926, "pcap_cnt": 8359, "event_type": "dns", "src_ip": "192.168.88.61", "src_port": 949, "dest_ip": "192.168.88.1", "dest_port": 53, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"type": "query", "id": 44738, "rrname": "time.nist.gov", "rrtype": "A", "tx_id": 1530}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151020.pcap"}`,
		`{"timestamp": "2016-08-19T17:35:33.997159+0000", "flow_id": 1547576631703331, "pcap_cnt": 780, "event_type": "dns", "src_ip": "192.168.1.195", "src_port": 63448, "dest_ip": "192.168.1.1", "dest_port": 53, "proto": "017", "community_id": "1:UGelqfOZ1E9fpEzxDHHg0ez4twc=", "dns": {"type": "query", "id": 36990, "rrname": "", "rrtype": "NS", "tx_id": 1}, "pcap_filename": "/pcaps/aug19.pcap"}`,
		`{"timestamp": "2017-03-17T03:27:32.934794+0000", "flow_id": 338045461349258, "pcap_cnt": 3356, "event_type": "dns", "src_ip": "192.168.1.46", "src_port": 54977, "dest_ip": "192.168.1.195", "dest_port": 53, "proto": "017", "community_id": "1:vyEaRqrsyhl5zIHfsPLHgNCKmp8=", "dns": {"type": "query", "id": 27385, "rrname": "www.millsborochamber.com", "rrtype": "A", "tx_id": 0}, "pcap_filename": "/pcaps/malware_infection.pcap"}`,
		`{"timestamp": "2015-10-22T09:25:14.655886+0000", "flow_id": 1650515353776555, "pcap_cnt": 1253022, "event_type": "dns", "src_ip": "192.168.88.1", "src_port": 53, "dest_ip": "192.168.88.61", "dest_port": 949, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"version": 2, "type": "answer", "id": 683, "flags": "8185", "qr": true, "rd": true, "ra": true, "rrname": "time.nist.gov", "rrtype": "A", "rcode": "REFUSED"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
	}

	parser := &DNSParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestDNSType(t *testing.T) {
	parser := &DNSParser{}
	require.Equal(t, "Suricata.DNS", parser.LogType())
}
