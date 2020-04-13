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
func TestDnp3(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2004-10-11T14:42:34.654966+0000", "flow_id": 666950899079861, "pcap_cnt": 85, "event_type": "dnp3", "src_ip": "10.0.0.9", "src_port": 1080, "dest_ip": "10.0.0.3", "dest_port": 20000, "proto": "006", "community_id": "1:YkWLtzU54bfAi7vaBG0GEtUooh8=", "dnp3": {"type": "unsolicited_response", "control": {"dir": false, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 4, "dst": 6, "application": {"control": {"fir": true, "fin": true, "con": true, "uns": true, "sequence": 9}, "function_code": 130, "objects": [], "complete": true}, "iin": {"indicators": ["device_restart"]}}, "pcap_filename": "/pcaps/DNP3-TestDataPart1.pcap"}`,
		`{"timestamp": "2011-12-26T16:25:27.347046+0000", "flow_id": 369348396399124, "pcap_cnt": 5, "event_type": "dnp3", "src_ip": "130.126.142.250", "src_port": 50059, "dest_ip": "130.126.140.229", "dest_port": 20000, "proto": "006", "community_id": "1:s2RR6y3tjg8tYDy+5cqNeJSunr0=", "dnp3": {"type": "request", "control": {"dir": true, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 3, "dst": 2, "application": {"control": {"fir": true, "fin": true, "con": false, "uns": false, "sequence": 11}, "function_code": 20, "objects": [{"group": 60, "variation": 2, "qualifier": 6, "prefix_code": 0, "range_code": 6, "start": 0, "stop": 0, "count": 0}, {"group": 60, "variation": 3, "qualifier": 6, "prefix_code": 0, "range_code": 6, "start": 0, "stop": 0, "count": 0}, {"group": 60, "variation": 4, "qualifier": 6, "prefix_code": 0, "range_code": 6, "start": 0, "stop": 0, "count": 0}], "complete": true}}, "pcap_filename": "/pcaps/dnp3_en_spon.pcap"}`,
		`{"timestamp": "2011-12-28T01:33:37.158535+0000", "flow_id": 698069388254487, "pcap_cnt": 19, "event_type": "dnp3", "src_ip": "130.126.142.250", "src_port": 50276, "dest_ip": "130.126.140.229", "dest_port": 20000, "proto": "006", "community_id": "1:ZawXCuVv/X4UgTLF9n7dwGbOawo=", "dnp3": {"type": "request", "control": {"dir": true, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 3, "dst": 4, "application": {"control": {"fir": true, "fin": true, "con": false, "uns": false, "sequence": 0}, "function_code": 2, "objects": [{"group": 50, "variation": 1, "qualifier": 7, "prefix_code": 0, "range_code": 7, "start": 0, "stop": 0, "count": 1, "points": [{"prefix": 0, "index": 0, "timestamp": 1324573673682}]}], "complete": true}}, "pcap_filename": "/pcaps/dnp3_file_read.pcap"}`,
		`{"timestamp": "2011-12-28T01:33:42.509281+0000", "flow_id": 698069388254487, "pcap_cnt": 25, "event_type": "dnp3", "src_ip": "130.126.142.250", "src_port": 50276, "dest_ip": "130.126.140.229", "dest_port": 20000, "proto": "006", "community_id": "1:ZawXCuVv/X4UgTLF9n7dwGbOawo=", "dnp3": {"type": "request", "control": {"dir": true, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 3, "dst": 4, "application": {"control": {"fir": true, "fin": true, "con": false, "uns": false, "sequence": 2}, "function_code": 26, "objects": [{"group": 70, "variation": 4, "qualifier": 91, "prefix_code": 5, "range_code": 11, "start": 0, "stop": 0, "count": 1, "points": [{"prefix": 13, "index": 0, "size": 13, "file_handle": 305419896, "file_size": 0, "maximum_block_size": 0, "request_id": 5, "status_code": 0, "optional_text": ""}]}], "complete": true}}, "pcap_filename": "/pcaps/dnp3_file_read.pcap"}`,
		`{"timestamp": "2011-12-28T01:33:32.837357+0000", "flow_id": 698069388254487, "pcap_cnt": 8, "event_type": "dnp3", "src_ip": "130.126.142.250", "src_port": 50276, "dest_ip": "130.126.140.229", "dest_port": 20000, "proto": "006", "community_id": "1:ZawXCuVv/X4UgTLF9n7dwGbOawo=", "dnp3": {"type": "request", "control": {"dir": true, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 3, "dst": 4, "application": {"control": {"fir": true, "fin": true, "con": false, "uns": false, "sequence": 15}, "function_code": 1, "objects": [{"group": 70, "variation": 5, "qualifier": 91, "prefix_code": 5, "range_code": 11, "start": 0, "stop": 0, "count": 1, "points": [{"prefix": 8, "index": 0, "size": 8, "file_handle": 305419896, "block_number": 0, "file_data": ""}]}], "complete": true}}, "pcap_filename": "/pcaps/dnp3_file_read.pcap"}`,
		`{"timestamp": "2011-12-28T01:33:39.982095+0000", "flow_id": 698069388254487, "pcap_cnt": 22, "event_type": "dnp3", "src_ip": "130.126.142.250", "src_port": 50276, "dest_ip": "130.126.140.229", "dest_port": 20000, "proto": "006", "community_id": "1:ZawXCuVv/X4UgTLF9n7dwGbOawo=", "dnp3": {"type": "request", "control": {"dir": true, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 3, "dst": 4, "application": {"control": {"fir": true, "fin": true, "con": false, "uns": false, "sequence": 1}, "function_code": 2, "objects": [{"group": 50, "variation": 1, "qualifier": 7, "prefix_code": 0, "range_code": 7, "start": 0, "stop": 0, "count": 1, "points": [{"prefix": 0, "index": 0, "timestamp": 1324573673780}]}], "complete": true}}, "pcap_filename": "/pcaps/dnp3_file_read.pcap"}`,
		`{"timestamp": "2011-12-28T01:33:42.300845+0000", "flow_id": 698069388254487, "pcap_cnt": 24, "event_type": "dnp3", "src_ip": "130.126.142.250", "src_port": 50276, "dest_ip": "130.126.140.229", "dest_port": 20000, "proto": "006", "community_id": "1:ZawXCuVv/X4UgTLF9n7dwGbOawo=", "dnp3": {"type": "response", "control": {"dir": false, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 4, "dst": 3, "application": {"control": {"fir": true, "fin": true, "con": false, "uns": false, "sequence": 1}, "function_code": 129, "objects": [], "complete": true}, "iin": {"indicators": []}}, "pcap_filename": "/pcaps/dnp3_file_read.pcap"}`,
		`{"timestamp": "2011-12-28T01:33:30.840568+0000", "flow_id": 698069388254487, "pcap_cnt": 5, "event_type": "dnp3", "src_ip": "130.126.142.250", "src_port": 50276, "dest_ip": "130.126.140.229", "dest_port": 20000, "proto": "006", "community_id": "1:ZawXCuVv/X4UgTLF9n7dwGbOawo=", "dnp3": {"type": "request", "control": {"dir": true, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 3, "dst": 4, "application": {"control": {"fir": true, "fin": true, "con": false, "uns": false, "sequence": 14}, "function_code": 25, "objects": [{"group": 70, "variation": 3, "qualifier": 91, "prefix_code": 5, "range_code": 11, "start": 0, "stop": 0, "count": 1, "points": [{"prefix": 36, "index": 0, "size": 36, "filename_offset": 26, "filename_size": 10, "created": 0, "permissions": 0, "authentication_key": 0, "file_size": 0, "operational_mode": 1, "maximum_block_size": 1024, "request_id": 4, "filename": "./test.xml"}]}], "complete": true}}, "pcap_filename": "/pcaps/dnp3_file_read.pcap"}`,
		`{"timestamp": "2011-12-28T03:53:00.002382+0000", "flow_id": 1579163149867677, "pcap_cnt": 9, "event_type": "dnp3", "src_ip": "130.126.142.250", "src_port": 50301, "dest_ip": "130.126.140.229", "dest_port": 20000, "proto": "006", "community_id": "1:1+mejUFFvt57BfrFFr/J0jlWyCw=", "dnp3": {"type": "response", "control": {"dir": false, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 4, "dst": 3, "application": {"control": {"fir": true, "fin": true, "con": false, "uns": false, "sequence": 9}, "function_code": 129, "objects": [{"group": 70, "variation": 4, "qualifier": 91, "prefix_code": 5, "range_code": 11, "start": 0, "stop": 0, "count": 1, "points": [{"prefix": 13, "index": 0, "size": 13, "file_handle": 0, "file_size": 0, "maximum_block_size": 0, "request_id": 30, "status_code": 0, "optional_text": ""}]}], "complete": true}, "iin": {"indicators": []}}, "pcap_filename": "/pcaps/dnp3_file_del.pcap"}`,
		`{"timestamp": "2015-10-22T08:45:53.774162+0000", "flow_id": 837014538155509, "pcap_cnt": 834231, "event_type": "dnp3", "src_ip": "192.168.2.166", "src_port": 2137, "dest_ip": "192.168.88.95", "dest_port": 20000, "proto": "006", "community_id": "1:D6M0MhRTeIjrxl4Rh9d7AXfzmgE=", "dnp3": {"type": "request", "control": {"dir": false, "pri": true, "fcb": false, "fcv": false, "function_code": 4}, "src": 1024, "dst": 1, "application": {"control": {"fir": true, "fin": true, "con": true, "uns": true, "sequence": 2}, "function_code": 130, "objects": [], "complete": false}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
	}

	parser := &Dnp3Parser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestDnp3Type(t *testing.T) {
	parser := &Dnp3Parser{}
	require.Equal(t, "Suricata.Dnp3", parser.LogType())
}
