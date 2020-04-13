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
func TestDrop(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2004-05-13T10:17:09.864896+0000", "flow_id": 49777784111032, "pcap_cnt": 12, "event_type": "drop", "src_ip": "145.254.160.237", "src_port": 3372, "dest_ip": "65.208.228.223", "dest_port": 80, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 40, "tos": 0, "ttl": 128, "ipid": 3912, "tcpseq": 951058419, "tcpack": 290223900, "tcpwin": 9660, "syn": false, "ack": true, "psh": false, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
		`{"timestamp": "2004-05-13T10:17:09.864896+0000", "flow_id": 49777784111032, "pcap_cnt": 11, "event_type": "drop", "src_ip": "65.208.228.223", "src_port": 80, "dest_ip": "145.254.160.237", "dest_port": 3372, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 1420, "tos": 0, "ttl": 47, "ipid": 49314, "tcpseq": 290222520, "tcpack": 951058419, "tcpwin": 6432, "syn": false, "ack": true, "psh": true, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
		`{"timestamp": "2004-05-13T10:17:09.945011+0000", "flow_id": 49777784111032, "pcap_cnt": 14, "event_type": "drop", "src_ip": "65.208.228.223", "src_port": 80, "dest_ip": "145.254.160.237", "dest_port": 3372, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 1420, "tos": 0, "ttl": 47, "ipid": 49315, "tcpseq": 290223900, "tcpack": 951058419, "tcpwin": 6432, "syn": false, "ack": true, "psh": false, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
		`{"timestamp": "2004-05-13T10:17:08.993643+0000", "flow_id": 49777784111032, "pcap_cnt": 6, "event_type": "drop", "src_ip": "65.208.228.223", "src_port": 80, "dest_ip": "145.254.160.237", "dest_port": 3372, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 1420, "tos": 0, "ttl": 47, "ipid": 49311, "tcpseq": 290218380, "tcpack": 951058419, "tcpwin": 6432, "syn": false, "ack": true, "psh": false, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
		`{"timestamp": "2004-05-13T10:17:09.324118+0000", "flow_id": 49777784111032, "pcap_cnt": 9, "event_type": "drop", "src_ip": "145.254.160.237", "src_port": 3372, "dest_ip": "65.208.228.223", "dest_port": 80, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 40, "tos": 0, "ttl": 128, "ipid": 3911, "tcpseq": 951058419, "tcpack": 290221140, "tcpwin": 9660, "syn": false, "ack": true, "psh": false, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
		`{"timestamp": "2004-05-13T10:17:09.123830+0000", "flow_id": 49777784111032, "pcap_cnt": 8, "event_type": "drop", "src_ip": "65.208.228.223", "src_port": 80, "dest_ip": "145.254.160.237", "dest_port": 3372, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 1420, "tos": 0, "ttl": 47, "ipid": 49312, "tcpseq": 290219760, "tcpack": 951058419, "tcpwin": 6432, "syn": false, "ack": true, "psh": false, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
		`{"timestamp": "2004-05-13T10:17:10.125270+0000", "flow_id": 49777784111032, "pcap_cnt": 15, "event_type": "drop", "src_ip": "145.254.160.237", "src_port": 3372, "dest_ip": "65.208.228.223", "dest_port": 80, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 40, "tos": 0, "ttl": 128, "ipid": 3914, "tcpseq": 951058419, "tcpack": 290225280, "tcpwin": 9660, "syn": false, "ack": true, "psh": false, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
		`{"timestamp": "2004-05-13T10:17:08.783340+0000", "flow_id": 49777784111032, "pcap_cnt": 5, "event_type": "drop", "src_ip": "65.208.228.223", "src_port": 80, "dest_ip": "145.254.160.237", "dest_port": 3372, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 40, "tos": 0, "ttl": 47, "ipid": 49310, "tcpseq": 290218380, "tcpack": 951058419, "tcpwin": 6432, "syn": false, "ack": true, "psh": false, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
		`{"timestamp": "2004-05-13T10:17:08.222534+0000", "flow_id": 49777784111032, "pcap_cnt": 4, "event_type": "drop", "src_ip": "145.254.160.237", "src_port": 3372, "dest_ip": "65.208.228.223", "dest_port": 80, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 519, "tos": 0, "ttl": 128, "ipid": 3909, "tcpseq": 951057940, "tcpack": 290218380, "tcpwin": 9660, "syn": false, "ack": true, "psh": true, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "alert": {"action": "blocked", "gid": 1, "signature_id": 125, "rev": 0, "signature": "FOO DROP", "category": "", "severity": 3}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
		`{"timestamp": "2004-05-13T10:17:09.123830+0000", "flow_id": 49777784111032, "pcap_cnt": 7, "event_type": "drop", "src_ip": "145.254.160.237", "src_port": 3372, "dest_ip": "65.208.228.223", "dest_port": 80, "proto": "006", "community_id": "1:oV2h5jcDdLnxQ1pF8Zr+7II/a/Y=", "drop": {"len": 40, "tos": 0, "ttl": 128, "ipid": 3910, "tcpseq": 951058419, "tcpack": 290219760, "tcpwin": 9660, "syn": false, "ack": true, "psh": false, "rst": false, "urg": false, "fin": false, "tcpres": 0, "tcpurgp": 0}, "pcap_filename": "/pcaps/http_drop.pcap"}`,
	}

	parser := &DropParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestDropType(t *testing.T) {
	parser := &DropParser{}
	require.Equal(t, "Suricata.Drop", parser.LogType())
}
