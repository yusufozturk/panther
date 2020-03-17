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

func TestSMTP(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	//nolint:lll
	logs := `{"timestamp": "2017-03-25T04:06:49.264648-0600", "flow_id": 2093638737172268, "pcap_cnt": 404753, "event_type": "smtp", "src_ip": "10.197.244.240", "src_port": 45452, "dest_ip": "10.10.3.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<tkauffman@mee3.seeks>", "rcpt_to": ["<rridley@mee3.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "tkauffman@mee3.seeks", "to": ["rridley@mee3.seeks"]}}
{"timestamp": "2017-03-24T17:23:55.883114-0600", "flow_id": 340898710094962, "pcap_cnt": 566241, "event_type": "smtp", "src_ip": "10.213.217.121", "src_port": 41289, "dest_ip": "172.16.37.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "sseclone5.wrccdc.secure", "mail_from": "<jgreer@spytellite7.com>", "rcpt_to": ["<jbenjamin@spytellite7.com>"]}, "email": {"status": "HEADER_READY"}}
{"timestamp": "2017-03-25T10:08:44.430630-0600", "flow_id": 1513428733316743, "pcap_cnt": 568973, "event_type": "smtp", "src_ip": "10.223.33.105", "src_port": 33665, "dest_ip": "10.10.2.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<jroiland@mee2.seeks>", "rcpt_to": ["<rridley@mee2.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "jroiland@mee2.seeks", "to": ["rridley@mee2.seeks"]}}
{"timestamp": "2017-03-25T00:18:27.321305-0600", "flow_id": 1950823734156384, "pcap_cnt": 157226, "event_type": "smtp", "src_ip": "10.196.187.58", "src_port": 54106, "dest_ip": "10.10.6.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<rridley@mee6.seeks>", "rcpt_to": ["<jroiland@mee6.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "rridley@mee6.seeks", "to": ["jroiland@mee6.seeks"]}}
{"timestamp": "2017-03-24T20:08:07.654628-0600", "flow_id": 1742574818022377, "pcap_cnt": 1014187, "event_type": "smtp", "src_ip": "10.226.13.99", "src_port": 51347, "dest_ip": "10.10.7.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<jroiland@mee7.seeks>", "rcpt_to": ["<jroiland@mee7.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "jroiland@mee7.seeks", "to": ["jroiland@mee7.seeks"]}}
{"timestamp": "2017-03-25T15:08:58.717123-0600", "flow_id": 677809666680977, "pcap_cnt": 494678, "event_type": "smtp", "src_ip": "10.239.179.209", "src_port": 37639, "dest_ip": "10.10.2.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<schalke@mee2.seeks>", "rcpt_to": ["<rridley@mee2.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "schalke@mee2.seeks", "to": ["rridley@mee2.seeks"]}}
{"timestamp": "2017-03-25T09:51:22.688639-0600", "flow_id": 1036511201474312, "pcap_cnt": 591038, "event_type": "smtp", "src_ip": "10.212.123.174", "src_port": 58514, "dest_ip": "10.10.6.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<tkauffman@mee6.seeks>", "rcpt_to": ["<schalke@mee6.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "tkauffman@mee6.seeks", "to": ["schalke@mee6.seeks"]}}
{"timestamp": "2017-03-24T13:03:44.534582-0600", "flow_id": 1480406198113903, "pcap_cnt": 414641, "event_type": "smtp", "src_ip": "10.216.74.156", "src_port": 41729, "dest_ip": "10.10.1.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<eacosta@mee1.seeks>", "rcpt_to": ["<eacosta@mee1.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "eacosta@mee1.seeks", "to": ["eacosta@mee1.seeks"]}}
{"timestamp": "2017-03-24T21:48:58.492225-0600", "flow_id": 76213803107818, "pcap_cnt": 955425, "event_type": "smtp", "src_ip": "10.215.227.49", "src_port": 58125, "dest_ip": "10.10.2.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "sse.wrccdc.secure", "mail_from": "<dharmon@mee2.seeks>", "rcpt_to": ["<sgrammer@mee2.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "dharmon@mee2.seeks", "to": ["sgrammer@mee2.seeks"]}}
{"timestamp": "2015-03-10T04:43:32.476160-0600", "flow_id": 182380599207300, "pcap_cnt": 161295, "event_type": "smtp", "src_ip": "192.168.0.51", "src_port": 36504, "dest_ip": "81.236.55.3", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "[192.168.0.51]", "mail_from": "<homer.pwned.se@gmx.com>", "rcpt_to": ["<ned.pwned.se@gmx.com>"]}, "email": {"status": "PARSE_DONE", "from": "Homer <homer.pwned.se@gmx.com>", "to": ["Password Ned <ned.pwned.se@gmx.com>"]}}
`

	parser := &SMTPParser{}
	lines := strings.FieldsFunc(logs, func(r rune) bool { return r == '\n' })
	for _, line := range lines {
		events := parser.Parse(line)
		require.Equal(t, 1, len(events))
	}
}

func TestSMTPType(t *testing.T) {
	parser := &SMTPParser{}
	require.Equal(t, "Suricata.SMTP", parser.LogType())
}
