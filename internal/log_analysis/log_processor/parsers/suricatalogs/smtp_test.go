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
func TestSMTP(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2017-03-24T16:19:40.605670-0600", "flow_id": 216017984097941, "pcap_cnt": 1754515, "event_type": "smtp", "src_ip": "10.251.145.70", "src_port": 59756, "dest_ip": "10.10.6.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<sgrammer@mee6.seeks>", "rcpt_to": ["<jroiland@mee6.seeks>"]}, "email": {"status": "HEADER_READY"}}`,
		`{"timestamp": "2017-03-25T08:08:31.208750-0600", "flow_id": 1370710792330534, "pcap_cnt": 789061, "event_type": "smtp", "src_ip": "10.195.201.169", "src_port": 59581, "dest_ip": "10.10.4.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<wrandolph@mee4.seeks>", "rcpt_to": ["<sgrammer@mee4.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "wrandolph@mee4.seeks", "to": ["sgrammer@mee4.seeks"]}}`,
		`{"timestamp": "2017-03-25T03:07:44.352661-0600", "flow_id": 619094627742959, "pcap_cnt": 687031, "event_type": "smtp", "src_ip": "10.202.35.205", "src_port": 45160, "dest_ip": "10.10.3.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<dharmon@mee3.seeks>", "rcpt_to": ["<jroiland@mee3.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "dharmon@mee3.seeks", "to": ["jroiland@mee3.seeks"]}}`,
		`{"timestamp": "2017-03-24T17:32:08.949674-0600", "flow_id": 2137414842851464, "pcap_cnt": 179995, "event_type": "smtp", "src_ip": "10.238.99.186", "src_port": 51252, "dest_ip": "172.16.33.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "sseclone5.wrccdc.secure", "mail_from": "<cparnell@spytellite3.com>", "rcpt_to": ["<anash@spytellite3.com>"]}, "email": {"status": "PARSE_DONE", "from": "cparnell@spytellite3.com", "to": ["anash@spytellite3.com"]}}`,
		`{"timestamp": "2017-03-25T17:09:00.917042-0600", "flow_id": 1706785518646778, "pcap_cnt": 87794, "event_type": "smtp", "src_ip": "10.201.130.164", "src_port": 52929, "dest_ip": "10.10.4.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "sse.wrccdc.secure", "mail_from": "<schalke@mee4.seeks>", "rcpt_to": ["<jroiland@mee4.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "schalke@mee4.seeks", "to": ["jroiland@mee4.seeks"]}}`,
		`{"timestamp": "2017-03-25T14:18:05.028317-0600", "flow_id": 1499032983293156, "pcap_cnt": 712604, "event_type": "smtp", "src_ip": "10.209.132.164", "src_port": 39435, "dest_ip": "10.10.4.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "sse.wrccdc.secure", "mail_from": "<eacosta@mee4.seeks>", "rcpt_to": ["<schalke@mee4.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "eacosta@mee4.seeks", "to": ["schalke@mee4.seeks"]}}`,
		`{"timestamp": "2017-03-25T06:31:52.594139-0600", "flow_id": 1657751666558755, "pcap_cnt": 280621, "event_type": "smtp", "src_ip": "10.250.172.73", "src_port": 49079, "dest_ip": "10.10.5.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<jroiland@mee5.seeks>", "rcpt_to": ["<jroiland@mee5.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "jroiland@mee5.seeks", "to": ["jroiland@mee5.seeks"]}}`,
		`{"timestamp": "2017-03-25T04:06:49.264648-0600", "flow_id": 2093638737172268, "pcap_cnt": 404753, "event_type": "smtp", "src_ip": "10.197.244.240", "src_port": 45452, "dest_ip": "10.10.3.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<tkauffman@mee3.seeks>", "rcpt_to": ["<rridley@mee3.seeks>"]}, "email": {"status": "PARSE_DONE", "from": "tkauffman@mee3.seeks", "to": ["rridley@mee3.seeks"]}}`,
		`{"timestamp": "2017-03-25T06:37:13.211939-0600", "flow_id": 1912846974866847, "pcap_cnt": 411145, "event_type": "smtp", "src_ip": "10.241.76.16", "src_port": 59030, "dest_ip": "10.10.6.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "debian.localdomain", "mail_from": "<jroiland@mee6.seeks>", "rcpt_to": ["<tkauffman@mee6.seeks>"]}, "email": {"status": "HEADER_READY"}}`,
		`{"timestamp": "2017-03-25T12:04:52.631248-0600", "flow_id": 812597901167947, "pcap_cnt": 354647, "event_type": "smtp", "src_ip": "10.242.6.140", "src_port": 46203, "dest_ip": "172.16.34.6", "dest_port": 25, "proto": "TCP", "tx_id": 0, "smtp": {"helo": "sse.wrccdc.secure", "mail_from": "<jgreer@spytellite4.com>", "rcpt_to": ["<anash@spytellite4.com>"]}, "email": {"status": "PARSE_DONE", "from": "jgreer@spytellite4.com", "to": ["anash@spytellite4.com"]}}`,
	}

	parser := &SMTPParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestSMTPType(t *testing.T) {
	parser := &SMTPParser{}
	require.Equal(t, "Suricata.SMTP", parser.LogType())
}
