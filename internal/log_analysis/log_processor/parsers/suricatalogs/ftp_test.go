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
func TestFTP(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2016-05-27T21:51:25.454849+0000", "flow_id": 409558439182545, "pcap_cnt": 325, "event_type": "ftp", "src_ip": "10.3.22.91", "src_port": 58218, "dest_ip": "10.167.25.101", "dest_port": 21, "proto": "006", "tx_id": 115, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:kfrG/xG6Jfo07U0b/idy9PvFgpA=", "ftp": {"command": "PASV", "reply": ["CWD command successful"], "completion_code": ["250"], "reply_received": "yes"}, "pcap_filename": "/pcaps/cwd-navigation.pcap"}`,
		`{"timestamp": "2015-10-21T15:36:12.419808+0000", "flow_id": 1480697237687211, "pcap_cnt": 988409, "event_type": "ftp", "src_ip": "192.168.2.88", "src_port": 40427, "dest_ip": "192.168.88.49", "dest_port": 21, "proto": "006", "tx_id": 0, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:H9xhR1HdFYSA9gGhBNCNPXo6okY=", "ftp": {"reply": ["AXIS 206 Network Camera 4.40 (Jun 20 2006) ready."], "completion_code": ["220"], "reply_received": "yes"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-22T11:38:15.905670+0000", "flow_id": 1210449738056989, "pcap_cnt": 1954986, "event_type": "ftp", "src_ip": "192.168.2.53", "src_port": 42428, "dest_ip": "192.168.88.49", "dest_port": 21, "proto": "006", "tx_id": 0, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:soy3DB8KoEE4iiXe5oZzL7i2hKw=", "ftp": {"reply": ["AXIS 206 Network Camera 4.40 (Jun 20 2006) ready."], "completion_code": ["220"], "reply_received": "yes"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2016-05-27T21:51:44.740130+0000", "flow_id": 409558439182545, "pcap_cnt": 599, "event_type": "ftp", "src_ip": "10.3.22.91", "src_port": 58218, "dest_ip": "10.167.25.101", "dest_port": 21, "proto": "006", "tx_id": 219, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:kfrG/xG6Jfo07U0b/idy9PvFgpA=", "ftp": {"command": "TYPE", "command_data": "I", "reply": ["Opening BINARY mode data connection for 720972-99999-2012.gz (64866 bytes)", "Transfer complete"], "completion_code": ["150", "226"], "reply_received": "yes"}, "pcap_filename": "/pcaps/cwd-navigation.pcap"}`,
		`{"timestamp": "2016-05-27T21:51:49.896194+0000", "flow_id": 409558439182545, "pcap_cnt": 663, "event_type": "ftp", "src_ip": "10.3.22.91", "src_port": 58218, "dest_ip": "10.167.25.101", "dest_port": 21, "proto": "006", "tx_id": 246, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:kfrG/xG6Jfo07U0b/idy9PvFgpA=", "ftp": {"command": "RETR", "command_data": "720972-99999-2014.gz", "reply": ["CWD command successful"], "completion_code": ["250"], "reply_received": "yes"}, "pcap_filename": "/pcaps/cwd-navigation.pcap"}`,
		`{"timestamp": "2014-01-14T17:37:53.407319+0000", "flow_id": 1862325568084556, "pcap_cnt": 295, "event_type": "ftp", "src_ip": "192.168.56.1", "src_port": 54033, "dest_ip": "192.168.56.101", "dest_port": 21, "proto": "006", "tx_id": 1, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:iKtN9EyovNJ9U9AGj0Ma/BPNeDw=", "ftp": {"command": "USER", "command_data": "bro", "reply": ["Password required for bro."], "completion_code": ["331"], "reply_received": "yes"}, "pcap_filename": "/pcaps/bruteforce.pcap"}`,
		`{"timestamp": "2016-05-27T21:51:52.428432+0000", "flow_id": 409558439182545, "pcap_cnt": 699, "event_type": "ftp", "src_ip": "10.3.22.91", "src_port": 58218, "dest_ip": "10.167.25.101", "dest_port": 21, "proto": "006", "tx_id": 260, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:kfrG/xG6Jfo07U0b/idy9PvFgpA=", "ftp": {"command": "PASV", "reply": ["CWD command successful"], "completion_code": ["250"], "reply_received": "yes"}, "pcap_filename": "/pcaps/cwd-navigation.pcap"}`,
		`{"timestamp": "2014-01-14T17:37:35.360362+0000", "flow_id": 1051012687157528, "pcap_cnt": 115, "event_type": "ftp", "src_ip": "192.168.56.1", "src_port": 54022, "dest_ip": "192.168.56.101", "dest_port": 21, "proto": "006", "tx_id": 1, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:BSltjEAOlSKcdCiYYZ5zB/k26KI=", "ftp": {"command": "USER", "command_data": "bro", "reply": ["Password required for bro."], "completion_code": ["331"], "reply_received": "yes"}, "pcap_filename": "/pcaps/bruteforce.pcap"}`,
		`{"timestamp": "2005-07-04T09:33:55.045444+0000", "flow_id": 1775230284621570, "pcap_cnt": 64, "event_type": "ftp", "src_ip": "192.168.1.2", "src_port": 2720, "dest_ip": "147.234.1.253", "dest_port": 21, "proto": "006", "tx_id": 5, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:3Lxr5aFQNSmpkK3xZSAzdp1EvEk=", "ftp": {"reply": [" /incoming\t-> Incoming Folder. \r\n", " \t\t   Anyone can access, write & retrieve a specific file"], "completion_code": [], "reply_received": "yes"}, "pcap_filename": "/pcaps/aaa.pcap"}`,
		`{"timestamp": "2005-07-04T09:33:55.049467+0000", "flow_id": 1775230284621570, "pcap_cnt": 73, "event_type": "ftp", "src_ip": "192.168.1.2", "src_port": 2720, "dest_ip": "147.234.1.253", "dest_port": 21, "proto": "006", "tx_id": 8, "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:3Lxr5aFQNSmpkK3xZSAzdp1EvEk=", "ftp": {"reply": [" Other Files will be deleted after 2 weeks !!!"], "completion_code": [], "reply_received": "yes"}, "pcap_filename": "/pcaps/aaa.pcap"}`,
	}

	parser := &FTPParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestFTPType(t *testing.T) {
	parser := &FTPParser{}
	require.Equal(t, "Suricata.FTP", parser.LogType())
}
