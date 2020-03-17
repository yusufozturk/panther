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

func TestAlert(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	//nolint:lll
	logs := `{"timestamp": "2018-03-24T14:39:24.925462-0600", "flow_id": 1222926296418519, "pcap_cnt": 337455, "event_type": "alert", "src_ip": "10.128.0.205", "src_port": 38290, "dest_ip": "10.47.3.30", "dest_port": 8080, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2019232, "rev": 4, "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.47.3.30", "url": "/cgi/mid.cgi", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)", "http_content_type": "text/html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 404, "length": 1016}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 8, "bytes_toserver": 1346, "bytes_toclient": 2960, "start": "2018-03-24T14:39:24.919767-0600"}}
{"timestamp": "2018-03-23T20:06:55.020717-0600", "flow_id": 1281445146346580, "pcap_cnt": 620456, "event_type": "alert", "src_ip": "10.128.0.207", "src_port": 35009, "dest_ip": "10.47.27.55", "dest_port": 80, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2024121, "rev": 4, "signature": "ET EXPLOIT NETGEAR WNR2000v5 hidden_lang_avi Stack Overflow (CVE-2016-10174)", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.47.27.55", "url": "/apply_noauth.cgi?/lang_check.html%20timestamp=63420824", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "http_content_type": "text/html", "http_method": "POST", "protocol": "HTTP/1.1", "status": 404, "length": 309}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 6, "bytes_toserver": 1434, "bytes_toclient": 1388, "start": "2018-03-23T20:06:55.017492-0600"}}
{"timestamp": "2018-03-24T16:14:08.365104-0600", "flow_id": 904381829492645, "pcap_cnt": 125610, "event_type": "alert", "src_ip": "10.227.37.30", "src_port": 38107, "dest_ip": "10.47.3.200", "dest_port": 902, "proto": "TCP", "tls": {"version": "0x3230"}, "vars": {"flowints": {"tls.anomaly.count": 2}}, "app_proto": "tls", "flow": {"pkts_toserver": 7, "pkts_toclient": 4, "bytes_toserver": 978, "bytes_toclient": 584, "start": "2018-03-24T16:14:08.339877-0600"}, "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2230015, "rev": 1, "signature": "SURICATA TLS invalid record version", "category": "Generic Protocol Command Decode", "severity": 3}}
{"timestamp": "2018-03-23T14:19:56.360182-0600", "flow_id": 822049784856775, "pcap_cnt": 378643, "event_type": "alert", "src_ip": "10.47.6.154", "src_port": 51747, "dest_ip": "91.189.91.23", "dest_port": 80, "proto": "TCP", "http": {"hostname": "us.archive.ubuntu.com", "url": "/ubuntu/pool/main/u/unity-scope-gdrive/unity-scope-gdrive_0.9+13.10.20130723-0ubuntu1_all.deb", "http_user_agent": "Debian APT-HTTP/1.3 (0.8.16~exp12ubuntu10.27)", "http_method": "GET", "protocol": "HTTP/1.1", "length": 0}, "app_proto": "http", "flow": {"pkts_toserver": 9678, "pkts_toclient": 15654, "bytes_toserver": 872804, "bytes_toclient": 23583386, "start": "2018-03-23T14:19:54.458951-0600"}, "tx_id": 62, "alert": {"action": "allowed", "gid": 1, "signature_id": 2013504, "rev": 5, "signature": "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management", "category": "Not Suspicious Traffic", "severity": 3}}
{"timestamp": "2018-03-23T21:43:15.430744-0600", "flow_id": 1921103594472099, "pcap_cnt": 581602, "event_type": "alert", "src_ip": "10.244.217.243", "src_port": 44093, "dest_ip": "10.47.27.65", "dest_port": 80, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2019232, "rev": 4, "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.47.27.65", "url": "/ucsm/isSamInstalled.cgi", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)", "http_method": "GET", "protocol": "HTTP/1.1", "length": 0}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 4, "bytes_toserver": 1550, "bytes_toclient": 1250, "start": "2018-03-23T21:43:15.410275-0600"}}
{"timestamp": "2018-03-23T21:49:49.001083-0600", "flow_id": 648728148731922, "pcap_cnt": 211543, "event_type": "alert", "src_ip": "10.244.217.243", "src_port": 42485, "dest_ip": "10.47.3.218", "dest_port": 65534, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2019232, "rev": 4, "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.47.3.218", "url": "/cgi-bin/search.cgi", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)", "http_content_type": "text/plain", "http_method": "GET", "protocol": "HTTP/1.1", "status": 404, "length": 19}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 6, "bytes_toserver": 1354, "bytes_toclient": 802, "start": "2018-03-23T21:49:48.944146-0600"}}
{"timestamp": "2018-03-24T16:46:03.596431-0600", "flow_id": 1289619046599996, "pcap_cnt": 604688, "event_type": "alert", "src_ip": "10.128.0.207", "src_port": 40271, "dest_ip": "10.47.41.20", "dest_port": 80, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2024121, "rev": 4, "signature": "ET EXPLOIT NETGEAR WNR2000v5 hidden_lang_avi Stack Overflow (CVE-2016-10174)", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.47.41.20", "url": "/apply_noauth.cgi?/lang_check.html%20timestamp=49048656", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "http_content_type": "text/html", "http_method": "POST", "protocol": "HTTP/1.1", "status": 404, "length": 291}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 6, "bytes_toserver": 1434, "bytes_toclient": 1316, "start": "2018-03-24T16:46:03.593212-0600"}}
{"timestamp": "2017-03-24T12:44:05.495958-0600", "flow_id": 2156449005667841, "pcap_cnt": 1592381, "event_type": "alert", "src_ip": "10.192.0.101", "src_port": 40886, "dest_ip": "10.10.3.80", "dest_port": 3389, "proto": "TCP", "tls": {"version": "UNDETERMINED"}, "vars": {"flowbits": {"ms.rdp.established": true}, "flowints": {"tls.anomaly.count": 2}}, "app_proto": "tls", "flow": {"pkts_toserver": 7, "pkts_toclient": 10, "bytes_toserver": 978, "bytes_toclient": 694, "start": "2017-03-24T12:44:05.493057-0600"}, "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2230015, "rev": 1, "signature": "SURICATA TLS invalid record version", "category": "Generic Protocol Command Decode", "severity": 3}}
{"timestamp": "2018-03-24T17:58:12.865306-0600", "flow_id": 237592860958221, "pcap_cnt": 35309, "event_type": "alert", "src_ip": "10.128.0.205", "src_port": 34092, "dest_ip": "10.47.41.30", "dest_port": 80, "proto": "TCP", "http": {"hostname": "10.47.41.30", "url": "/cgi-bin/index.pl", "http_user_agent": "() { _; } >_[$($())] { echo Content-Type: text/plain ; echo ; echo \"bash_cve_2014_6278 Output : $((45+15))\"; }", "http_content_type": "text/html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 404, "length": 169}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 6, "bytes_toserver": 1208, "bytes_toclient": 1060, "start": "2018-03-24T17:58:12.859661-0600"}, "alert": {"action": "allowed", "gid": 1, "signature_id": 2022028, "rev": 1, "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt", "category": "Attempted Administrator Privilege Gain", "severity": 1}}
{"timestamp": "2018-03-24T12:18:05.945605-0600", "flow_id": 1654720277862032, "pcap_cnt": 96314, "event_type": "alert", "src_ip": "10.128.0.241", "src_port": 39875, "dest_ip": "10.47.21.186", "dest_port": 80, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2024121, "rev": 4, "signature": "ET EXPLOIT NETGEAR WNR2000v5 hidden_lang_avi Stack Overflow (CVE-2016-10174)", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.47.21.186", "url": "/apply_noauth.cgi?/lang_check.html%20timestamp=75362624", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "http_content_type": "text/html", "http_method": "POST", "protocol": "HTTP/1.1", "status": 404, "length": 292}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 6, "bytes_toserver": 1438, "bytes_toclient": 1318, "start": "2018-03-24T12:18:05.939664-0600"}}
`

	parser := &AlertParser{}
	lines := strings.FieldsFunc(logs, func(r rune) bool { return r == '\n' })
	for _, line := range lines {
		events := parser.Parse(line)
		require.Equal(t, 1, len(events))
	}
}

func TestAlertType(t *testing.T) {
	parser := &AlertParser{}
	require.Equal(t, "Suricata.Alert", parser.LogType())
}
