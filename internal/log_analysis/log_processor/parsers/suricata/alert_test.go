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
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

//nolint:lll
func TestAlert(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2018-03-23T21:43:10.187376-0600", "flow_id": 916918765527317, "pcap_cnt": 403027, "event_type": "alert", "src_ip": "10.244.217.243", "src_port": 44983, "dest_ip": "10.47.21.81", "dest_port": 65534, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2019232, "rev": 4, "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.47.21.81", "url": "/cgi-bin/ncbook/book.cgi", "http_user_agent": "() { ignored; }; echo Content-Type: text/plain ; echo ; echo \"bash_cve_2014_6271_rce Output : $((24+24))\"", "http_content_type": "text/plain", "http_method": "GET", "protocol": "HTTP/1.1", "status": 404, "length": 19}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 6, "bytes_toserver": 1214, "bytes_toclient": 802, "start": "2018-03-23T21:43:10.172309-0600"}}`,
		`{"timestamp": "2018-03-23T17:49:19.632165-0600", "flow_id": 470254132102605, "pcap_cnt": 1798791, "event_type": "alert", "src_ip": "10.241.111.81", "src_port": 35189, "dest_ip": "10.47.23.55", "dest_port": 80, "proto": "TCP", "alert": {"action": "allowed", "gid": 1, "signature_id": 2022028, "rev": 1, "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "flow": {"pkts_toserver": 6, "pkts_toclient": 2, "bytes_toserver": 1264, "bytes_toclient": 148, "start": "2018-03-23T17:49:19.624077-0600"}}`,
		`{"timestamp": "2018-03-23T17:46:38.461087-0600", "flow_id": 1865401233211746, "pcap_cnt": 272201, "event_type": "alert", "src_ip": "10.241.111.81", "src_port": 38177, "dest_ip": "10.47.22.65", "dest_port": 80, "proto": "TCP", "http": {"hostname": "10.47.22.65", "url": "/cgi-bin/search", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)", "http_method": "GET", "protocol": "HTTP/1.1", "length": 0}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 4, "bytes_toserver": 1532, "bytes_toclient": 1232, "start": "2018-03-23T17:46:38.426338-0600"}, "alert": {"action": "allowed", "gid": 1, "signature_id": 2022028, "rev": 1, "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt", "category": "Attempted Administrator Privilege Gain", "severity": 1}}`,
		`{"timestamp": "2017-03-24T11:33:37.542630-0600", "flow_id": 1511396180177218, "pcap_cnt": 474454, "event_type": "alert", "src_ip": "10.192.0.159", "src_port": 43036, "dest_ip": "10.10.8.119", "dest_port": 161, "proto": "UDP", "alert": {"action": "allowed", "gid": 1, "signature_id": 2015856, "rev": 5, "signature": "ET SNMP Attempt to retrieve Cisco Config via TFTP (CISCO-CONFIG-COPY)", "category": "Potential Corporate Privacy Violation", "severity": 1}, "app_proto": "failed", "flow": {"pkts_toserver": 95, "pkts_toclient": 0, "bytes_toserver": 21470, "bytes_toclient": 0, "start": "2017-03-24T11:33:35.536898-0600"}}`,
		`{"timestamp": "2018-03-23T14:19:55.826054-0600", "flow_id": 822049784856775, "pcap_cnt": 345260, "event_type": "alert", "src_ip": "10.47.6.154", "src_port": 51747, "dest_ip": "91.189.91.23", "dest_port": 80, "proto": "TCP", "tx_id": 44, "alert": {"action": "allowed", "gid": 1, "signature_id": 2013504, "rev": 5, "signature": "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management", "category": "Not Suspicious Traffic", "severity": 3}, "http": {"hostname": "us.archive.ubuntu.com", "url": "/ubuntu/pool/main/c/cups-pk-helper/cups-pk-helper_0.2.5-0ubuntu1_amd64.deb", "http_user_agent": "Debian APT-HTTP/1.3 (0.8.16~exp12ubuntu10.27)", "http_method": "GET", "protocol": "HTTP/1.1", "length": 0}, "app_proto": "http", "flow": {"pkts_toserver": 4050, "pkts_toclient": 6982, "bytes_toserver": 348857, "bytes_toclient": 10524490, "start": "2018-03-23T14:19:54.458951-0600"}}`,
		`{"timestamp": "2018-03-23T18:12:38.127266-0600", "flow_id": 590281379821614, "pcap_cnt": 3655048, "event_type": "alert", "src_ip": "10.128.0.207", "src_port": 36765, "dest_ip": "10.47.27.65", "dest_port": 80, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2024121, "rev": 4, "signature": "ET EXPLOIT NETGEAR WNR2000v5 hidden_lang_avi Stack Overflow (CVE-2016-10174)", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.47.27.65", "url": "/apply_noauth.cgi?/lang_check.html%20timestamp=24708390", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "http_content_type": "text/html", "http_method": "POST", "protocol": "HTTP/1.1", "status": 404, "length": 298}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 4, "bytes_toserver": 1434, "bytes_toclient": 1236, "start": "2018-03-23T18:12:38.079918-0600"}}`,
		`{"timestamp": "2018-03-24T15:59:58.255031-0600", "flow_id": 176633925254879, "pcap_cnt": 394369, "event_type": "alert", "src_ip": "10.128.0.207", "src_port": 36075, "dest_ip": "10.47.41.40", "dest_port": 80, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2024121, "rev": 4, "signature": "ET EXPLOIT NETGEAR WNR2000v5 hidden_lang_avi Stack Overflow (CVE-2016-10174)", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.47.41.40", "url": "/apply_noauth.cgi?/lang_check.html%20timestamp=62018408", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "http_method": "POST", "protocol": "HTTP/1.1", "status": 302, "redirect": "https://10.47.41.40/apply_noauth.cgi", "length": 3}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 6, "bytes_toserver": 1434, "bytes_toclient": 716, "start": "2018-03-24T15:59:58.245471-0600"}}`,
		`{"timestamp": "2018-03-23T16:13:10.058642-0600", "flow_id": 2022865104188498, "pcap_cnt": 179155, "event_type": "alert", "src_ip": "10.240.105.57", "src_port": 42875, "dest_ip": "10.10.3.2", "dest_port": 4443, "proto": "TCP", "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2019239, "rev": 4, "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Cookie", "category": "Attempted Administrator Privilege Gain", "severity": 1}, "http": {"hostname": "10.10.3.2", "url": "/cgi-bin/admin.cgi", "http_user_agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)", "http_content_type": "text/html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 400, "length": 661}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 8, "bytes_toserver": 1342, "bytes_toclient": 2126, "start": "2018-03-23T16:13:10.046162-0600"}}`,
		`{"timestamp": "2017-03-24T12:43:46.306300-0600", "flow_id": 1201147346069552, "pcap_cnt": 1201457, "event_type": "alert", "src_ip": "10.192.0.101", "src_port": 35664, "dest_ip": "10.10.3.80", "dest_port": 3389, "proto": "TCP", "tls": {"version": "UNDETERMINED"}, "vars": {"flowbits": {"ms.rdp.established": true}, "flowints": {"tls.anomaly.count": 2}}, "app_proto": "tls", "flow": {"pkts_toserver": 7, "pkts_toclient": 10, "bytes_toserver": 978, "bytes_toclient": 694, "start": "2017-03-24T12:43:46.305200-0600"}, "tx_id": 0, "alert": {"action": "allowed", "gid": 1, "signature_id": 2230015, "rev": 1, "signature": "SURICATA TLS invalid record version", "category": "Generic Protocol Command Decode", "severity": 3}}`,
		`{"timestamp": "2018-03-23T19:05:28.155488-0600", "flow_id": 1293792935692843, "pcap_cnt": 466853, "event_type": "alert", "src_ip": "10.128.0.221", "src_port": 45148, "dest_ip": "10.47.6.1", "dest_port": 80, "proto": "TCP", "http": {"hostname": "10.47.6.1", "url": "/cgi-bin/wa.exe", "http_user_agent": "() { ignored; }; echo Content-Type: text/plain ; echo ; echo \"bash_cve_2014_6271_rce Output : $((94+84))\"", "http_content_type": "application/octet-stream", "http_method": "GET", "protocol": "HTTP/1.1", "status": 404, "length": 190}, "app_proto": "http", "flow": {"pkts_toserver": 7, "pkts_toclient": 6, "bytes_toserver": 1294, "bytes_toclient": 1088, "start": "2018-03-23T19:05:28.150059-0600"}, "alert": {"action": "allowed", "gid": 1, "signature_id": 2022028, "rev": 1, "signature": "ET WEB_SERVER Possible CVE-2014-6271 Attempt", "category": "Attempted Administrator Privilege Gain", "severity": 1}}`,
	}

	parser := &AlertParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestAlertType(t *testing.T) {
	parser := &AlertParser{}
	require.Equal(t, "Suricata.Alert", parser.LogType())
}
