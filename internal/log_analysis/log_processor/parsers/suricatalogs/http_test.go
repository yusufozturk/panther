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
func TestHTTP(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2017-04-18T14:56:25.108682+0000", "flow_id": 1521660320828047, "pcap_cnt": 1504, "event_type": "http", "src_ip": "192.168.1.46", "src_port": 49201, "dest_ip": "37.72.175.221", "dest_port": 443, "proto": "006", "tx_id": 62, "community_id": "1:LCBJY8F9+XJKelgxYXjhk+ka8Ak=", "http": {"hostname": "37.72.175.221", "url": "/web/?ID=CD51CF2868B04D8B8DCF3232462F540F", "http_method": "POST", "protocol": "HTTP/1.1", "status": 200, "length": 12, "request_headers": [{"name": "HOST", "value": "37.72.175.221"}, {"name": "CONTENT-LENGTH", "value": "43"}], "response_headers": [{"name": "CONTENT-LENGTH", "value": "12"}]}, "pcap_filename": "/pcaps/post_rig_infection_svchost.pcap"}`,
		`{"timestamp": "2017-04-18T14:55:55.064953+0000", "flow_id": 1521660320828047, "pcap_cnt": 1478, "event_type": "http", "src_ip": "192.168.1.46", "src_port": 49201, "dest_ip": "37.72.175.221", "dest_port": 443, "proto": "006", "tx_id": 59, "community_id": "1:LCBJY8F9+XJKelgxYXjhk+ka8Ak=", "http": {"hostname": "37.72.175.221", "url": "/web/?ID=CD51CF2868B04D8B8DCF3232462F540F", "http_method": "POST", "protocol": "HTTP/1.1", "status": 200, "length": 15, "request_headers": [{"name": "HOST", "value": "37.72.175.221"}, {"name": "CONTENT-LENGTH", "value": "46"}], "response_headers": [{"name": "CONTENT-LENGTH", "value": "15"}]}, "pcap_filename": "/pcaps/post_rig_infection_svchost.pcap"}`,
		`{"timestamp": "2017-02-22T00:03:46.733375+0000", "flow_id": 1631571455486921, "event_type": "http", "src_ip": "192.168.1.195", "src_port": 50030, "dest_ip": "192.168.1.161", "dest_port": 80, "proto": "006", "tx_id": 0, "community_id": "1:q/8YcKlGDXVVuI3l4PRdls8Ybq4=", "http": {"hostname": "192.168.1.161", "url": "/news.asp", "http_user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 173, "request_headers": [{"name": "Cookie", "value": "SESSIONID=1YW3KSLVVWYDG3VY"}, {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"}, {"name": "Host", "value": "192.168.1.161"}, {"name": "Connection", "value": "Keep-Alive"}], "response_headers": [{"name": "Server", "value": "Microsoft-IIS/7.5 "}, {"name": "Date", "value": "Wed, 22 Feb 2017 00:02:13 GMT"}]}, "pcap_filename": "/pcaps/wmi_to_vss.pcap"}`,
		`{"timestamp": "2017-02-21T18:09:05.074660+0000", "flow_id": 1159153705362646, "event_type": "http", "src_ip": "192.168.1.195", "src_port": 49968, "dest_ip": "192.168.1.161", "dest_port": 80, "proto": "006", "tx_id": 0, "community_id": "1:2Gk6yw7iKgIAg5LKIO7rnyRtN0E=", "http": {"hostname": "192.168.1.161", "url": "/news.asp", "http_user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 173, "request_headers": [{"name": "Cookie", "value": "SESSIONID=XHXKW4DXWMWUZAPM"}, {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"}, {"name": "Host", "value": "192.168.1.161"}, {"name": "Connection", "value": "Keep-Alive"}], "response_headers": [{"name": "Server", "value": "Microsoft-IIS/7.5 "}, {"name": "Date", "value": "Tue, 21 Feb 2017 18:03:03 GMT"}]}, "pcap_filename": "/pcaps/Empire_from_AD.pcap"}`,
		`{"timestamp": "2015-10-22T10:36:06.062719+0000", "flow_id": 1599375961091197, "event_type": "http", "src_ip": "192.168.2.22", "src_port": 39725, "dest_ip": "192.168.88.95", "dest_port": 443, "proto": "006", "tx_id": 0, "community_id": "1:ksOkLPTYXAgGy45RQQZuUYhp2V0=", "http": {"hostname": "192.168.88.95", "url": "/", "http_user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)", "http_method": "OPTIONS", "protocol": "HTTP/1.1", "length": 0, "request_headers": [{"name": "Access-Control-Request-Method", "value": "PATCH"}, {"name": "Connection", "value": "close"}, {"name": "Host", "value": "192.168.88.95"}, {"name": "User-Agent", "value": "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)"}, {"name": "Origin", "value": "example.com"}], "response_headers": []}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T08:01:51.275193+0000", "flow_id": 1662026032189418, "event_type": "http", "src_ip": "192.168.2.166", "src_port": 1726, "dest_ip": "192.168.88.95", "dest_port": 80, "proto": "006", "tx_id": 1, "metadata": {"flowints": {"http.anomaly.count": 1}}, "community_id": "1:B6krml1kRiuIzP11ja3l7OBIcK0=", "http": {"http_port": 0, "url": "/libhtp::request_uri_not_seen", "status": 400, "length": 0, "request_headers": [], "response_headers": []}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-21T10:11:29.810093+0000", "flow_id": 890369879137474, "event_type": "http", "src_ip": "192.168.2.64", "src_port": 51926, "dest_ip": "192.168.88.95", "dest_port": 20000, "proto": "006", "tx_id": 0, "community_id": "1:U1XCPLK248rcSKf3TWc7cwtOVRg=", "http": {"url": "/", "http_method": "GET", "protocol": "HTTP/1.0", "length": 0, "request_headers": [], "response_headers": []}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-22T08:11:12.780811+0000", "flow_id": 291776849540078, "event_type": "http", "src_ip": "192.168.2.133", "src_port": 47554, "dest_ip": "192.168.88.61", "dest_port": 502, "proto": "006", "tx_id": 0, "community_id": "1:NcXWwHRjSSGMkFAFuJT4dmSZUPQ=", "http": {"url": "/", "http_method": "GET", "protocol": "HTTP/1.0", "length": 0, "request_headers": [], "response_headers": []}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T10:35:47.145653+0000", "flow_id": 102566969421990, "event_type": "http", "src_ip": "192.168.2.22", "src_port": 48511, "dest_ip": "192.168.88.51", "dest_port": 443, "proto": "006", "tx_id": 0, "community_id": "1:5if3u3X2qsRtPDCkAij3WtZ/XJw=", "http": {"hostname": "192.168.88.51", "url": "/robots.txt", "http_user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)", "http_method": "GET", "protocol": "HTTP/1.1", "length": 0, "request_headers": [{"name": "User-Agent", "value": "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)"}, {"name": "Connection", "value": "close"}, {"name": "Host", "value": "192.168.88.51"}], "response_headers": []}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2017-02-13T22:27:39.216942+0000", "flow_id": 8622999652639, "event_type": "http", "src_ip": "192.168.1.46", "src_port": 49711, "dest_ip": "192.168.1.161", "dest_port": 80, "proto": "006", "tx_id": 0, "community_id": "1:nnX0n50YfclAC1bgOWKxSpoSd2g=", "http": {"hostname": "192.168.1.161", "url": "/admin/get.php", "http_user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 173, "request_headers": [{"name": "Cookie", "value": "SESSIONID=LF1GYUGSYDCHACGW"}, {"name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"}, {"name": "Host", "value": "192.168.1.161"}, {"name": "Connection", "value": "Keep-Alive"}], "response_headers": [{"name": "Server", "value": "Microsoft-IIS/7.5 "}, {"name": "Date", "value": "Mon, 13 Feb 2017 22:27:31 GMT"}]}, "pcap_filename": "/pcaps/capture-Mon-02-13-17-17-15-34_Empire.pcap"}`,
	}

	parser := &HTTPParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestHTTPType(t *testing.T) {
	parser := &HTTPParser{}
	require.Equal(t, "Suricata.HTTP", parser.LogType())
}
