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
func TestFileinfo(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2015-10-21T13:01:03.336642+0000", "flow_id": 271692978075092, "event_type": "fileinfo", "src_ip": "192.168.88.20", "src_port": 80, "dest_ip": "192.168.2.42", "dest_port": 38223, "proto": "006", "http": {"hostname": "192.168.88.20", "url": "/deviceinfo.htm", "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.64 Safari/537.36", "http_content_type": "text/html", "http_refer": "http://192.168.88.20/", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 7951}, "app_proto": "http", "fileinfo": {"filename": "/deviceinfo.htm", "sid": [123, 15], "magic": "HTML document, ASCII text", "gaps": false, "state": "TRUNCATED", "sha256": "d789f2c3c6f9146eb4e7b0e74c7118e1506d41e2f4597422c5c52bfd1809bf9d", "stored": true, "file_id": 4904, "size": 7951, "tx_id": 0}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-21T11:17:46.520820+0000", "flow_id": 1831846273475556, "event_type": "fileinfo", "src_ip": "192.168.88.100", "src_port": 80, "dest_ip": "192.168.2.42", "dest_port": 38221, "proto": "006", "http": {"hostname": "192.168.88.100", "url": "/getstatus.html&sid=0.7227659265045077", "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.64 Safari/537.36", "http_content_type": "text/xml", "http_refer": "http://192.168.88.100/showstatus.html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 1552}, "app_proto": "http", "fileinfo": {"filename": "/getstatus.html&sid=0.7227659265045077", "sid": [123, 15], "magic": "XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators", "gaps": false, "state": "TRUNCATED", "sha256": "daa5d515aec9fca8eb928911e95aae955472bee276eb452f11e131db800d5981", "stored": true, "file_id": 4387, "size": 1552, "tx_id": 0}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-21T12:10:38.589223+0000", "flow_id": 1028324459824371, "event_type": "fileinfo", "src_ip": "192.168.88.100", "src_port": 80, "dest_ip": "192.168.2.42", "dest_port": 36984, "proto": "006", "http": {"hostname": "192.168.88.100", "url": "/getstatus.html&sid=0.6507323088590056", "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.64 Safari/537.36", "http_content_type": "text/xml", "http_refer": "http://192.168.88.100/showstatus.html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 1552}, "app_proto": "http", "fileinfo": {"filename": "/getstatus.html&sid=0.6507323088590056", "sid": [123, 15], "magic": "XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators", "gaps": false, "state": "TRUNCATED", "sha256": "f4db13a542e4a376d4d682aca3d716df429066a6d81db4fd847481da758ce469", "stored": true, "file_id": 2837, "size": 1552, "tx_id": 0}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-21T11:09:24.494413+0000", "flow_id": 330783108948762, "event_type": "fileinfo", "src_ip": "192.168.88.100", "src_port": 80, "dest_ip": "192.168.2.42", "dest_port": 34948, "proto": "006", "http": {"hostname": "192.168.88.100", "url": "/getstatus.html&sid=0.3635057592764497", "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.64 Safari/537.36", "http_content_type": "text/xml", "http_refer": "http://192.168.88.100/showstatus.html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 1552}, "app_proto": "http", "fileinfo": {"filename": "/getstatus.html&sid=0.3635057592764497", "sid": [123, 15], "magic": "XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators", "gaps": false, "state": "TRUNCATED", "sha256": "ad171fc83b5eeaea89887ddc838380d58d9f8f7fe90317943707def927e75d93", "stored": true, "file_id": 1104, "size": 1552, "tx_id": 0}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-21T12:56:48.069979+0000", "flow_id": 389276281414329, "event_type": "fileinfo", "src_ip": "192.168.88.100", "src_port": 80, "dest_ip": "192.168.2.42", "dest_port": 38547, "proto": "006", "http": {"hostname": "192.168.88.100", "url": "/getstatus.html&sid=0.45961158885620534", "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.64 Safari/537.36", "http_content_type": "text/xml", "http_refer": "http://192.168.88.100/showstatus.html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 1552}, "app_proto": "http", "fileinfo": {"filename": "/getstatus.html&sid=0.45961158885620534", "sid": [123, 15], "magic": "XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators", "gaps": false, "state": "TRUNCATED", "sha256": "465ab1531e0f85cf5c30d7adae3f1e90a937417270abe14578ff7d300c52139e", "stored": true, "file_id": 4565, "size": 1552, "tx_id": 0}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2014-01-02T09:10:07.573117+0000", "flow_id": 1638148525230482, "pcap_cnt": 48, "event_type": "fileinfo", "src_ip": "95.136.242.99", "src_port": 65386, "dest_ip": "199.7.71.72", "dest_port": 80, "proto": "006", "http": {"hostname": "ocsp.thawte.com", "url": "/", "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:26.0) Gecko/20100101 Firefox/26.0", "http_method": "POST", "protocol": "HTTP/1.1", "length": 0}, "app_proto": "http", "fileinfo": {"filename": "/", "sid": [], "magic": "data", "gaps": false, "state": "CLOSED", "md5": "a4c335b3f83339ee6135104b89ad8d10", "sha1": "086af8300b52ef08bdc7ab2028685ab86f96acba", "sha256": "dbef52e178b8477b4b8eda8ad82010881295b1d57bc637edbbe05d35af5ed3ab", "stored": true, "file_id": 1, "size": 115, "tx_id": 0}, "pcap_filename": "/pcaps/nb6-hotspot.pcap"}`,
		`{"timestamp": "2015-10-21T11:09:41.129453+0000", "flow_id": 625718513481046, "event_type": "fileinfo", "src_ip": "192.168.88.100", "src_port": 80, "dest_ip": "192.168.2.42", "dest_port": 35045, "proto": "006", "http": {"hostname": "192.168.88.100", "url": "/getstatus.html&sid=0.696590883191675", "http_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.64 Safari/537.36", "http_content_type": "text/xml", "http_refer": "http://192.168.88.100/showstatus.html", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 1552}, "app_proto": "http", "fileinfo": {"filename": "/getstatus.html&sid=0.696590883191675", "sid": [123, 15], "magic": "XML 1.0 document, ASCII text, with very long lines, with CRLF line terminators", "gaps": false, "state": "TRUNCATED", "sha256": "79b139f0c14ccb487c5e62dc4e2c16201b20e6eef070dc71ee20790fc5e02366", "stored": true, "file_id": 1125, "size": 1552, "tx_id": 0}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2002-02-28T03:18:55.469837+0000", "flow_id": 708410322390386, "pcap_cnt": 57509, "event_type": "fileinfo", "src_ip": "192.168.0.2", "src_port": 8000, "dest_ip": "192.168.0.1", "dest_port": 2470, "proto": "006", "http": {"hostname": "192.168.0.2", "http_port": 8000, "url": "/", "http_user_agent": "Wget/1.5.3", "http_content_type": "text/html", "http_method": "GET", "protocol": "HTTP/1.0", "status": 200, "length": 80}, "app_proto": "http", "fileinfo": {"filename": "/", "sid": [], "magic": "HTML document, ASCII text, with no line terminators", "gaps": false, "state": "CLOSED", "md5": "5ea5334dcdd67d784c808b8244679604", "sha1": "383f977b29b80ccfdb50757afa6233da96c0fab1", "sha256": "0e7036abf3d7aed8e45c8d5368dec932b1c366ff43e31fcc15a81f5910c13098", "stored": true, "file_id": 3000, "size": 80, "tx_id": 0}, "pcap_filename": "/pcaps/c05-http-reply-r1.pcap"}`,
		`{"timestamp": "2014-01-14T17:04:02.434501+0000", "flow_id": 2073818214570473, "pcap_cnt": 319, "event_type": "fileinfo", "src_ip": "192.150.187.43", "src_port": 80, "dest_ip": "10.0.2.15", "dest_port": 55083, "proto": "006", "http": {"hostname": "bro.org", "url": "/images/icons/feed-icon-14x14.png", "http_user_agent": "Mozilla/5.0 (X11; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0", "http_content_type": "image/png", "http_refer": "http://bro.org/", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 689}, "app_proto": "http", "fileinfo": {"filename": "/images/icons/feed-icon-14x14.png", "sid": [], "magic": "PNG image data, 14 x 14, 8-bit/color RGBA, non-interlaced", "gaps": false, "state": "CLOSED", "md5": "2168a573d0d45bd2f9a89b8236453d61", "sha1": "30733f525b9d191ac4720041a49fc2d17f4c99a1", "sha256": "8ee173565b2e771fecf3b471a79bdf072aaa1bd9dc27582cfda2b2a322beeba8", "stored": true, "file_id": 15, "size": 689, "tx_id": 2}, "pcap_filename": "/pcaps/bro.org.pcap"}`,
		`{"timestamp": "2002-02-28T02:56:40.025106+0000", "flow_id": 47985994648644, "event_type": "fileinfo", "src_ip": "192.168.0.2", "src_port": 8000, "dest_ip": "192.168.0.1", "dest_port": 3193, "proto": "006", "http": {"hostname": "192.168.0.2", "http_port": 8000, "url": "/", "http_user_agent": "Wget/1.5.3", "http_content_type": "text/html", "http_method": "GET", "protocol": "HTTP/1.0", "status": 200, "length": 79}, "app_proto": "http", "fileinfo": {"filename": "/", "sid": [123, 15], "magic": "HTML document, ASCII text, with no line terminators", "gaps": false, "state": "TRUNCATED", "sha256": "c6be15fb57f7ea12d836d2f15b2ce34c1122985185ab83d494f1d6d706d7ab47", "stored": true, "file_id": 93, "size": 79, "tx_id": 0}, "pcap_filename": "/pcaps/c05-http-reply-r1.pcap"}`,
	}

	parser := &FileinfoParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestFileinfoType(t *testing.T) {
	parser := &FileinfoParser{}
	require.Equal(t, "Suricata.Fileinfo", parser.LogType())
}
