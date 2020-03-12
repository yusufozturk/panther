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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

//nolint:lll
// {"timestamp":"2016-11-26T14:52:59.669097+0000","flow_id":1844600973768105,"pcap_cnt":3,"event_type":"alert","src_ip":"10.0.2.15","src_port":27942,"dest_ip":"10.0.2.15","dest_port":27942,"proto":"017","community_id":"1:NALMnASfrmROPp+ghhgVXLG+cpM=","alert":{"action":"allowed","gid":1,"signature_id":2200075,"rev":2,"signature":"SURICATA UDPv4 invalid checksum","category":"Generic Protocol Command Decode","severity":3},"app_proto":"failed","flow":{"pkts_toserver":1,"pkts_toclient":0,"bytes_toserver":47,"bytes_toclient":0,"start":"2016-11-26T14:52:59.669097+0000"},"payload":"VEVTVAA=","payload_printable":"TEST.","stream":0,"packet":"AAAAAAAAAAAAAAAACABFAAAhvzpAAEARY3QKAAIPCgACD20mbSYADRg8VEVTVAA=","packet_info":{"linktype":1},"pcap_filename":"\/pcaps\/sip-rtp-g711.pcap"}

//nolint:lll
// {"timestamp":"2013-03-07T21:42:07.009775+0000","flow_id":619927151985632,"pcap_cnt":9,"event_type":"alert","src_ip":"192.150.187.43","src_port":80,"dest_ip":"141.142.228.5","dest_port":59856,"proto":"006","community_id":"1:+49TarwoW9lFS8886GydFbUG720=","alert":{"action":"allowed","gid":1,"signature_id":101,"rev":0,"signature":"FOO HTTP","category":"","severity":3},"http":{"hostname":"bro.org","url":"HTTP\/1.1","http_method":"GET","length":0},"app_proto":"http","flow":{"pkts_toserver":3,"pkts_toclient":6,"bytes_toserver":346,"bytes_toclient":5411,"start":"2013-03-07T21:42:06.869344+0000"},"payload":"IHRocmVhZCBsaWJyYXJ5IHdoZW4gbmVjZXNzYXJ5IChlLmcuCiAgICBQRl9SSU5HJ3MgbGlicGNhcCkgKEpvbiBTaXdlaykKCiAgKiBJbnN0YWxsIGJpbmFyaWVzIHdpdGggYW4gUlBBVEggKEpvbiBTaXdlaykKCiAgKiBXb3JrYXJvdW5kIGZvciBGcmVlQlNEIENNYWtlIHBvcnQgbWlzc2luZyBkZWJ1ZyBmbGFncyAoSm9uIFNpd2VrKQoKICAqIFJld3JpdGUgb2YgdGhlIHVwZGF0ZS1jaGFuZ2VzIHNjcmlwdC4gKFJvYmluIFNvbW1lcikKCjAuMS0xIHwgMjAxMS0wNi0xNCAyMToxMjo0MSAtMDcwMAoKICAqIEFkZCBhIHNjcmlwdCBmb3IgZ2VuZXJhdGluZyBNb3ppbGxhJ3MgQ0EgbGlzdCBmb3IgdGhlIFNTTCBhbmFseXplci4KICAgIChTZXRoIEhhbGwpCgowLjEgfCAyMDExLTA0LTAxIDE2OjI4OjIyIC0wNzAwCgogICogQ29udmVydGluZyBidWlsZCBwcm9jZXNzIHRvIENNYWtlLiAoSm9uIFNpd2VrKQoKICAqIFJlbW92aW5nIGNmL2hmL2NhLSogZnJvbSBkaXN0cmlidXRpb24uIFRoZSBSRUFETUUgaGFzIGEgbm90ZSB3aGVyZQogICAgdG8gZmluZCB0aGVtIG5vdy4gKFJvYmluIFNvbW1lcikKCiAgKiBHZW5lcmFsIGNsZWFudXAuIChSb2JpbiBTb21tZXIpCgogICogSW5pdGlhbCBpbXBvcnQgb2YgYnJvL2F1eCBmcm9tIFNWTiByNzA4OC4gKEpvbiBTaXdlaykK","payload_printable":" thread library when necessary (e.g.\n    PF_RING's libpcap) (Jon Siwek)\n\n  * Install binaries with an RPATH (Jon Siwek)\n\n  * Workaround for FreeBSD CMake port missing debug flags (Jon Siwek)\n\n  * Rewrite of the update-changes script. (Robin Sommer)\n\n0.1-1 | 2011-06-14 21:12:41 -0700\n\n  * Add a script for generating Mozilla's CA list for the SSL analyzer.\n    (Seth Hall)\n\n0.1 | 2011-04-01 16:28:22 -0700\n\n  * Converting build process to CMake. (Jon Siwek)\n\n  * Removing cf\/hf\/ca-* from distribution. The README has a note where\n    to find them now. (Robin Sommer)\n\n  * General cleanup. (Robin Sommer)\n\n  * Initial import of bro\/aux from SVN r7088. (Jon Siwek)\n","stream":0,"packet":"yLzIltKgABDbiNLvCABFAALLjKRAAC8GzzLAlrsrjY7kBQBQ6dClr983\/iEyw4AYAHqlKAAAAQEICi+JQp8WSt1mIHRocmVhZCBsaWJyYXJ5IHdoZW4gbmVjZXNzYXJ5IChlLmcuCiAgICBQRl9SSU5HJ3MgbGlicGNhcCkgKEpvbiBTaXdlaykKCiAgKiBJbnN0YWxsIGJpbmFyaWVzIHdpdGggYW4gUlBBVEggKEpvbiBTaXdlaykKCiAgKiBXb3JrYXJvdW5kIGZvciBGcmVlQlNEIENNYWtlIHBvcnQgbWlzc2luZyBkZWJ1ZyBmbGFncyAoSm9uIFNpd2VrKQoKICAqIFJld3JpdGUgb2YgdGhlIHVwZGF0ZS1jaGFuZ2VzIHNjcmlwdC4gKFJvYmluIFNvbW1lcikKCjAuMS0xIHwgMjAxMS0wNi0xNCAyMToxMjo0MSAtMDcwMAoKICAqIEFkZCBhIHNjcmlwdCBmb3IgZ2VuZXJhdGluZyBNb3ppbGxhJ3MgQ0EgbGlzdCBmb3IgdGhlIFNTTCBhbmFseXplci4KICAgIChTZXRoIEhhbGwpCgowLjEgfCAyMDExLTA0LTAxIDE2OjI4OjIyIC0wNzAwCgogICogQ29udmVydGluZyBidWlsZCBwcm9jZXNzIHRvIENNYWtlLiAoSm9uIFNpd2VrKQoKICAqIFJlbW92aW5nIGNmL2hmL2NhLSogZnJvbSBkaXN0cmlidXRpb24uIFRoZSBSRUFETUUgaGFzIGEgbm90ZSB3aGVyZQogICAgdG8gZmluZCB0aGVtIG5vdy4gKFJvYmluIFNvbW1lcikKCiAgKiBHZW5lcmFsIGNsZWFudXAuIChSb2JpbiBTb21tZXIpCgogICogSW5pdGlhbCBpbXBvcnQgb2YgYnJvL2F1eCBmcm9tIFNWTiByNzA4OC4gKEpvbiBTaXdlaykK","packet_info":{"linktype":1},"pcap_filename":"\/pcaps\/no-uri.pcap"}

//nolint:lll
// {"timestamp":"2014-05-20T00:53:33.668004+0000","flow_id":1938390271209551,"pcap_cnt":37,"event_type":"alert","src_ip":"118.189.96.132","src_port":55483,"dest_ip":"118.189.96.132","dest_port":502,"proto":"006","metadata":{"flowints":{"applayer.anomaly.count":1}},"community_id":"1:Cy0CEi2sORlkOHxwWifTYWCjBkg=","alert":{"action":"allowed","gid":1,"signature_id":2260002,"rev":1,"signature":"SURICATA Applayer Detect protocol only one direction","category":"Generic Protocol Command Decode","severity":3},"app_proto":"modbus","app_proto_tc":"failed","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":284,"bytes_toclient":216,"start":"2014-05-20T00:53:33.667727+0000"},"payload":"","payload_printable":"","stream":0,"packet":"AAAAAAAAAAAAAAAACABFAAA07zxAAEAGnQR2vWCEdr1ghNi7Afa9vjlvbs58L4AQAVb+KAAAAQEICgFW1lsBVtZb","packet_info":{"linktype":1},"pcap_filename":"\/pcaps\/modbusSmall.pcap"}

//nolint:lll
// {"timestamp":"2014-05-20T00:53:57.108698+0000","flow_id":1001889833785988,"pcap_cnt":102,"event_type":"alert","src_ip":"118.189.96.132","src_port":53,"dest_ip":"118.189.96.132","dest_port":56426,"proto":"017","community_id":"1:tGrjcWyaaeBeTrnonYdHgIU\/YWU=","alert":{"action":"allowed","gid":1,"signature_id":2200075,"rev":2,"signature":"SURICATA UDPv4 invalid checksum","category":"Generic Protocol Command Decode","severity":3},"app_proto":"dns","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":75,"bytes_toclient":270,"start":"2014-05-20T00:53:57.105092+0000"},"payload":"mBCBgAABAAMABAAEBG1haWwGZ29vZ2xlA2NvbQAAAQABwAwABQABAAU4rgAPCmdvb2dsZW1haWwBbMARwC0AAQABAAAAIwAESn3vNsAtAAEAAQAAACMABEp97zXAEQACAAEAAUQhAAYDbnMzwBHAEQACAAEAAUQhAAYDbnMywBHAEQACAAEAAUQhAAYDbnM0wBHAEQACAAEAAUQhAAYDbnMxwBHAjAABAAEAAVWKAATY7yYKwGgAAQABAAFVigAE2O8kCsB6AAEAAQABVYoABNjvIgrAngABAAEAAVWKAATY7yAK","payload_printable":".............mail.google.com.............8...\ngooglemail.l...-.......#..J}.6.-.......#..J}.5........D!...ns3..........D!...ns2..........D!...ns4..........D!...ns1..........U.....&\n.h......U.....$\n.z......U.....\"\n........U..... \n","stream":0,"packet":"AAAAAAAAAAAAAAAACABFAAEAeuFAAEAREIl2vWCEdr1ghAA13GoA7P7\/mBCBgAABAAMABAAEBG1haWwGZ29vZ2xlA2NvbQAAAQABwAwABQABAAU4rgAPCmdvb2dsZW1haWwBbMARwC0AAQABAAAAIwAESn3vNsAtAAEAAQAAACMABEp97zXAEQACAAEAAUQhAAYDbnMzwBHAEQACAAEAAUQhAAYDbnMywBHAEQACAAEAAUQhAAYDbnM0wBHAEQACAAEAAUQhAAYDbnMxwBHAjAABAAEAAVWKAATY7yYKwGgAAQABAAFVigAE2O8kCsB6AAEAAQABVYoABNjvIgrAngABAAEAAVWKAATY7yAK","packet_info":{"linktype":1},"pcap_filename":"\/pcaps\/modbusSmall.pcap"}

//nolint:lll
//{"timestamp":"2016-09-14T18:19:04.752237+0300","flow_id":1472623664406443,"event_type":"flow","src_ip":"10.1.1.1","src_port":53455,"dest_ip":"10.1.1.2","dest_port":80,"proto":"TCP","flow":{"pkts_toserver":7,"pkts_toclient":4,"bytes_toserver":3242,"bytes_toclient":5081,"start":"2016-09-14T18:19:03.696235+0300","end":"2016-09-14T18:19:04.752237+0300","age":1,"state":"new","reason":"shutdown"},"tcp":{"tcp_flags":"13","tcp_flags_ts":"13","tcp_flags_tc":"00","syn":true,"fin":true,"ack":true,"state":"syn_sent"}}

//nolint:lll
//{"timestamp":"2016-09-19T16:31:28.875464+0300","event_type":"stats","stats":{"uptime":0,"decoder":{"pkts":11,"bytes":8323,"invalid":0,"ipv4":11,"ipv6":0,"ethernet":11,"raw":0,"null":0,"sll":0,"tcp":11,"udp":0,"sctp":0,"icmpv4":0,"icmpv6":0,"ppp":0,"pppoe":0,"gre":0,"vlan":0,"vlan_qinq":0,"teredo":0,"ipv4_in_ipv6":0,"ipv6_in_ipv6":0,"mpls":0,"avg_pkt_size":756,"max_pkt_size":4907,"erspan":0,"ipraw":{"invalid_ip_version":0},"ltnull":{"pkt_too_small":0,"unsupported_type":0},"dce":{"pkt_too_small":0}},"flow":{"memcap":0,"spare":10000,"emerg_mode_entered":0,"emerg_mode_over":0,"tcp_reuse":0,"memuse":7154600},"defrag":{"ipv4":{"fragments":0,"reassembled":0,"timeouts":0},"ipv6":{"fragments":0,"reassembled":0,"timeouts":0},"max_frag_hits":0},"stream":{"3whs_ack_in_wrong_dir":0,"3whs_async_wrong_seq":0,"3whs_right_seq_wrong_ack_evasion":0},"tcp":{"sessions":1,"ssn_memcap_drop":0,"pseudo":0,"pseudo_failed":0,"invalid_checksum":5,"no_flow":0,"syn":1,"synack":0,"rst":0,"segment_memcap_drop":0,"stream_depth_reached":0,"reassembly_gap":0,"memuse":786432,"reassembly_memuse":12320544},"detect":{"alert":0},"flow_mgr":{"closed_pruned":0,"new_pruned":0,"est_pruned":0},"dns":{"memuse":0,"memcap_state":0,"memcap_global":0},"http":{"memuse":0,"memcap":0}}}

func TestAlert(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	log := `{
		"timestamp": "2009-10-05T06:06:09.957250+0000",
		"flow_id": 1745769129251478,
		"pcap_cnt": 18,
		"event_type": "alert",
		"src_ip": "10.10.1.4",
		"src_port": 1470,
		"dest_ip": "74.53.140.153",
		"dest_port": 25,
		"proto": "006",
		"metadata": {
			"flowints": {
			"applayer.anomaly.count": 1
			}
		},
		"community_id": "1:gr+OgB+EqGk3Rt+VUVWX92tFJxU=",
		"alert": {
			"action": "allowed",
			"gid": 1,
			"signature_id": 103,
			"rev": 0,
			"signature": "FOO SMTP",
			"category": "",
			"severity": 3
		},
		"smtp": {
			"helo": "GP",
			"mail_from": "<acme@example.com>"
		},
		"app_proto": "smtp",
		"app_proto_tc": "failed",
		"flow": {
			"pkts_toserver": 8,
			"pkts_toclient": 8,
			"bytes_toserver": 584,
			"bytes_toclient": 838,
			"start": "2009-10-05T06:06:07.529046+0000"
		},
		"payload": "ABCD",
		"payload_printable": "RCPT TO: acme@example.com>\r\n",
		"stream": 0,
		"packet": "ANCD",
		"packet_info": {
			"linktype": 1
		},
		"pcap_filename": "/pcaps/smtp.pcap"
	}`

	expectedTime, _ := timestamp.Parse(time.RFC3339Nano, "2009-10-05T06:06:09.957250+0000")

	expectedEvent := &Alert{
		Timestamp: aws.String("2009-10-05T06:06:09.957250+0000"),
		FlowID:    aws.Int(1745769129251478),
		PcapCnt:   aws.Int(18),
		EventType: aws.String("alert"),
		Alert: &AlertDetails{
			Action:      aws.String("allowed"),
			GID:         aws.Int(1),
			SignatureID: aws.Int(103),
			Rev:         aws.Int(0),
			Signature:   aws.String("FOO SMTP"),
			Category:    aws.String(""),
			Severity:    aws.Int(3),
		},
		DestIP:   aws.String("74.53.140.153"),
		DestPort: aws.Int(25),
		Packet:   aws.String("ANCD"),
		PacketInfo: &AlertPacketInfo{
			Linktype: aws.Int(1),
		},
		PcapFilename: aws.String("/pcaps/smtp.pcap"),
		Proto:        aws.String("006"),
		SrcIP:        aws.String("10.10.1.4"),
		SrcPort:      aws.Int(1470),
		Stream:       aws.Int(0),
		Metadata: &AlertMetadata{
			Flowints: &AlertMetadataFlowints{
				ApplayerAnomalyCount: aws.Int(1),
			},
		},
		CommunityID: aws.String("1:gr+OgB+EqGk3Rt+VUVWX92tFJxU="),
		SMTP: &AlertSMTP{
			Helo:     aws.String("GP"),
			MailFrom: aws.String("<acme@example.com>"),
		},
		AppProto:   aws.String("smtp"),
		AppProtoTc: aws.String("failed"),
		Flow: &AlertFlow{
			PktsToserver:  aws.Int(8),
			PktsToclient:  aws.Int(8),
			BytesToserver: aws.Int(584),
			BytesToclient: aws.Int(838),
			Start:         aws.String("2009-10-05T06:06:07.529046+0000"),
		},
		Payload:          aws.String("ABCD"),
		PayloadPrintable: aws.String("RCPT TO: acme@example.com>\r\n"),
	}

	expectedEvent.AppendAnyIPAddresses("10.10.1.4", "74.53.140.153")
	// panther fields
	expectedEvent.PantherLogType = aws.String("Suricata.Alert")
	expectedEvent.PantherEventTime = &expectedTime

	checkAlert(t, log, expectedEvent)
}

func TestAlertType(t *testing.T) {
	parser := &AlertParser{}
	require.Equal(t, "Suricata.Alert", parser.LogType())
}

func checkAlert(t *testing.T, log string, expectedEvent *Alert) {
	parser := &AlertParser{}
	events := parser.Parse(log)
	require.Equal(t, 1, len(events))
	event := events[0].(*Alert)

	// rowid changes each time
	require.Greater(t, len(*event.PantherRowID), 0) // ensure something is there.
	expectedEvent.PantherRowID = event.PantherRowID

	// PantherParseTime is set to time.Now().UTC(). Require not nil
	require.NotNil(t, event.PantherParseTime)
	expectedEvent.PantherParseTime = event.PantherParseTime

	require.Equal(t, expectedEvent, event)
}
