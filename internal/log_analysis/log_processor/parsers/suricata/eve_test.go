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

// {"timestamp":"2020-03-05T02:49:15.651187+0000","flow_id":1338637835562931,"in_iface":"eth0","event_type":"dns","src_ip":"172.31.8.201","src_port":47930,"dest_ip":"172.31.0.2","dest_port":53,"proto":"UDP","dns":{"type":"query","id":60065,"rrname":"ip-172-31-8-201.ap-southeast-2.compute.internal","rrtype":"A","tx_id":0}}
// {"timestamp":"2020-03-05T02:49:15.651291+0000","flow_id":1397500362354715,"in_iface":"eth0","event_type":"dns","src_ip":"172.31.8.201","src_port":47035,"dest_ip":"172.31.0.2","dest_port":53,"proto":"UDP","dns":{"type":"query","id":23632,"rrname":"ip-172-31-8-201.ap-southeast-2.compute.internal","rrtype":"AAAA","tx_id":0}}
// {"timestamp":"2020-03-05T02:49:15.653247+0000","flow_id":1338637835562931,"in_iface":"eth0","event_type":"dns","src_ip":"172.31.8.201","src_port":47930,"dest_ip":"172.31.0.2","dest_port":53,"proto":"UDP","dns":{"version":2,"type":"answer","id":60065,"flags":"8180","qr":true,"rd":true,"ra":true,"rrname":"ip-172-31-8-201.ap-southeast-2.compute.internal","rrtype":"A","rcode":"NOERROR","answers":[{"rrname":"ip-172-31-8-201.ap-southeast-2.compute.internal","rrtype":"A","ttl":60,"rdata":"172.31.8.201"}],"grouped":{"A":["172.31.8.201"]}}}
// {"timestamp":"2020-03-05T02:49:15.671146+0000","flow_id":1397500362354715,"in_iface":"eth0","event_type":"dns","src_ip":"172.31.8.201","src_port":47035,"dest_ip":"172.31.0.2","dest_port":53,"proto":"UDP","dns":{"version":2,"type":"answer","id":23632,"flags":"8180","qr":true,"rd":true,"ra":true,"rrname":"ip-172-31-8-201.ap-southeast-2.compute.internal","rrtype":"AAAA","rcode":"NOERROR","authorities":[{"rrname":"ap-southeast-2.compute.internal","rrtype":"SOA","ttl":60}]}}
// {"timestamp":"2020-03-05T02:49:17.000632+0000","flow_id":837750155345603,"in_iface":"eth0","event_type":"flow","src_ip":"45.141.86.128","src_port":59315,"dest_ip":"172.31.8.201","dest_port":22,"proto":"TCP","app_proto":"ssh","flow":{"pkts_toserver":18,"pkts_toclient":16,"bytes_toserver":2982,"bytes_toclient":3477,"start":"2020-03-05T02:48:11.360131+0000","end":"2020-03-05T02:48:16.753392+0000","age":5,"state":"closed","reason":"timeout","alerted":false},"tcp":{"tcp_flags":"db","tcp_flags_ts":"db","tcp_flags_tc":"5b","syn":true,"fin":true,"psh":true,"ack":true,"ecn":true,"cwr":true,"state":"closed"}}
// {"timestamp":"2020-03-05T02:49:20.642408+0000","flow_id":283589856884159,"in_iface":"eth0","event_type":"ssh","src_ip":"45.141.86.128","src_port":22361,"dest_ip":"172.31.8.201","dest_port":22,"proto":"TCP","ssh":{"client":{"proto_version":"2.0","software_version":"paramiko_1.8.1"},"server":{"proto_version":"2.0","software_version":"OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"}}}
// {"timestamp":"2020-03-05T02:49:22.528275+0000","event_type":"stats","stats":{"uptime":104383,"capture":{"kernel_packets":107675,"kernel_drops":0,"errors":0},"decoder":{"pkts":107679,"bytes":90207430,"invalid":0,"ipv4":103436,"ipv6":29,"ethernet":107679,"raw":0,"null":0,"sll":0,"tcp":103121,"udp":315,"sctp":0,"icmpv4":0,"icmpv6":29,"ppp":0,"pppoe":0,"gre":0,"vlan":0,"vlan_qinq":0,"vxlan":0,"ieee8021ah":0,"teredo":0,"ipv4_in_ipv6":0,"ipv6_in_ipv6":0,"mpls":0,"avg_pkt_size":837,"max_pkt_size":1514,"erspan":0,"event":{"ipv4":{"pkt_too_small":0,"hlen_too_small":0,"iplen_smaller_than_hlen":0,"trunc_pkt":0,"opt_invalid":0,"opt_invalid_len":0,"opt_malformed":0,"opt_pad_required":0,"opt_eol_required":0,"opt_duplicate":0,"opt_unknown":0,"wrong_ip_version":0,"icmpv6":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_ignored":0},"icmpv4":{"pkt_too_small":0,"unknown_type":0,"unknown_code":0,"ipv4_trunc_pkt":0,"ipv4_unknown_ver":0},"icmpv6":{"unknown_type":0,"unknown_code":0,"pkt_too_small":0,"ipv6_unknown_version":0,"ipv6_trunc_pkt":0,"mld_message_with_invalid_hl":0,"unassigned_type":0,"experimentation_type":0},"ipv6":{"pkt_too_small":0,"trunc_pkt":0,"trunc_exthdr":0,"exthdr_dupl_fh":0,"exthdr_useless_fh":0,"exthdr_dupl_rh":0,"exthdr_dupl_hh":0,"exthdr_dupl_dh":0,"exthdr_dupl_ah":0,"exthdr_dupl_eh":0,"exthdr_invalid_optlen":0,"wrong_ip_version":0,"exthdr_ah_res_not_null":0,"hopopts_unknown_opt":0,"hopopts_only_padding":0,"dstopts_unknown_opt":0,"dstopts_only_padding":0,"rh_type_0":0,"zero_len_padn":0,"fh_non_zero_reserved_field":0,"data_after_none_header":0,"unknown_next_header":0,"icmpv4":0,"frag_pkt_too_large":0,"frag_overlap":0,"frag_ignored":0,"ipv4_in_ipv6_too_small":0,"ipv4_in_ipv6_wrong_version":0,"ipv6_in_ipv6_too_small":0,"ipv6_in_ipv6_wrong_version":0},"tcp":{"pkt_too_small":0,"hlen_too_small":0,"invalid_optlen":0,"opt_invalid_len":0,"opt_duplicate":0},"udp":{"pkt_too_small":0,"hlen_too_small":0,"hlen_invalid":0},"sll":{"pkt_too_small":0},"ethernet":{"pkt_too_small":0},"ppp":{"pkt_too_small":0,"vju_pkt_too_small":0,"ip4_pkt_too_small":0,"ip6_pkt_too_small":0,"wrong_type":0,"unsup_proto":0},"pppoe":{"pkt_too_small":0,"wrong_code":0,"malformed_tags":0},"gre":{"pkt_too_small":0,"wrong_version":0,"version0_recur":0,"version0_flags":0,"version0_hdr_too_big":0,"version0_malformed_sre_hdr":0,"version1_chksum":0,"version1_route":0,"version1_ssr":0,"version1_recur":0,"version1_flags":0,"version1_no_key":0,"version1_wrong_protocol":0,"version1_malformed_sre_hdr":0,"version1_hdr_too_big":0},"vlan":{"header_too_small":0,"unknown_type":0,"too_many_layers":0},"ieee8021ah":{"header_too_small":0},"ipraw":{"invalid_ip_version":0},"ltnull":{"pkt_too_small":0,"unsupported_type":0},"sctp":{"pkt_too_small":0},"mpls":{"header_too_small":0,"pkt_too_small":0,"bad_label_router_alert":0,"bad_label_implicit_null":0,"bad_label_reserved":0,"unknown_payload_type":0},"erspan":{"header_too_small":0,"unsupported_version":0,"too_many_vlan_layers":0}},"dce":{"pkt_too_small":0}},"flow":{"memcap":0,"tcp":1151,"udp":157,"icmpv4":0,"icmpv6":29,"spare":10000,"emerg_mode_entered":0,"emerg_mode_over":0,"tcp_reuse":0,"memuse":7479880},"defrag":{"ipv4":{"fragments":0,"reassembled":0,"timeouts":0},"ipv6":{"fragments":0,"reassembled":0,"timeouts":0},"max_frag_hits":0},"flow_bypassed":{"local_pkts":0,"local_bytes":0,"local_capture_pkts":0,"local_capture_bytes":0,"closed":0,"pkts":0,"bytes":0},"tcp":{"sessions":1103,"ssn_memcap_drop":0,"pseudo":0,"pseudo_failed":0,"invalid_checksum":0,"no_flow":0,"syn":1202,"synack":1307,"rst":147,"midstream_pickups":0,"pkt_on_wrong_thread":0,"segment_memcap_drop":0,"stream_depth_reached":2,"reassembly_gap":2,"overlap":1059,"overlap_diff_data":0,"insert_data_normal_fail":0,"insert_data_overlap_fail":0,"insert_list_fail":0,"memuse":573440,"reassembly_memuse":108544},"detect":{"engines":[{"id":0,"last_reload":"2020-03-03T21:49:39.260181+0000","rules_loaded":0,"rules_failed":0}],"alert":0},"app_layer":{"flow":{"http":42,"ftp":0,"smtp":0,"tls":9,"ssh":953,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":61,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":59,"snmp":0,"failed_tcp":0,"dcerpc_udp":0,"dns_udp":37,"nfs_udp":0,"krb5_udp":0,"failed_udp":0},"tx":{"http":46,"ftp":0,"smtp":0,"tls":0,"ssh":0,"imap":0,"smb":0,"dcerpc_tcp":0,"dns_tcp":0,"nfs_tcp":0,"ntp":61,"ftp-data":0,"tftp":0,"ikev2":0,"krb5_tcp":0,"dhcp":116,"snmp":0,"dcerpc_udp":0,"dns_udp":80,"nfs_udp":0,"krb5_udp":0},"expectations":0},"flow_mgr":{"closed_pruned":992,"new_pruned":92,"est_pruned":236,"bypassed_pruned":0,"flows_checked":0,"flows_notimeout":0,"flows_timeout":0,"flows_timeout_inuse":0,"flows_removed":0,"rows_checked":65536,"rows_skipped":65536,"rows_empty":0,"rows_busy":0,"rows_maxlen":0},"http":{"memuse":0,"memcap":0},"ftp":{"memuse":0,"memcap":0}}}
// {"timestamp":"2020-03-05T02:49:23.000494+0000","flow_id":342179649256017,"in_iface":"eth0","event_type":"flow","src_ip":"45.141.86.128","src_port":19638,"dest_ip":"172.31.8.201","dest_port":22,"proto":"TCP","app_proto":"ssh","flow":{"pkts_toserver":16,"pkts_toclient":15,"bytes_toserver":3080,"bytes_toclient":3111,"start":"2020-03-05T02:48:17.424529+0000","end":"2020-03-05T02:48:22.120404+0000","age":5,"state":"closed","reason":"timeout","alerted":false},"tcp":{"tcp_flags":"db","tcp_flags_ts":"db","tcp_flags_tc":"5b","syn":true,"fin":true,"psh":true,"ack":true,"ecn":true,"cwr":true,"state":"closed"}}

func TestEve(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	//nolint:lll
	log := `{"timestamp":"2020-03-05T02:49:20.642408+0000","flow_id":283589856884159,"in_iface":"eth0","event_type":"ssh","src_ip":"45.141.86.128","src_port":22361,"dest_ip":"172.31.8.201","dest_port":22,"proto":"TCP","ssh":{"client":{"proto_version":"2.0","software_version":"paramiko_1.8.1"},"server":{"proto_version":"2.0","software_version":"OpenSSH_7.6p1 Ubuntu-4ubuntu0.3"}}}`

	expectedTime, _ := timestamp.Parse(time.RFC3339Nano, "2020-03-05T02:49:20.642408+0000")

	expectedEvent := &Eve{
		Timestamp: aws.String("2020-03-05T02:49:20.642408+0000"),
		EventType: "ssh",
		SSH:       nil,
	}
	// panther fields
	expectedEvent.PantherLogType = aws.String("Suricata.Eve")
	expectedEvent.PantherEventTime = &expectedTime

	checkEve(t, log, expectedEvent)
}

func TestEveType(t *testing.T) {
	parser := &EveParser{}
	require.Equal(t, "Suricata.Eve", parser.LogType())
}

func checkEve(t *testing.T, log string, expectedEvent *Eve) {
	parser := &EveParser{}
	events := parser.Parse(log)
	require.Equal(t, 1, len(events))
	event := events[0].(*Eve)

	// rowid changes each time
	require.Greater(t, len(*event.PantherRowID), 0) // ensure something is there.
	expectedEvent.PantherRowID = event.PantherRowID

	// PantherParseTime is set to time.Now().UTC(). Require not nil
	require.NotNil(t, event.PantherParseTime)
	expectedEvent.PantherParseTime = event.PantherParseTime

	require.Equal(t, expectedEvent, event)
}
