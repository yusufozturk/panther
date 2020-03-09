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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
)

type Eve struct {
	Alert            *Alert       `json:"alert,omitempty"`
	Anomaly          *Anomaly     `json:"anomaly,omitempty"`
	AppProto         *string      `json:"app_proto,omitempty"`
	AppProtoExpected *string      `json:"app_proto_expected,omitempty"`
	AppProtoOrig     *string      `json:"app_proto_orig,omitempty"`
	AppProtoTc       *string      `json:"app_proto_tc,omitempty"`
	AppProtoTs       *string      `json:"app_proto_ts,omitempty"`
	CommunityID      *string      `json:"community_id,omitempty"`
	DestIP           *string      `json:"dest_ip,omitempty"`
	DestPort         *int64       `json:"dest_port,omitempty"`
	DHCP             *DHCP        `json:"dhcp,omitempty"`
	Dnp3             *Dnp3        `json:"dnp3,omitempty"`
	DNS              *DNS         `json:"dns,omitempty"`
	Drop             *Drop        `json:"drop,omitempty"`
	Email            *Email       `json:"email,omitempty"`
	EventType        string       `json:"event_type" validate:"required"`
	Fileinfo         *Fileinfo    `json:"fileinfo,omitempty"`
	Flow             *EveFlow     `json:"flow,omitempty"`
	FlowID           *int64       `json:"flow_id,omitempty"`
	FTP              *EveFTP      `json:"ftp,omitempty"`
	HTTP             *EveHTTP     `json:"http,omitempty"`
	ICMPCode         *int64       `json:"icmp_code,omitempty"`
	ICMPType         *int64       `json:"icmp_type,omitempty"`
	Ikev2            *Ikev2       `json:"ikev2,omitempty"`
	InIface          *string      `json:"in_iface,omitempty"`
	Krb5             *Krb5        `json:"krb5,omitempty"`
	Metadata         *EveMetadata `json:"metadata,omitempty"`
	Netflow          *Netflow     `json:"netflow,omitempty"`
	NFS              *NFS         `json:"nfs,omitempty"`
	Packet           *string      `json:"packet,omitempty"`
	PacketInfo       *PacketInfo  `json:"packet_info,omitempty"`
	Payload          *string      `json:"payload,omitempty"`
	PayloadPrintable *string      `json:"payload_printable,omitempty"`
	PcapCnt          *int64       `json:"pcap_cnt,omitempty"`
	PcapFilename     string       `json:"pcap_filename",omitempty`
	Proto            *string      `json:"proto,omitempty"`
	RDP              *RDP         `json:"rdp,omitempty"`
	ResponseICMPCode *int64       `json:"response_icmp_code,omitempty"`
	ResponseICMPType *int64       `json:"response_icmp_type,omitempty"`
	RPC              *RPC         `json:"rpc,omitempty"`
	SIP              *SIP         `json:"sip,omitempty"`
	SMB              *SMB         `json:"smb,omitempty"`
	SMTP             *SMTP        `json:"smtp,omitempty"`
	SNMP             *SNMP        `json:"snmp,omitempty"`
	SrcIP            *string      `json:"src_ip,omitempty"`
	SrcPort          *int64       `json:"src_port,omitempty"`
	SSH              *SSH         `json:"ssh,omitempty"`
	Stats            *Stats       `json:"stats,omitempty"`
	Stream           *int64       `json:"stream,omitempty"`
	TCP              *EveTCP      `json:"tcp,omitempty"`
	TFTP             *TFTP        `json:"tftp,omitempty"`
	Timestamp        *string      `json:"timestamp" validate:"required"`
	TLS              *TLS         `json:"tls,omitempty"`
	Tunnel           *Tunnel      `json:"tunnel,omitempty"`
	TxID             *int64       `json:"tx_id,omitempty"`
	Vars             *Vars        `json:"vars,omitempty"`
	VLAN             []int64      `json:"vlan,omitempty"`

	parsers.PantherLog
}

type Alert struct {
	Action      string         `json:"action" validate:"required"`
	Category    string         `json:"category" validate:"required"`
	Gid         int64          `json:"gid" validate:"required"`
	Metadata    *AlertMetadata `json:"metadata,omitempty"`
	Rev         int64          `json:"rev" validate:"required"`
	Severity    int64          `json:"severity" validate:"required"`
	Signature   string         `json:"signature" validate:"required"`
	SignatureID int64          `json:"signature_id" validate:"required"`
}

type AlertMetadata struct {
	AffectedProduct   []string `json:"affected_product" validate:"required"`
	AttackTarget      []string `json:"attack_target" validate:"required"`
	CreatedAt         []string `json:"created_at" validate:"required"`
	Deployment        []string `json:"deployment" validate:"required"`
	FormerCategory    []string `json:"former_category" validate:"required"`
	MalwareFamily     []string `json:"malware_family" validate:"required"`
	PerformanceImpact []string `json:"performance_impact" validate:"required"`
	SignatureSeverity []string `json:"signature_severity" validate:"required"`
	Tag               []string `json:"tag" validate:"required"`
	UpdatedAt         []string `json:"updated_at" validate:"required"`
}

type Anomaly struct {
	Code    *int64  `json:"code,omitempty"`
	Event   *string `json:"event,omitempty"`
	EventNo *string `json:"event_no,omitempty"`
	Layer   *string `json:"layer,omitempty"`
	Type    string  `json:"type" validate:"required"`
}

type DHCP struct {
	AssignedIP    string   `json:"assigned_ip" validate:"required"`
	ClientID      *string  `json:"client_id,omitempty"`
	ClientIP      string   `json:"client_ip" validate:"required"`
	ClientMAC     string   `json:"client_mac" validate:"required"`
	DHCPType      *string  `json:"dhcp_type,omitempty"`
	DNSServers    []string `json:"dns_servers" validate:"required"`
	Hostname      *string  `json:"hostname,omitempty"`
	ID            int64    `json:"id" validate:"required"`
	LeaseTime     *int64   `json:"lease_time,omitempty"`
	NextServerIP  *string  `json:"next_server_ip,omitempty"`
	Params        []string `json:"params" validate:"required"`
	RebindingTime *int64   `json:"rebinding_time,omitempty"`
	RelayIP       *string  `json:"relay_ip,omitempty"`
	RenewalTime   *int64   `json:"renewal_time,omitempty"`
	RequestedIP   *string  `json:"requested_ip,omitempty"`
	Routers       []string `json:"routers" validate:"required"`
	SubnetMask    *string  `json:"subnet_mask,omitempty"`
	Type          string   `json:"type" validate:"required"`
}

type DNS struct {
	Aa          *bool                  `json:"aa,omitempty"`
	Answer      *PurpleAnswer          `json:"answer,omitempty"`
	Answers     []AnswerElement        `json:"answers" validate:"required"`
	Authorities []DNSAuthority         `json:"authorities" validate:"required"`
	Flags       *string                `json:"flags,omitempty"`
	Grouped     map[string]interface{} `json:"grouped,omitempty"`
	ID          *int64                 `json:"id,omitempty"`
	Qr          *bool                  `json:"qr,omitempty"`
	Query       []Query                `json:"query" validate:"required"`
	Ra          *bool                  `json:"ra,omitempty"`
	Rcode       *string                `json:"rcode,omitempty"`
	RD          *bool                  `json:"rd,omitempty"`
	Rrname      *string                `json:"rrname,omitempty"`
	Rrtype      *string                `json:"rrtype,omitempty"`
	Tc          *bool                  `json:"tc,omitempty"`
	TxID        *int64                 `json:"tx_id,omitempty"`
	Type        *string                `json:"type,omitempty"`
	Version     *int64                 `json:"version,omitempty"`
}

type PurpleAnswer struct {
	Aa          bool              `json:"aa" validate:"required"`
	Authorities []AnswerAuthority `json:"authorities" validate:"required"`
	Flags       string            `json:"flags" validate:"required"`
	ID          int64             `json:"id" validate:"required"`
	Qr          bool              `json:"qr" validate:"required"`
	Ra          bool              `json:"ra" validate:"required"`
	Rcode       string            `json:"rcode" validate:"required"`
	Rrname      string            `json:"rrname" validate:"required"`
	Rrtype      string            `json:"rrtype" validate:"required"`
	Type        string            `json:"type" validate:"required"`
	Version     int64             `json:"version" validate:"required"`
}

type AnswerAuthority struct {
	Rrname string `json:"rrname" validate:"required"`
	Rrtype string `json:"rrtype" validate:"required"`
	TTL    int64  `json:"ttl" validate:"required"`
}

type AnswerElement struct {
	Rdata  *string `json:"rdata,omitempty"`
	Rrname string  `json:"rrname" validate:"required"`
	Rrtype string  `json:"rrtype" validate:"required"`
	TTL    int64   `json:"ttl" validate:"required"`
}

type DNSAuthority struct {
	Rdata  *string `json:"rdata,omitempty"`
	Rrname string  `json:"rrname" validate:"required"`
	Rrtype string  `json:"rrtype" validate:"required"`
	TTL    int64   `json:"ttl" validate:"required"`
}

type Query struct {
	ID     int64  `json:"id" validate:"required"`
	Rrname string `json:"rrname" validate:"required"`
	Rrtype string `json:"rrtype" validate:"required"`
	TxID   int64  `json:"tx_id" validate:"required"`
	Type   string `json:"type" validate:"required"`
}

type Dnp3 struct {
	Application *Dnp3Application `json:"application,omitempty"`
	Control     *Dnp3Control     `json:"control,omitempty"`
	Dst         *int64           `json:"dst,omitempty"`
	Iin         *Dnp3Iin         `json:"iin,omitempty"`
	Request     *Dnp3Request     `json:"request,omitempty"`
	Response    *Dnp3Response    `json:"response,omitempty"`
	Src         *int64           `json:"src,omitempty"`
	Type        *string          `json:"type,omitempty"`
}

type Dnp3Application struct {
	Complete     bool           `json:"complete" validate:"required"`
	Control      PurpleControl  `json:"control" validate:"required"`
	FunctionCode int64          `json:"function_code" validate:"required"`
	Objects      []PurpleObject `json:"objects" validate:"required"`
}

type PurpleControl struct {
	Con      bool  `json:"con" validate:"required"`
	Fin      bool  `json:"fin" validate:"required"`
	Fir      bool  `json:"fir" validate:"required"`
	Sequence int64 `json:"sequence" validate:"required"`
	Uns      bool  `json:"uns" validate:"required"`
}

type PurpleObject struct {
	Count      int64         `json:"count" validate:"required"`
	Group      int64         `json:"group" validate:"required"`
	Points     []PurplePoint `json:"points" validate:"required"`
	PrefixCode int64         `json:"prefix_code" validate:"required"`
	Qualifier  int64         `json:"qualifier" validate:"required"`
	RangeCode  int64         `json:"range_code" validate:"required"`
	Start      int64         `json:"start" validate:"required"`
	Stop       int64         `json:"stop" validate:"required"`
	Variation  int64         `json:"variation" validate:"required"`
}

type PurplePoint struct {
	AuthenticationKey  *int64  `json:"authentication_key,omitempty"`
	BlockNumber        *int64  `json:"block_number,omitempty"`
	ChallengeDataLen   *int64  `json:"challenge_data_len,omitempty"`
	ChatterFilter      *int64  `json:"chatter_filter,omitempty"`
	CommLost           *int64  `json:"comm_lost,omitempty"`
	Count              *int64  `json:"count,omitempty"`
	CR                 *int64  `json:"cr,omitempty"`
	Created            *int64  `json:"created,omitempty"`
	DataMACValue       *string `json:"data->mac_value,omitempty"`
	DataWrappedKeyData *string `json:"data->wrapped_key_data,omitempty"`
	DelayMS            *int64  `json:"delay_ms,omitempty"`
	FileData           *string `json:"file_data,omitempty"`
	FileHandle         *int64  `json:"file_handle,omitempty"`
	FileSize           *int64  `json:"file_size,omitempty"`
	Filename           *string `json:"filename,omitempty"`
	FilenameOffset     *int64  `json:"filename_offset,omitempty"`
	FilenameSize       *int64  `json:"filename_size,omitempty"`
	Index              int64   `json:"index" validate:"required"`
	KeyStatus          *int64  `json:"key_status,omitempty"`
	KeyWrapAlg         *int64  `json:"key_wrap_alg,omitempty"`
	Ksq                *int64  `json:"ksq,omitempty"`
	LocalForced        *int64  `json:"local_forced,omitempty"`
	Mal                *int64  `json:"mal,omitempty"`
	MaximumBlockSize   *int64  `json:"maximum_block_size,omitempty"`
	Offtime            *int64  `json:"offtime,omitempty"`
	Online             *int64  `json:"online,omitempty"`
	Ontime             *int64  `json:"ontime,omitempty"`
	OpType             *int64  `json:"op_type,omitempty"`
	OperationalMode    *int64  `json:"operational_mode,omitempty"`
	OptionalText       *string `json:"optional_text,omitempty"`
	OverRange          *int64  `json:"over_range,omitempty"`
	Permissions        *int64  `json:"permissions,omitempty"`
	Prefix             int64   `json:"prefix" validate:"required"`
	Qu                 *int64  `json:"qu,omitempty"`
	ReferenceErr       *int64  `json:"reference_err,omitempty"`
	RemoteForced       *int64  `json:"remote_forced,omitempty"`
	RequestID          *int64  `json:"request_id,omitempty"`
	Reserved           *int64  `json:"reserved,omitempty"`
	Reserved0          *int64  `json:"reserved0,omitempty"`
	Reserved1          *int64  `json:"reserved1,omitempty"`
	Restart            *int64  `json:"restart,omitempty"`
	Size               *int64  `json:"size,omitempty"`
	State              *int64  `json:"state,omitempty"`
	StatusCode         *int64  `json:"status_code,omitempty"`
	Tcc                *int64  `json:"tcc,omitempty"`
	Timestamp          *int64  `json:"timestamp,omitempty"`
	UserNumber         *int64  `json:"user_number,omitempty"`
	USR                *int64  `json:"usr,omitempty"`
	Value              *int64  `json:"value,omitempty"`
}

type Dnp3Control struct {
	Dir          bool  `json:"dir" validate:"required"`
	FCB          bool  `json:"fcb" validate:"required"`
	Fcv          bool  `json:"fcv" validate:"required"`
	FunctionCode int64 `json:"function_code" validate:"required"`
	Pri          bool  `json:"pri" validate:"required"`
}

type Dnp3Iin struct {
	Indicators []string `json:"indicators" validate:"required"`
}

type Dnp3Request struct {
	Application RequestApplication `json:"application" validate:"required"`
	Control     RequestControl     `json:"control" validate:"required"`
	Dst         int64              `json:"dst" validate:"required"`
	Src         int64              `json:"src" validate:"required"`
	Type        string             `json:"type" validate:"required"`
}

type RequestApplication struct {
	Complete     bool           `json:"complete" validate:"required"`
	Control      FluffyControl  `json:"control" validate:"required"`
	FunctionCode int64          `json:"function_code" validate:"required"`
	Objects      []FluffyObject `json:"objects" validate:"required"`
}

type FluffyControl struct {
	Con      bool  `json:"con" validate:"required"`
	Fin      bool  `json:"fin" validate:"required"`
	Fir      bool  `json:"fir" validate:"required"`
	Sequence int64 `json:"sequence" validate:"required"`
	Uns      bool  `json:"uns" validate:"required"`
}

type FluffyObject struct {
	Count      int64         `json:"count" validate:"required"`
	Group      int64         `json:"group" validate:"required"`
	Points     []FluffyPoint `json:"points" validate:"required"`
	PrefixCode int64         `json:"prefix_code" validate:"required"`
	Qualifier  int64         `json:"qualifier" validate:"required"`
	RangeCode  int64         `json:"range_code" validate:"required"`
	Start      int64         `json:"start" validate:"required"`
	Stop       int64         `json:"stop" validate:"required"`
	Variation  int64         `json:"variation" validate:"required"`
}

type FluffyPoint struct {
	AuthenticationKey *int64  `json:"authentication_key,omitempty"`
	Count             *int64  `json:"count,omitempty"`
	CR                *int64  `json:"cr,omitempty"`
	Created           *int64  `json:"created,omitempty"`
	FileSize          *int64  `json:"file_size,omitempty"`
	Filename          *string `json:"filename,omitempty"`
	FilenameOffset    *int64  `json:"filename_offset,omitempty"`
	FilenameSize      *int64  `json:"filename_size,omitempty"`
	Index             int64   `json:"index" validate:"required"`
	MaximumBlockSize  *int64  `json:"maximum_block_size,omitempty"`
	Offtime           *int64  `json:"offtime,omitempty"`
	Ontime            *int64  `json:"ontime,omitempty"`
	OpType            *int64  `json:"op_type,omitempty"`
	OperationalMode   *int64  `json:"operational_mode,omitempty"`
	Permissions       *int64  `json:"permissions,omitempty"`
	Prefix            int64   `json:"prefix" validate:"required"`
	Qu                *int64  `json:"qu,omitempty"`
	RequestID         *int64  `json:"request_id,omitempty"`
	Reserved          *int64  `json:"reserved,omitempty"`
	Size              *int64  `json:"size,omitempty"`
	StatusCode        *int64  `json:"status_code,omitempty"`
	Tcc               *int64  `json:"tcc,omitempty"`
	Timestamp         *int64  `json:"timestamp,omitempty"`
	UserNumber        *int64  `json:"user_number,omitempty"`
}

type RequestControl struct {
	Dir          bool  `json:"dir" validate:"required"`
	FCB          bool  `json:"fcb" validate:"required"`
	Fcv          bool  `json:"fcv" validate:"required"`
	FunctionCode int64 `json:"function_code" validate:"required"`
	Pri          bool  `json:"pri" validate:"required"`
}

type Dnp3Response struct {
	Application ResponseApplication `json:"application" validate:"required"`
	Control     ResponseControl     `json:"control" validate:"required"`
	Dst         int64               `json:"dst" validate:"required"`
	Iin         ResponseIin         `json:"iin" validate:"required"`
	Src         int64               `json:"src" validate:"required"`
	Type        string              `json:"type" validate:"required"`
}

type ResponseApplication struct {
	Complete     bool              `json:"complete" validate:"required"`
	Control      TentacledControl  `json:"control" validate:"required"`
	FunctionCode int64             `json:"function_code" validate:"required"`
	Objects      []TentacledObject `json:"objects" validate:"required"`
}

type TentacledControl struct {
	Con      bool  `json:"con" validate:"required"`
	Fin      bool  `json:"fin" validate:"required"`
	Fir      bool  `json:"fir" validate:"required"`
	Sequence int64 `json:"sequence" validate:"required"`
	Uns      bool  `json:"uns" validate:"required"`
}

type TentacledObject struct {
	Count      int64            `json:"count" validate:"required"`
	Group      int64            `json:"group" validate:"required"`
	Points     []TentacledPoint `json:"points" validate:"required"`
	PrefixCode int64            `json:"prefix_code" validate:"required"`
	Qualifier  int64            `json:"qualifier" validate:"required"`
	RangeCode  int64            `json:"range_code" validate:"required"`
	Start      int64            `json:"start" validate:"required"`
	Stop       int64            `json:"stop" validate:"required"`
	Variation  int64            `json:"variation" validate:"required"`
}

type TentacledPoint struct {
	ChallengeDataLen  *int64  `json:"challenge_data_len,omitempty"`
	ChatterFilter     *int64  `json:"chatter_filter,omitempty"`
	CommLost          *int64  `json:"comm_lost,omitempty"`
	Count             *int64  `json:"count,omitempty"`
	CR                *int64  `json:"cr,omitempty"`
	DataChallengeData *string `json:"data->challenge_data,omitempty"`
	DataMACValue      *string `json:"data->mac_value,omitempty"`
	DelayMS           *int64  `json:"delay_ms,omitempty"`
	FileHandle        *int64  `json:"file_handle,omitempty"`
	FileSize          *int64  `json:"file_size,omitempty"`
	Index             int64   `json:"index" validate:"required"`
	KeyStatus         *int64  `json:"key_status,omitempty"`
	KeyWrapAlg        *int64  `json:"key_wrap_alg,omitempty"`
	Ksq               *int64  `json:"ksq,omitempty"`
	LocalForced       *int64  `json:"local_forced,omitempty"`
	Mal               *int64  `json:"mal,omitempty"`
	MaximumBlockSize  *int64  `json:"maximum_block_size,omitempty"`
	Offtime           *int64  `json:"offtime,omitempty"`
	Online            *int64  `json:"online,omitempty"`
	Ontime            *int64  `json:"ontime,omitempty"`
	OpType            *int64  `json:"op_type,omitempty"`
	OptionalText      *string `json:"optional_text,omitempty"`
	OverRange         *int64  `json:"over_range,omitempty"`
	Prefix            int64   `json:"prefix" validate:"required"`
	Qu                *int64  `json:"qu,omitempty"`
	ReferenceErr      *int64  `json:"reference_err,omitempty"`
	RemoteForced      *int64  `json:"remote_forced,omitempty"`
	RequestID         *int64  `json:"request_id,omitempty"`
	Reserved          *int64  `json:"reserved,omitempty"`
	Reserved0         *int64  `json:"reserved0,omitempty"`
	Reserved1         *int64  `json:"reserved1,omitempty"`
	Restart           *int64  `json:"restart,omitempty"`
	Size              *int64  `json:"size,omitempty"`
	State             *int64  `json:"state,omitempty"`
	StatusCode        *int64  `json:"status_code,omitempty"`
	Tcc               *int64  `json:"tcc,omitempty"`
	UserNumber        *int64  `json:"user_number,omitempty"`
	Value             *int64  `json:"value,omitempty"`
}

type ResponseControl struct {
	Dir          bool  `json:"dir" validate:"required"`
	FCB          bool  `json:"fcb" validate:"required"`
	Fcv          bool  `json:"fcv" validate:"required"`
	FunctionCode int64 `json:"function_code" validate:"required"`
	Pri          bool  `json:"pri" validate:"required"`
}

type ResponseIin struct {
	Indicators []string `json:"indicators" validate:"required"`
}

type Drop struct {
	ACK     bool  `json:"ack" validate:"required"`
	Fin     bool  `json:"fin" validate:"required"`
	Ipid    int64 `json:"ipid" validate:"required"`
	Len     int64 `json:"len" validate:"required"`
	Psh     bool  `json:"psh" validate:"required"`
	Rst     bool  `json:"rst" validate:"required"`
	Syn     bool  `json:"syn" validate:"required"`
	Tcpack  int64 `json:"tcpack" validate:"required"`
	Tcpres  int64 `json:"tcpres" validate:"required"`
	Tcpseq  int64 `json:"tcpseq" validate:"required"`
	Tcpurgp int64 `json:"tcpurgp" validate:"required"`
	Tcpwin  int64 `json:"tcpwin" validate:"required"`
	Tos     int64 `json:"tos" validate:"required"`
	TTL     int64 `json:"ttl" validate:"required"`
	Urg     bool  `json:"urg" validate:"required"`
}

type Email struct {
	Attachment []string `json:"attachment" validate:"required"`
	BodyMd5    *string  `json:"body_md5,omitempty"`
	Cc         []string `json:"cc" validate:"required"`
	From       *string  `json:"from,omitempty"`
	Status     string   `json:"status" validate:"required"`
	SubjectMd5 *string  `json:"subject_md5,omitempty"`
	To         []string `json:"to" validate:"required"`
}

type EveFTP struct {
	Command        *string  `json:"command,omitempty"`
	CommandData    *string  `json:"command_data,omitempty"`
	CompletionCode []string `json:"completion_code" validate:"required"`
	DynamicPort    *int64   `json:"dynamic_port,omitempty"`
	Reply          []string `json:"reply" validate:"required"`
	ReplyReceived  string   `json:"reply_received" validate:"required"`
}

type Fileinfo struct {
	End      *int64  `json:"end,omitempty"`
	FileID   int64   `json:"file_id" validate:"required"`
	Filename string  `json:"filename" validate:"required"`
	Gaps     bool    `json:"gaps" validate:"required"`
	Magic    *string `json:"magic,omitempty"`
	Md5      *string `json:"md5,omitempty"`
	Sha1     *string `json:"sha1,omitempty"`
	Sha256   string  `json:"sha256" validate:"required"`
	Sid      []int64 `json:"sid" validate:"required"`
	Size     int64   `json:"size" validate:"required"`
	Start    *int64  `json:"start,omitempty"`
	State    string  `json:"state" validate:"required"`
	Stored   bool    `json:"stored" validate:"required"`
	TxID     int64   `json:"tx_id" validate:"required"`
}

type EveFlow struct {
	Age           *int64  `json:"age,omitempty"`
	Alerted       *bool   `json:"alerted,omitempty"`
	BytesToclient int64   `json:"bytes_toclient" validate:"required"`
	BytesToserver int64   `json:"bytes_toserver" validate:"required"`
	Emergency     *bool   `json:"emergency,omitempty"`
	End           *string `json:"end,omitempty"`
	PktsToclient  int64   `json:"pkts_toclient" validate:"required"`
	PktsToserver  int64   `json:"pkts_toserver" validate:"required"`
	Reason        *string `json:"reason,omitempty"`
	Start         string  `json:"start" validate:"required"`
	State         *string `json:"state,omitempty"`
}

type EveHTTP struct {
	ContentRange              *ContentRange    `json:"content_range,omitempty"`
	Hostname                  *string          `json:"hostname,omitempty"`
	HTTPContentType           *string          `json:"http_content_type,omitempty"`
	HTTPMethod                *string          `json:"http_method,omitempty"`
	HTTPPort                  *int64           `json:"http_port,omitempty"`
	HTTPRefer                 *string          `json:"http_refer,omitempty"`
	HTTPRequestBody           *string          `json:"http_request_body,omitempty"`
	HTTPRequestBodyPrintable  *string          `json:"http_request_body_printable,omitempty"`
	HTTPResponseBody          *string          `json:"http_response_body,omitempty"`
	HTTPResponseBodyPrintable *string          `json:"http_response_body_printable,omitempty"`
	HTTPUserAgent             *string          `json:"http_user_agent,omitempty"`
	Length                    int64            `json:"length" validate:"required"`
	Protocol                  *string          `json:"protocol,omitempty"`
	Redirect                  *string          `json:"redirect,omitempty"`
	RequestHeaders            []RequestHeader  `json:"request_headers" validate:"required"`
	ResponseHeaders           []ResponseHeader `json:"response_headers" validate:"required"`
	Status                    *int64           `json:"status,omitempty"`
	URL                       *string          `json:"url,omitempty"`
}

type ContentRange struct {
	End   *int64 `json:"end,omitempty"`
	Raw   string `json:"raw" validate:"required"`
	Size  *int64 `json:"size,omitempty"`
	Start *int64 `json:"start,omitempty"`
}

type RequestHeader struct {
	Name  string `json:"name" validate:"required"`
	Value string `json:"value" validate:"required"`
}

type ResponseHeader struct {
	Name  string `json:"name" validate:"required"`
	Value string `json:"value" validate:"required"`
}

type Ikev2 struct {
	AlgAuth      *string  `json:"alg_auth,omitempty"`
	AlgDh        *string  `json:"alg_dh,omitempty"`
	AlgEnc       *string  `json:"alg_enc,omitempty"`
	AlgEsn       *string  `json:"alg_esn,omitempty"`
	AlgPrf       *string  `json:"alg_prf,omitempty"`
	Errors       int64    `json:"errors" validate:"required"`
	ExchangeType int64    `json:"exchange_type" validate:"required"`
	InitSPI      string   `json:"init_spi" validate:"required"`
	MessageID    int64    `json:"message_id" validate:"required"`
	Notify       []string `json:"notify" validate:"required"`
	Payload      []string `json:"payload" validate:"required"`
	RespSPI      string   `json:"resp_spi" validate:"required"`
	Role         string   `json:"role" validate:"required"`
	VersionMajor int64    `json:"version_major" validate:"required"`
	VersionMinor int64    `json:"version_minor" validate:"required"`
}

type Krb5 struct {
	Cname          string  `json:"cname" validate:"required"`
	Encryption     string  `json:"encryption" validate:"required"`
	ErrorCode      *string `json:"error_code,omitempty"`
	FailedRequest  *string `json:"failed_request,omitempty"`
	MsgType        string  `json:"msg_type" validate:"required"`
	Realm          string  `json:"realm" validate:"required"`
	Sname          string  `json:"sname" validate:"required"`
	WeakEncryption bool    `json:"weak_encryption" validate:"required"`
}

type EveMetadata struct {
	Flowbits []string  `json:"flowbits" validate:"required"`
	Flowints *Flowints `json:"flowints,omitempty"`
}

type Flowints struct {
	ApplayerAnomalyCount   *int64 `json:"applayer.anomaly.count,omitempty"`
	HTTPAnomalyCount       *int64 `json:"http.anomaly.count,omitempty"`
	TCPRetransmissionCount *int64 `json:"tcp.retransmission.count,omitempty"`
	TLSAnomalyCount        *int64 `json:"tls.anomaly.count,omitempty"`
}

type NFS struct {
	FileTx    bool       `json:"file_tx" validate:"required"`
	Filename  string     `json:"filename" validate:"required"`
	Hhash     *string    `json:"hhash,omitempty"`
	ID        int64      `json:"id" validate:"required"`
	Procedure string     `json:"procedure" validate:"required"`
	Rename    *NFSRename `json:"rename,omitempty"`
	Status    string     `json:"status" validate:"required"`
	Type      string     `json:"type" validate:"required"`
	Version   int64      `json:"version" validate:"required"`
}

type NFSRename struct {
	From string `json:"from" validate:"required"`
	To   string `json:"to" validate:"required"`
}

type Netflow struct {
	Age    int64  `json:"age" validate:"required"`
	Bytes  int64  `json:"bytes" validate:"required"`
	End    string `json:"end" validate:"required"`
	MaxTTL int64  `json:"max_ttl" validate:"required"`
	MinTTL int64  `json:"min_ttl" validate:"required"`
	Pkts   int64  `json:"pkts" validate:"required"`
	Start  string `json:"start" validate:"required"`
}

type PacketInfo struct {
	Linktype int64 `json:"linktype" validate:"required"`
}

type RDP struct {
	Channels       []string   `json:"channels" validate:"required"`
	Client         *RDPClient `json:"client,omitempty"`
	Cookie         *string    `json:"cookie,omitempty"`
	ErrorCode      *int64     `json:"error_code,omitempty"`
	EventType      string     `json:"event_type" validate:"required"`
	Protocol       *string    `json:"protocol,omitempty"`
	Reason         *string    `json:"reason,omitempty"`
	ServerSupports []string   `json:"server_supports" validate:"required"`
	TxID           int64      `json:"tx_id" validate:"required"`
	X509Serials    []string   `json:"x509_serials" validate:"required"`
}

type RDPClient struct {
	Build          string   `json:"build" validate:"required"`
	Capabilities   []string `json:"capabilities" validate:"required"`
	ClientName     string   `json:"client_name" validate:"required"`
	ColorDepth     int64    `json:"color_depth" validate:"required"`
	ConnectionHint *string  `json:"connection_hint,omitempty"`
	DesktopHeight  int64    `json:"desktop_height" validate:"required"`
	DesktopWidth   int64    `json:"desktop_width" validate:"required"`
	FunctionKeys   int64    `json:"function_keys" validate:"required"`
	ID             *string  `json:"id,omitempty"`
	KeyboardLayout string   `json:"keyboard_layout" validate:"required"`
	KeyboardType   string   `json:"keyboard_type" validate:"required"`
	ProductID      int64    `json:"product_id" validate:"required"`
	Version        string   `json:"version" validate:"required"`
}

type RPC struct {
	AuthType string `json:"auth_type" validate:"required"`
	Creds    *Creds `json:"creds,omitempty"`
	Status   string `json:"status" validate:"required"`
	Xid      int64  `json:"xid" validate:"required"`
}

type Creds struct {
	Gid         int64  `json:"gid" validate:"required"`
	MachineName string `json:"machine_name" validate:"required"`
	Uid         int64  `json:"uid" validate:"required"`
}

type SIP struct {
	Code         *string `json:"code,omitempty"`
	Method       *string `json:"method,omitempty"`
	Reason       *string `json:"reason,omitempty"`
	RequestLine  *string `json:"request_line,omitempty"`
	ResponseLine *string `json:"response_line,omitempty"`
	URI          *string `json:"uri,omitempty"`
	Version      string  `json:"version" validate:"required"`
}

type SMB struct {
	Access         *string      `json:"access,omitempty"`
	Accessed       *int64       `json:"accessed,omitempty"`
	Changed        *int64       `json:"changed,omitempty"`
	ClientDialects []string     `json:"client_dialects" validate:"required"`
	ClientGUID     *string      `json:"client_guid,omitempty"`
	Command        string       `json:"command" validate:"required"`
	Created        *int64       `json:"created,omitempty"`
	Dcerpc         *Dcerpc      `json:"dcerpc,omitempty"`
	Dialect        string       `json:"dialect" validate:"required"`
	Directory      *string      `json:"directory,omitempty"`
	Disposition    *string      `json:"disposition,omitempty"`
	Filename       *string      `json:"filename,omitempty"`
	Fuid           *string      `json:"fuid,omitempty"`
	Function       *string      `json:"function,omitempty"`
	ID             int64        `json:"id" validate:"required"`
	Kerberos       *Kerberos    `json:"kerberos,omitempty"`
	Modified       *int64       `json:"modified,omitempty"`
	NamedPipe      *string      `json:"named_pipe,omitempty"`
	Ntlmssp        *Ntlmssp     `json:"ntlmssp,omitempty"`
	Rename         *SMBRename   `json:"rename,omitempty"`
	Request        *SMBRequest  `json:"request,omitempty"`
	Response       *SMBResponse `json:"response,omitempty"`
	ServerGUID     *string      `json:"server_guid,omitempty"`
	Service        *Service     `json:"service,omitempty"`
	SessionID      int64        `json:"session_id" validate:"required"`
	SetInfo        *SetInfo     `json:"set_info,omitempty"`
	Share          *string      `json:"share,omitempty"`
	ShareType      *string      `json:"share_type,omitempty"`
	Size           *int64       `json:"size,omitempty"`
	Status         *string      `json:"status,omitempty"`
	StatusCode     *string      `json:"status_code,omitempty"`
	TreeID         int64        `json:"tree_id" validate:"required"`
}

type Dcerpc struct {
	CallID     int64       `json:"call_id" validate:"required"`
	Interfaces []Interface `json:"interfaces" validate:"required"`
	Opnum      *int64      `json:"opnum,omitempty"`
	Req        *Req        `json:"req,omitempty"`
	Request    string      `json:"request" validate:"required"`
	Res        *Res        `json:"res,omitempty"`
	Response   string      `json:"response" validate:"required"`
}

type Interface struct {
	ACKReason *int64 `json:"ack_reason,omitempty"`
	ACKResult *int64 `json:"ack_result,omitempty"`
	UUID      string `json:"uuid" validate:"required"`
	Version   string `json:"version" validate:"required"`
}

type Req struct {
	FragCnt      int64 `json:"frag_cnt" validate:"required"`
	StubDataSize int64 `json:"stub_data_size" validate:"required"`
}

type Res struct {
	FragCnt      int64 `json:"frag_cnt" validate:"required"`
	StubDataSize int64 `json:"stub_data_size" validate:"required"`
}

type Kerberos struct {
	Realm  string   `json:"realm" validate:"required"`
	Snames []string `json:"snames" validate:"required"`
}

type Ntlmssp struct {
	Domain string `json:"domain" validate:"required"`
	Host   string `json:"host" validate:"required"`
	User   string `json:"user" validate:"required"`
}

type SMBRename struct {
	From string `json:"from" validate:"required"`
	To   string `json:"to" validate:"required"`
}

type SMBRequest struct {
	NativeLM string `json:"native_lm" validate:"required"`
	NativeOS string `json:"native_os" validate:"required"`
}

type SMBResponse struct {
	NativeLM string `json:"native_lm" validate:"required"`
	NativeOS string `json:"native_os" validate:"required"`
}

type Service struct {
	Request  string  `json:"request" validate:"required"`
	Response *string `json:"response,omitempty"`
}

type SetInfo struct {
	Class     string `json:"class" validate:"required"`
	InfoLevel string `json:"info_level" validate:"required"`
}

type SMTP struct {
	Helo     string   `json:"helo" validate:"required"`
	MailFrom *string  `json:"mail_from,omitempty"`
	RcptTo   []string `json:"rcpt_to" validate:"required"`
}

type SNMP struct {
	Community   *string  `json:"community,omitempty"`
	Error       *string  `json:"error,omitempty"`
	PduType     string   `json:"pdu_type" validate:"required"`
	TrapAddress *string  `json:"trap_address,omitempty"`
	TrapOID     *string  `json:"trap_oid,omitempty"`
	TrapType    *string  `json:"trap_type,omitempty"`
	Usm         *string  `json:"usm,omitempty"`
	Vars        []string `json:"vars" validate:"required"`
	Version     int64    `json:"version" validate:"required"`
}

type SSH struct {
	Client SSHClient `json:"client" validate:"required"`
	Server Server    `json:"server" validate:"required"`
}

type SSHClient struct {
	ProtoVersion    *string `json:"proto_version,omitempty"`
	SoftwareVersion *string `json:"software_version,omitempty"`
}

type Server struct {
	ProtoVersion    *string `json:"proto_version,omitempty"`
	SoftwareVersion *string `json:"software_version,omitempty"`
}

type Stats struct {
	AppLayer     StatsAppLayer     `json:"app_layer" validate:"required"`
	Decoder      StatsDecoder      `json:"decoder" validate:"required"`
	Defrag       StatsDefrag       `json:"defrag" validate:"required"`
	Detect       StatsDetect       `json:"detect" validate:"required"`
	FileStore    StatsFileStore    `json:"file_store" validate:"required"`
	Flow         StatsFlow         `json:"flow" validate:"required"`
	FlowBypassed StatsFlowBypassed `json:"flow_bypassed" validate:"required"`
	FlowMgr      StatsFlowMgr      `json:"flow_mgr" validate:"required"`
	FTP          StatsFTP          `json:"ftp" validate:"required"`
	HTTP         StatsHTTP         `json:"http" validate:"required"`
	Stream       StatsStream       `json:"stream" validate:"required"`
	TCP          StatsTCP          `json:"tcp" validate:"required"`
	Threads      map[string]Thread `json:"threads" validate:"required"`
	Uptime       int64             `json:"uptime" validate:"required"`
}

type StatsAppLayer struct {
	Expectations      int64      `json:"expectations" validate:"required"`
	ExpectationsDelta int64      `json:"expectations_delta" validate:"required"`
	Flow              PurpleFlow `json:"flow" validate:"required"`
	Tx                PurpleTx   `json:"tx" validate:"required"`
}

type PurpleFlow struct {
	DcerpcTCP      int64  `json:"dcerpc_tcp" validate:"required"`
	DcerpcTCPDelta int64  `json:"dcerpc_tcp_delta" validate:"required"`
	DcerpcUDP      int64  `json:"dcerpc_udp" validate:"required"`
	DcerpcUDPDelta int64  `json:"dcerpc_udp_delta" validate:"required"`
	DHCP           int64  `json:"dhcp" validate:"required"`
	DHCPDelta      int64  `json:"dhcp_delta" validate:"required"`
	Dnp3           int64  `json:"dnp3" validate:"required"`
	Dnp3Delta      int64  `json:"dnp3_delta" validate:"required"`
	DNSTCP         int64  `json:"dns_tcp" validate:"required"`
	DNSTCPDelta    int64  `json:"dns_tcp_delta" validate:"required"`
	DNSUDP         int64  `json:"dns_udp" validate:"required"`
	DNSUDPDelta    int64  `json:"dns_udp_delta" validate:"required"`
	EnipTCP        int64  `json:"enip_tcp" validate:"required"`
	EnipTCPDelta   int64  `json:"enip_tcp_delta" validate:"required"`
	EnipUDP        int64  `json:"enip_udp" validate:"required"`
	EnipUDPDelta   int64  `json:"enip_udp_delta" validate:"required"`
	FailedTCP      int64  `json:"failed_tcp" validate:"required"`
	FailedTCPDelta int64  `json:"failed_tcp_delta" validate:"required"`
	FailedUDP      int64  `json:"failed_udp" validate:"required"`
	FailedUDPDelta int64  `json:"failed_udp_delta" validate:"required"`
	FTP            int64  `json:"ftp" validate:"required"`
	FTPData        int64  `json:"ftp-data" validate:"required"`
	FTPDataDelta   int64  `json:"ftp-data_delta" validate:"required"`
	FTPDelta       int64  `json:"ftp_delta" validate:"required"`
	HTTP           int64  `json:"http" validate:"required"`
	HTTPDelta      int64  `json:"http_delta" validate:"required"`
	Ikev2          int64  `json:"ikev2" validate:"required"`
	Ikev2Delta     int64  `json:"ikev2_delta" validate:"required"`
	IMAP           int64  `json:"imap" validate:"required"`
	IMAPDelta      int64  `json:"imap_delta" validate:"required"`
	Krb5TCP        int64  `json:"krb5_tcp" validate:"required"`
	Krb5TCPDelta   int64  `json:"krb5_tcp_delta" validate:"required"`
	Krb5UDP        int64  `json:"krb5_udp" validate:"required"`
	Krb5UDPDelta   int64  `json:"krb5_udp_delta" validate:"required"`
	Modbus         int64  `json:"modbus" validate:"required"`
	ModbusDelta    int64  `json:"modbus_delta" validate:"required"`
	MSN            *int64 `json:"msn,omitempty"`
	MSNDelta       *int64 `json:"msn_delta,omitempty"`
	NFSTCP         int64  `json:"nfs_tcp" validate:"required"`
	NFSTCPDelta    int64  `json:"nfs_tcp_delta" validate:"required"`
	NFSUDP         int64  `json:"nfs_udp" validate:"required"`
	NFSUDPDelta    int64  `json:"nfs_udp_delta" validate:"required"`
	NTP            int64  `json:"ntp" validate:"required"`
	NTPDelta       int64  `json:"ntp_delta" validate:"required"`
	RDP            int64  `json:"rdp" validate:"required"`
	RDPDelta       int64  `json:"rdp_delta" validate:"required"`
	SIP            int64  `json:"sip" validate:"required"`
	SIPDelta       int64  `json:"sip_delta" validate:"required"`
	SMB            int64  `json:"smb" validate:"required"`
	SMBDelta       int64  `json:"smb_delta" validate:"required"`
	SMTP           int64  `json:"smtp" validate:"required"`
	SMTPDelta      int64  `json:"smtp_delta" validate:"required"`
	SNMP           int64  `json:"snmp" validate:"required"`
	SNMPDelta      int64  `json:"snmp_delta" validate:"required"`
	SSH            int64  `json:"ssh" validate:"required"`
	SSHDelta       int64  `json:"ssh_delta" validate:"required"`
	TFTP           int64  `json:"tftp" validate:"required"`
	TFTPDelta      int64  `json:"tftp_delta" validate:"required"`
	TLS            int64  `json:"tls" validate:"required"`
	TLSDelta       int64  `json:"tls_delta" validate:"required"`
}

type PurpleTx struct {
	DcerpcTCP      int64  `json:"dcerpc_tcp" validate:"required"`
	DcerpcTCPDelta int64  `json:"dcerpc_tcp_delta" validate:"required"`
	DcerpcUDP      int64  `json:"dcerpc_udp" validate:"required"`
	DcerpcUDPDelta int64  `json:"dcerpc_udp_delta" validate:"required"`
	DHCP           int64  `json:"dhcp" validate:"required"`
	DHCPDelta      int64  `json:"dhcp_delta" validate:"required"`
	Dnp3           int64  `json:"dnp3" validate:"required"`
	Dnp3Delta      int64  `json:"dnp3_delta" validate:"required"`
	DNSTCP         int64  `json:"dns_tcp" validate:"required"`
	DNSTCPDelta    int64  `json:"dns_tcp_delta" validate:"required"`
	DNSUDP         int64  `json:"dns_udp" validate:"required"`
	DNSUDPDelta    int64  `json:"dns_udp_delta" validate:"required"`
	EnipTCP        int64  `json:"enip_tcp" validate:"required"`
	EnipTCPDelta   int64  `json:"enip_tcp_delta" validate:"required"`
	EnipUDP        int64  `json:"enip_udp" validate:"required"`
	EnipUDPDelta   int64  `json:"enip_udp_delta" validate:"required"`
	FTP            int64  `json:"ftp" validate:"required"`
	FTPData        int64  `json:"ftp-data" validate:"required"`
	FTPDataDelta   int64  `json:"ftp-data_delta" validate:"required"`
	FTPDelta       int64  `json:"ftp_delta" validate:"required"`
	HTTP           int64  `json:"http" validate:"required"`
	HTTPDelta      int64  `json:"http_delta" validate:"required"`
	Ikev2          int64  `json:"ikev2" validate:"required"`
	Ikev2Delta     int64  `json:"ikev2_delta" validate:"required"`
	IMAP           int64  `json:"imap" validate:"required"`
	IMAPDelta      int64  `json:"imap_delta" validate:"required"`
	Krb5TCP        int64  `json:"krb5_tcp" validate:"required"`
	Krb5TCPDelta   int64  `json:"krb5_tcp_delta" validate:"required"`
	Krb5UDP        int64  `json:"krb5_udp" validate:"required"`
	Krb5UDPDelta   int64  `json:"krb5_udp_delta" validate:"required"`
	Modbus         int64  `json:"modbus" validate:"required"`
	ModbusDelta    int64  `json:"modbus_delta" validate:"required"`
	MSN            *int64 `json:"msn,omitempty"`
	MSNDelta       *int64 `json:"msn_delta,omitempty"`
	NFSTCP         int64  `json:"nfs_tcp" validate:"required"`
	NFSTCPDelta    int64  `json:"nfs_tcp_delta" validate:"required"`
	NFSUDP         int64  `json:"nfs_udp" validate:"required"`
	NFSUDPDelta    int64  `json:"nfs_udp_delta" validate:"required"`
	NTP            int64  `json:"ntp" validate:"required"`
	NTPDelta       int64  `json:"ntp_delta" validate:"required"`
	RDP            int64  `json:"rdp" validate:"required"`
	RDPDelta       int64  `json:"rdp_delta" validate:"required"`
	SIP            int64  `json:"sip" validate:"required"`
	SIPDelta       int64  `json:"sip_delta" validate:"required"`
	SMB            int64  `json:"smb" validate:"required"`
	SMBDelta       int64  `json:"smb_delta" validate:"required"`
	SMTP           int64  `json:"smtp" validate:"required"`
	SMTPDelta      int64  `json:"smtp_delta" validate:"required"`
	SNMP           int64  `json:"snmp" validate:"required"`
	SNMPDelta      int64  `json:"snmp_delta" validate:"required"`
	SSH            int64  `json:"ssh" validate:"required"`
	SSHDelta       int64  `json:"ssh_delta" validate:"required"`
	TFTP           int64  `json:"tftp" validate:"required"`
	TFTPDelta      int64  `json:"tftp_delta" validate:"required"`
	TLS            int64  `json:"tls" validate:"required"`
	TLSDelta       int64  `json:"tls_delta" validate:"required"`
}

type StatsDecoder struct {
	AvgPktSize      int64       `json:"avg_pkt_size" validate:"required"`
	AvgPktSizeDelta int64       `json:"avg_pkt_size_delta" validate:"required"`
	Bytes           int64       `json:"bytes" validate:"required"`
	BytesDelta      int64       `json:"bytes_delta" validate:"required"`
	Dce             PurpleDce   `json:"dce" validate:"required"`
	Erspan          int64       `json:"erspan" validate:"required"`
	ErspanDelta     int64       `json:"erspan_delta" validate:"required"`
	Ethernet        int64       `json:"ethernet" validate:"required"`
	EthernetDelta   int64       `json:"ethernet_delta" validate:"required"`
	Event           PurpleEvent `json:"event" validate:"required"`
	Gre             int64       `json:"gre" validate:"required"`
	GreDelta        int64       `json:"gre_delta" validate:"required"`
	Icmpv4          int64       `json:"icmpv4" validate:"required"`
	Icmpv4Delta     int64       `json:"icmpv4_delta" validate:"required"`
	Icmpv6          int64       `json:"icmpv6" validate:"required"`
	Icmpv6Delta     int64       `json:"icmpv6_delta" validate:"required"`
	Ieee8021Ah      int64       `json:"ieee8021ah" validate:"required"`
	Ieee8021AhDelta int64       `json:"ieee8021ah_delta" validate:"required"`
	Invalid         int64       `json:"invalid" validate:"required"`
	InvalidDelta    int64       `json:"invalid_delta" validate:"required"`
	Ipv4            int64       `json:"ipv4" validate:"required"`
	Ipv4Delta       int64       `json:"ipv4_delta" validate:"required"`
	Ipv4InIpv6      int64       `json:"ipv4_in_ipv6" validate:"required"`
	Ipv4InIpv6Delta int64       `json:"ipv4_in_ipv6_delta" validate:"required"`
	Ipv6            int64       `json:"ipv6" validate:"required"`
	Ipv6Delta       int64       `json:"ipv6_delta" validate:"required"`
	Ipv6InIpv6      int64       `json:"ipv6_in_ipv6" validate:"required"`
	Ipv6InIpv6Delta int64       `json:"ipv6_in_ipv6_delta" validate:"required"`
	MaxPktSize      int64       `json:"max_pkt_size" validate:"required"`
	MaxPktSizeDelta int64       `json:"max_pkt_size_delta" validate:"required"`
	MPLS            int64       `json:"mpls" validate:"required"`
	MPLSDelta       int64       `json:"mpls_delta" validate:"required"`
	Null            int64       `json:"null" validate:"required"`
	NullDelta       int64       `json:"null_delta" validate:"required"`
	Pkts            int64       `json:"pkts" validate:"required"`
	PktsDelta       int64       `json:"pkts_delta" validate:"required"`
	PPP             int64       `json:"ppp" validate:"required"`
	PPPDelta        int64       `json:"ppp_delta" validate:"required"`
	Pppoe           int64       `json:"pppoe" validate:"required"`
	PppoeDelta      int64       `json:"pppoe_delta" validate:"required"`
	Raw             int64       `json:"raw" validate:"required"`
	RawDelta        int64       `json:"raw_delta" validate:"required"`
	SCTP            int64       `json:"sctp" validate:"required"`
	SCTPDelta       int64       `json:"sctp_delta" validate:"required"`
	Sll             int64       `json:"sll" validate:"required"`
	SllDelta        int64       `json:"sll_delta" validate:"required"`
	TCP             int64       `json:"tcp" validate:"required"`
	TCPDelta        int64       `json:"tcp_delta" validate:"required"`
	Teredo          int64       `json:"teredo" validate:"required"`
	TeredoDelta     int64       `json:"teredo_delta" validate:"required"`
	UDP             int64       `json:"udp" validate:"required"`
	UDPDelta        int64       `json:"udp_delta" validate:"required"`
	VLAN            int64       `json:"vlan" validate:"required"`
	VLANDelta       int64       `json:"vlan_delta" validate:"required"`
	VLANQinq        int64       `json:"vlan_qinq" validate:"required"`
	VLANQinqDelta   int64       `json:"vlan_qinq_delta" validate:"required"`
	Vxlan           int64       `json:"vxlan" validate:"required"`
	VxlanDelta      int64       `json:"vxlan_delta" validate:"required"`
}

type PurpleDce struct {
	PktTooSmall      int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta int64 `json:"pkt_too_small_delta" validate:"required"`
}

type PurpleEvent struct {
	Erspan     PurpleErspan     `json:"erspan" validate:"required"`
	Ethernet   PurpleEthernet   `json:"ethernet" validate:"required"`
	Gre        PurpleGre        `json:"gre" validate:"required"`
	Icmpv4     PurpleIcmpv4     `json:"icmpv4" validate:"required"`
	Icmpv6     PurpleIcmpv6     `json:"icmpv6" validate:"required"`
	Ieee8021Ah PurpleIeee8021Ah `json:"ieee8021ah" validate:"required"`
	Ipraw      PurpleIpraw      `json:"ipraw" validate:"required"`
	Ipv4       PurpleIpv4       `json:"ipv4" validate:"required"`
	Ipv6       PurpleIpv6       `json:"ipv6" validate:"required"`
	Ltnull     PurpleLtnull     `json:"ltnull" validate:"required"`
	MPLS       PurpleMPLS       `json:"mpls" validate:"required"`
	PPP        PurplePPP        `json:"ppp" validate:"required"`
	Pppoe      PurplePppoe      `json:"pppoe" validate:"required"`
	SCTP       PurpleSCTP       `json:"sctp" validate:"required"`
	Sll        PurpleSll        `json:"sll" validate:"required"`
	TCP        PurpleTCP        `json:"tcp" validate:"required"`
	UDP        PurpleUDP        `json:"udp" validate:"required"`
	VLAN       PurpleVLAN       `json:"vlan" validate:"required"`
}

type PurpleErspan struct {
	HeaderTooSmall          int64 `json:"header_too_small" validate:"required"`
	HeaderTooSmallDelta     int64 `json:"header_too_small_delta" validate:"required"`
	TooManyVLANLayers       int64 `json:"too_many_vlan_layers" validate:"required"`
	TooManyVLANLayersDelta  int64 `json:"too_many_vlan_layers_delta" validate:"required"`
	UnsupportedVersion      int64 `json:"unsupported_version" validate:"required"`
	UnsupportedVersionDelta int64 `json:"unsupported_version_delta" validate:"required"`
}

type PurpleEthernet struct {
	PktTooSmall      int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta int64 `json:"pkt_too_small_delta" validate:"required"`
}

type PurpleGre struct {
	PktTooSmall                  int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta             int64 `json:"pkt_too_small_delta" validate:"required"`
	Version0Flags                int64 `json:"version0_flags" validate:"required"`
	Version0FlagsDelta           int64 `json:"version0_flags_delta" validate:"required"`
	Version0HdrTooBig            int64 `json:"version0_hdr_too_big" validate:"required"`
	Version0HdrTooBigDelta       int64 `json:"version0_hdr_too_big_delta" validate:"required"`
	Version0MalformedSreHdr      int64 `json:"version0_malformed_sre_hdr" validate:"required"`
	Version0MalformedSreHdrDelta int64 `json:"version0_malformed_sre_hdr_delta" validate:"required"`
	Version0Recur                int64 `json:"version0_recur" validate:"required"`
	Version0RecurDelta           int64 `json:"version0_recur_delta" validate:"required"`
	Version1Chksum               int64 `json:"version1_chksum" validate:"required"`
	Version1ChksumDelta          int64 `json:"version1_chksum_delta" validate:"required"`
	Version1Flags                int64 `json:"version1_flags" validate:"required"`
	Version1FlagsDelta           int64 `json:"version1_flags_delta" validate:"required"`
	Version1HdrTooBig            int64 `json:"version1_hdr_too_big" validate:"required"`
	Version1HdrTooBigDelta       int64 `json:"version1_hdr_too_big_delta" validate:"required"`
	Version1MalformedSreHdr      int64 `json:"version1_malformed_sre_hdr" validate:"required"`
	Version1MalformedSreHdrDelta int64 `json:"version1_malformed_sre_hdr_delta" validate:"required"`
	Version1NoKey                int64 `json:"version1_no_key" validate:"required"`
	Version1NoKeyDelta           int64 `json:"version1_no_key_delta" validate:"required"`
	Version1Recur                int64 `json:"version1_recur" validate:"required"`
	Version1RecurDelta           int64 `json:"version1_recur_delta" validate:"required"`
	Version1Route                int64 `json:"version1_route" validate:"required"`
	Version1RouteDelta           int64 `json:"version1_route_delta" validate:"required"`
	Version1Ssr                  int64 `json:"version1_ssr" validate:"required"`
	Version1SsrDelta             int64 `json:"version1_ssr_delta" validate:"required"`
	Version1WrongProtocol        int64 `json:"version1_wrong_protocol" validate:"required"`
	Version1WrongProtocolDelta   int64 `json:"version1_wrong_protocol_delta" validate:"required"`
	WrongVersion                 int64 `json:"wrong_version" validate:"required"`
	WrongVersionDelta            int64 `json:"wrong_version_delta" validate:"required"`
}

type PurpleIcmpv4 struct {
	Ipv4TruncPkt        int64 `json:"ipv4_trunc_pkt" validate:"required"`
	Ipv4TruncPktDelta   int64 `json:"ipv4_trunc_pkt_delta" validate:"required"`
	Ipv4UnknownVer      int64 `json:"ipv4_unknown_ver" validate:"required"`
	Ipv4UnknownVerDelta int64 `json:"ipv4_unknown_ver_delta" validate:"required"`
	PktTooSmall         int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta    int64 `json:"pkt_too_small_delta" validate:"required"`
	UnknownCode         int64 `json:"unknown_code" validate:"required"`
	UnknownCodeDelta    int64 `json:"unknown_code_delta" validate:"required"`
	UnknownType         int64 `json:"unknown_type" validate:"required"`
	UnknownTypeDelta    int64 `json:"unknown_type_delta" validate:"required"`
}

type PurpleIcmpv6 struct {
	ExperimentationType          int64 `json:"experimentation_type" validate:"required"`
	ExperimentationTypeDelta     int64 `json:"experimentation_type_delta" validate:"required"`
	Ipv6TruncPkt                 int64 `json:"ipv6_trunc_pkt" validate:"required"`
	Ipv6TruncPktDelta            int64 `json:"ipv6_trunc_pkt_delta" validate:"required"`
	Ipv6UnknownVersion           int64 `json:"ipv6_unknown_version" validate:"required"`
	Ipv6UnknownVersionDelta      int64 `json:"ipv6_unknown_version_delta" validate:"required"`
	MldMessageWithInvalidHl      int64 `json:"mld_message_with_invalid_hl" validate:"required"`
	MldMessageWithInvalidHlDelta int64 `json:"mld_message_with_invalid_hl_delta" validate:"required"`
	PktTooSmall                  int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta             int64 `json:"pkt_too_small_delta" validate:"required"`
	UnassignedType               int64 `json:"unassigned_type" validate:"required"`
	UnassignedTypeDelta          int64 `json:"unassigned_type_delta" validate:"required"`
	UnknownCode                  int64 `json:"unknown_code" validate:"required"`
	UnknownCodeDelta             int64 `json:"unknown_code_delta" validate:"required"`
	UnknownType                  int64 `json:"unknown_type" validate:"required"`
	UnknownTypeDelta             int64 `json:"unknown_type_delta" validate:"required"`
}

type PurpleIeee8021Ah struct {
	HeaderTooSmall      int64 `json:"header_too_small" validate:"required"`
	HeaderTooSmallDelta int64 `json:"header_too_small_delta" validate:"required"`
}

type PurpleIpraw struct {
	InvalidIPVersion      int64 `json:"invalid_ip_version" validate:"required"`
	InvalidIPVersionDelta int64 `json:"invalid_ip_version_delta" validate:"required"`
}

type PurpleIpv4 struct {
	FragIgnored               int64 `json:"frag_ignored" validate:"required"`
	FragIgnoredDelta          int64 `json:"frag_ignored_delta" validate:"required"`
	FragOverlap               int64 `json:"frag_overlap" validate:"required"`
	FragOverlapDelta          int64 `json:"frag_overlap_delta" validate:"required"`
	FragPktTooLarge           int64 `json:"frag_pkt_too_large" validate:"required"`
	FragPktTooLargeDelta      int64 `json:"frag_pkt_too_large_delta" validate:"required"`
	HlenTooSmall              int64 `json:"hlen_too_small" validate:"required"`
	HlenTooSmallDelta         int64 `json:"hlen_too_small_delta" validate:"required"`
	Icmpv6                    int64 `json:"icmpv6" validate:"required"`
	Icmpv6Delta               int64 `json:"icmpv6_delta" validate:"required"`
	IplenSmallerThanHlen      int64 `json:"iplen_smaller_than_hlen" validate:"required"`
	IplenSmallerThanHlenDelta int64 `json:"iplen_smaller_than_hlen_delta" validate:"required"`
	OptDuplicate              int64 `json:"opt_duplicate" validate:"required"`
	OptDuplicateDelta         int64 `json:"opt_duplicate_delta" validate:"required"`
	OptEOLRequired            int64 `json:"opt_eol_required" validate:"required"`
	OptEOLRequiredDelta       int64 `json:"opt_eol_required_delta" validate:"required"`
	OptInvalid                int64 `json:"opt_invalid" validate:"required"`
	OptInvalidDelta           int64 `json:"opt_invalid_delta" validate:"required"`
	OptInvalidLen             int64 `json:"opt_invalid_len" validate:"required"`
	OptInvalidLenDelta        int64 `json:"opt_invalid_len_delta" validate:"required"`
	OptMalformed              int64 `json:"opt_malformed" validate:"required"`
	OptMalformedDelta         int64 `json:"opt_malformed_delta" validate:"required"`
	OptPadRequired            int64 `json:"opt_pad_required" validate:"required"`
	OptPadRequiredDelta       int64 `json:"opt_pad_required_delta" validate:"required"`
	OptUnknown                int64 `json:"opt_unknown" validate:"required"`
	OptUnknownDelta           int64 `json:"opt_unknown_delta" validate:"required"`
	PktTooSmall               int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta          int64 `json:"pkt_too_small_delta" validate:"required"`
	TruncPkt                  int64 `json:"trunc_pkt" validate:"required"`
	TruncPktDelta             int64 `json:"trunc_pkt_delta" validate:"required"`
	WrongIPVersion            int64 `json:"wrong_ip_version" validate:"required"`
	WrongIPVersionDelta       int64 `json:"wrong_ip_version_delta" validate:"required"`
}

type PurpleIpv6 struct {
	DataAfterNoneHeader         int64 `json:"data_after_none_header" validate:"required"`
	DataAfterNoneHeaderDelta    int64 `json:"data_after_none_header_delta" validate:"required"`
	DstoptsOnlyPadding          int64 `json:"dstopts_only_padding" validate:"required"`
	DstoptsOnlyPaddingDelta     int64 `json:"dstopts_only_padding_delta" validate:"required"`
	DstoptsUnknownOpt           int64 `json:"dstopts_unknown_opt" validate:"required"`
	DstoptsUnknownOptDelta      int64 `json:"dstopts_unknown_opt_delta" validate:"required"`
	ExthdrAhResNotNull          int64 `json:"exthdr_ah_res_not_null" validate:"required"`
	ExthdrAhResNotNullDelta     int64 `json:"exthdr_ah_res_not_null_delta" validate:"required"`
	ExthdrDuplAh                int64 `json:"exthdr_dupl_ah" validate:"required"`
	ExthdrDuplAhDelta           int64 `json:"exthdr_dupl_ah_delta" validate:"required"`
	ExthdrDuplDh                int64 `json:"exthdr_dupl_dh" validate:"required"`
	ExthdrDuplDhDelta           int64 `json:"exthdr_dupl_dh_delta" validate:"required"`
	ExthdrDuplEh                int64 `json:"exthdr_dupl_eh" validate:"required"`
	ExthdrDuplEhDelta           int64 `json:"exthdr_dupl_eh_delta" validate:"required"`
	ExthdrDuplFh                int64 `json:"exthdr_dupl_fh" validate:"required"`
	ExthdrDuplFhDelta           int64 `json:"exthdr_dupl_fh_delta" validate:"required"`
	ExthdrDuplHh                int64 `json:"exthdr_dupl_hh" validate:"required"`
	ExthdrDuplHhDelta           int64 `json:"exthdr_dupl_hh_delta" validate:"required"`
	ExthdrDuplRh                int64 `json:"exthdr_dupl_rh" validate:"required"`
	ExthdrDuplRhDelta           int64 `json:"exthdr_dupl_rh_delta" validate:"required"`
	ExthdrInvalidOptlen         int64 `json:"exthdr_invalid_optlen" validate:"required"`
	ExthdrInvalidOptlenDelta    int64 `json:"exthdr_invalid_optlen_delta" validate:"required"`
	ExthdrUselessFh             int64 `json:"exthdr_useless_fh" validate:"required"`
	ExthdrUselessFhDelta        int64 `json:"exthdr_useless_fh_delta" validate:"required"`
	FhNonZeroReservedField      int64 `json:"fh_non_zero_reserved_field" validate:"required"`
	FhNonZeroReservedFieldDelta int64 `json:"fh_non_zero_reserved_field_delta" validate:"required"`
	FragIgnored                 int64 `json:"frag_ignored" validate:"required"`
	FragIgnoredDelta            int64 `json:"frag_ignored_delta" validate:"required"`
	FragOverlap                 int64 `json:"frag_overlap" validate:"required"`
	FragOverlapDelta            int64 `json:"frag_overlap_delta" validate:"required"`
	FragPktTooLarge             int64 `json:"frag_pkt_too_large" validate:"required"`
	FragPktTooLargeDelta        int64 `json:"frag_pkt_too_large_delta" validate:"required"`
	HopoptsOnlyPadding          int64 `json:"hopopts_only_padding" validate:"required"`
	HopoptsOnlyPaddingDelta     int64 `json:"hopopts_only_padding_delta" validate:"required"`
	HopoptsUnknownOpt           int64 `json:"hopopts_unknown_opt" validate:"required"`
	HopoptsUnknownOptDelta      int64 `json:"hopopts_unknown_opt_delta" validate:"required"`
	Icmpv4                      int64 `json:"icmpv4" validate:"required"`
	Icmpv4Delta                 int64 `json:"icmpv4_delta" validate:"required"`
	Ipv4InIpv6TooSmall          int64 `json:"ipv4_in_ipv6_too_small" validate:"required"`
	Ipv4InIpv6TooSmallDelta     int64 `json:"ipv4_in_ipv6_too_small_delta" validate:"required"`
	Ipv4InIpv6WrongVersion      int64 `json:"ipv4_in_ipv6_wrong_version" validate:"required"`
	Ipv4InIpv6WrongVersionDelta int64 `json:"ipv4_in_ipv6_wrong_version_delta" validate:"required"`
	Ipv6InIpv6TooSmall          int64 `json:"ipv6_in_ipv6_too_small" validate:"required"`
	Ipv6InIpv6TooSmallDelta     int64 `json:"ipv6_in_ipv6_too_small_delta" validate:"required"`
	Ipv6InIpv6WrongVersion      int64 `json:"ipv6_in_ipv6_wrong_version" validate:"required"`
	Ipv6InIpv6WrongVersionDelta int64 `json:"ipv6_in_ipv6_wrong_version_delta" validate:"required"`
	PktTooSmall                 int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta            int64 `json:"pkt_too_small_delta" validate:"required"`
	RhType0                     int64 `json:"rh_type_0" validate:"required"`
	RhType0_Delta               int64 `json:"rh_type_0_delta" validate:"required"`
	TruncExthdr                 int64 `json:"trunc_exthdr" validate:"required"`
	TruncExthdrDelta            int64 `json:"trunc_exthdr_delta" validate:"required"`
	TruncPkt                    int64 `json:"trunc_pkt" validate:"required"`
	TruncPktDelta               int64 `json:"trunc_pkt_delta" validate:"required"`
	UnknownNextHeader           int64 `json:"unknown_next_header" validate:"required"`
	UnknownNextHeaderDelta      int64 `json:"unknown_next_header_delta" validate:"required"`
	WrongIPVersion              int64 `json:"wrong_ip_version" validate:"required"`
	WrongIPVersionDelta         int64 `json:"wrong_ip_version_delta" validate:"required"`
	ZeroLenPadn                 int64 `json:"zero_len_padn" validate:"required"`
	ZeroLenPadnDelta            int64 `json:"zero_len_padn_delta" validate:"required"`
}

type PurpleLtnull struct {
	PktTooSmall          int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta     int64 `json:"pkt_too_small_delta" validate:"required"`
	UnsupportedType      int64 `json:"unsupported_type" validate:"required"`
	UnsupportedTypeDelta int64 `json:"unsupported_type_delta" validate:"required"`
}

type PurpleMPLS struct {
	BadLabelImplicitNull      int64 `json:"bad_label_implicit_null" validate:"required"`
	BadLabelImplicitNullDelta int64 `json:"bad_label_implicit_null_delta" validate:"required"`
	BadLabelReserved          int64 `json:"bad_label_reserved" validate:"required"`
	BadLabelReservedDelta     int64 `json:"bad_label_reserved_delta" validate:"required"`
	BadLabelRouterAlert       int64 `json:"bad_label_router_alert" validate:"required"`
	BadLabelRouterAlertDelta  int64 `json:"bad_label_router_alert_delta" validate:"required"`
	HeaderTooSmall            int64 `json:"header_too_small" validate:"required"`
	HeaderTooSmallDelta       int64 `json:"header_too_small_delta" validate:"required"`
	PktTooSmall               int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta          int64 `json:"pkt_too_small_delta" validate:"required"`
	UnknownPayloadType        int64 `json:"unknown_payload_type" validate:"required"`
	UnknownPayloadTypeDelta   int64 `json:"unknown_payload_type_delta" validate:"required"`
}

type PurplePPP struct {
	Ip4PktTooSmall      int64 `json:"ip4_pkt_too_small" validate:"required"`
	Ip4PktTooSmallDelta int64 `json:"ip4_pkt_too_small_delta" validate:"required"`
	Ip6PktTooSmall      int64 `json:"ip6_pkt_too_small" validate:"required"`
	Ip6PktTooSmallDelta int64 `json:"ip6_pkt_too_small_delta" validate:"required"`
	PktTooSmall         int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta    int64 `json:"pkt_too_small_delta" validate:"required"`
	UnsupProto          int64 `json:"unsup_proto" validate:"required"`
	UnsupProtoDelta     int64 `json:"unsup_proto_delta" validate:"required"`
	VjuPktTooSmall      int64 `json:"vju_pkt_too_small" validate:"required"`
	VjuPktTooSmallDelta int64 `json:"vju_pkt_too_small_delta" validate:"required"`
	WrongType           int64 `json:"wrong_type" validate:"required"`
	WrongTypeDelta      int64 `json:"wrong_type_delta" validate:"required"`
}

type PurplePppoe struct {
	MalformedTags      int64 `json:"malformed_tags" validate:"required"`
	MalformedTagsDelta int64 `json:"malformed_tags_delta" validate:"required"`
	PktTooSmall        int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta   int64 `json:"pkt_too_small_delta" validate:"required"`
	WrongCode          int64 `json:"wrong_code" validate:"required"`
	WrongCodeDelta     int64 `json:"wrong_code_delta" validate:"required"`
}

type PurpleSCTP struct {
	PktTooSmall      int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta int64 `json:"pkt_too_small_delta" validate:"required"`
}

type PurpleSll struct {
	PktTooSmall      int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta int64 `json:"pkt_too_small_delta" validate:"required"`
}

type PurpleTCP struct {
	HlenTooSmall       int64 `json:"hlen_too_small" validate:"required"`
	HlenTooSmallDelta  int64 `json:"hlen_too_small_delta" validate:"required"`
	InvalidOptlen      int64 `json:"invalid_optlen" validate:"required"`
	InvalidOptlenDelta int64 `json:"invalid_optlen_delta" validate:"required"`
	OptDuplicate       int64 `json:"opt_duplicate" validate:"required"`
	OptDuplicateDelta  int64 `json:"opt_duplicate_delta" validate:"required"`
	OptInvalidLen      int64 `json:"opt_invalid_len" validate:"required"`
	OptInvalidLenDelta int64 `json:"opt_invalid_len_delta" validate:"required"`
	PktTooSmall        int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta   int64 `json:"pkt_too_small_delta" validate:"required"`
}

type PurpleUDP struct {
	HlenInvalid       int64 `json:"hlen_invalid" validate:"required"`
	HlenInvalidDelta  int64 `json:"hlen_invalid_delta" validate:"required"`
	HlenTooSmall      int64 `json:"hlen_too_small" validate:"required"`
	HlenTooSmallDelta int64 `json:"hlen_too_small_delta" validate:"required"`
	PktTooSmall       int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta  int64 `json:"pkt_too_small_delta" validate:"required"`
}

type PurpleVLAN struct {
	HeaderTooSmall      int64 `json:"header_too_small" validate:"required"`
	HeaderTooSmallDelta int64 `json:"header_too_small_delta" validate:"required"`
	TooManyLayers       int64 `json:"too_many_layers" validate:"required"`
	TooManyLayersDelta  int64 `json:"too_many_layers_delta" validate:"required"`
	UnknownType         int64 `json:"unknown_type" validate:"required"`
	UnknownTypeDelta    int64 `json:"unknown_type_delta" validate:"required"`
}

type StatsDefrag struct {
	Ipv4             FluffyIpv4 `json:"ipv4" validate:"required"`
	Ipv6             FluffyIpv6 `json:"ipv6" validate:"required"`
	MaxFragHits      int64      `json:"max_frag_hits" validate:"required"`
	MaxFragHitsDelta int64      `json:"max_frag_hits_delta" validate:"required"`
}

type FluffyIpv4 struct {
	Fragments        int64 `json:"fragments" validate:"required"`
	FragmentsDelta   int64 `json:"fragments_delta" validate:"required"`
	Reassembled      int64 `json:"reassembled" validate:"required"`
	ReassembledDelta int64 `json:"reassembled_delta" validate:"required"`
	Timeouts         int64 `json:"timeouts" validate:"required"`
	TimeoutsDelta    int64 `json:"timeouts_delta" validate:"required"`
}

type FluffyIpv6 struct {
	Fragments        int64 `json:"fragments" validate:"required"`
	FragmentsDelta   int64 `json:"fragments_delta" validate:"required"`
	Reassembled      int64 `json:"reassembled" validate:"required"`
	ReassembledDelta int64 `json:"reassembled_delta" validate:"required"`
	Timeouts         int64 `json:"timeouts" validate:"required"`
	TimeoutsDelta    int64 `json:"timeouts_delta" validate:"required"`
}

type StatsDetect struct {
	Alert      int64          `json:"alert" validate:"required"`
	AlertDelta int64          `json:"alert_delta" validate:"required"`
	Engines    []PurpleEngine `json:"engines" validate:"required"`
}

type PurpleEngine struct {
	ID          int64  `json:"id" validate:"required"`
	LastReload  string `json:"last_reload" validate:"required"`
	RulesFailed int64  `json:"rules_failed" validate:"required"`
	RulesLoaded int64  `json:"rules_loaded" validate:"required"`
}

type StatsFTP struct {
	Memcap      int64 `json:"memcap" validate:"required"`
	MemcapDelta int64 `json:"memcap_delta" validate:"required"`
	Memuse      int64 `json:"memuse" validate:"required"`
	MemuseDelta int64 `json:"memuse_delta" validate:"required"`
}

type StatsFileStore struct {
	FSErrors             int64 `json:"fs_errors" validate:"required"`
	FSErrorsDelta        int64 `json:"fs_errors_delta" validate:"required"`
	OpenFiles            int64 `json:"open_files" validate:"required"`
	OpenFilesDelta       int64 `json:"open_files_delta" validate:"required"`
	OpenFilesMaxHit      int64 `json:"open_files_max_hit" validate:"required"`
	OpenFilesMaxHitDelta int64 `json:"open_files_max_hit_delta" validate:"required"`
}

type StatsFlow struct {
	EmergModeEntered      int64 `json:"emerg_mode_entered" validate:"required"`
	EmergModeEnteredDelta int64 `json:"emerg_mode_entered_delta" validate:"required"`
	EmergModeOver         int64 `json:"emerg_mode_over" validate:"required"`
	EmergModeOverDelta    int64 `json:"emerg_mode_over_delta" validate:"required"`
	Icmpv4                int64 `json:"icmpv4" validate:"required"`
	Icmpv4Delta           int64 `json:"icmpv4_delta" validate:"required"`
	Icmpv6                int64 `json:"icmpv6" validate:"required"`
	Icmpv6Delta           int64 `json:"icmpv6_delta" validate:"required"`
	Memcap                int64 `json:"memcap" validate:"required"`
	MemcapDelta           int64 `json:"memcap_delta" validate:"required"`
	Memuse                int64 `json:"memuse" validate:"required"`
	MemuseDelta           int64 `json:"memuse_delta" validate:"required"`
	Spare                 int64 `json:"spare" validate:"required"`
	SpareDelta            int64 `json:"spare_delta" validate:"required"`
	TCP                   int64 `json:"tcp" validate:"required"`
	TCPDelta              int64 `json:"tcp_delta" validate:"required"`
	TCPReuse              int64 `json:"tcp_reuse" validate:"required"`
	TCPReuseDelta         int64 `json:"tcp_reuse_delta" validate:"required"`
	UDP                   int64 `json:"udp" validate:"required"`
	UDPDelta              int64 `json:"udp_delta" validate:"required"`
}

type StatsFlowBypassed struct {
	Bytes                  int64 `json:"bytes" validate:"required"`
	BytesDelta             int64 `json:"bytes_delta" validate:"required"`
	Closed                 int64 `json:"closed" validate:"required"`
	ClosedDelta            int64 `json:"closed_delta" validate:"required"`
	LocalBytes             int64 `json:"local_bytes" validate:"required"`
	LocalBytesDelta        int64 `json:"local_bytes_delta" validate:"required"`
	LocalCaptureBytes      int64 `json:"local_capture_bytes" validate:"required"`
	LocalCaptureBytesDelta int64 `json:"local_capture_bytes_delta" validate:"required"`
	LocalCapturePkts       int64 `json:"local_capture_pkts" validate:"required"`
	LocalCapturePktsDelta  int64 `json:"local_capture_pkts_delta" validate:"required"`
	LocalPkts              int64 `json:"local_pkts" validate:"required"`
	LocalPktsDelta         int64 `json:"local_pkts_delta" validate:"required"`
	Pkts                   int64 `json:"pkts" validate:"required"`
	PktsDelta              int64 `json:"pkts_delta" validate:"required"`
}

type StatsFlowMgr struct {
	BypassedPruned         int64 `json:"bypassed_pruned" validate:"required"`
	BypassedPrunedDelta    int64 `json:"bypassed_pruned_delta" validate:"required"`
	ClosedPruned           int64 `json:"closed_pruned" validate:"required"`
	ClosedPrunedDelta      int64 `json:"closed_pruned_delta" validate:"required"`
	EstPruned              int64 `json:"est_pruned" validate:"required"`
	EstPrunedDelta         int64 `json:"est_pruned_delta" validate:"required"`
	FlowsChecked           int64 `json:"flows_checked" validate:"required"`
	FlowsCheckedDelta      int64 `json:"flows_checked_delta" validate:"required"`
	FlowsNotimeout         int64 `json:"flows_notimeout" validate:"required"`
	FlowsNotimeoutDelta    int64 `json:"flows_notimeout_delta" validate:"required"`
	FlowsRemoved           int64 `json:"flows_removed" validate:"required"`
	FlowsRemovedDelta      int64 `json:"flows_removed_delta" validate:"required"`
	FlowsTimeout           int64 `json:"flows_timeout" validate:"required"`
	FlowsTimeoutDelta      int64 `json:"flows_timeout_delta" validate:"required"`
	FlowsTimeoutInuse      int64 `json:"flows_timeout_inuse" validate:"required"`
	FlowsTimeoutInuseDelta int64 `json:"flows_timeout_inuse_delta" validate:"required"`
	NewPruned              int64 `json:"new_pruned" validate:"required"`
	NewPrunedDelta         int64 `json:"new_pruned_delta" validate:"required"`
	RowsBusy               int64 `json:"rows_busy" validate:"required"`
	RowsBusyDelta          int64 `json:"rows_busy_delta" validate:"required"`
	RowsChecked            int64 `json:"rows_checked" validate:"required"`
	RowsCheckedDelta       int64 `json:"rows_checked_delta" validate:"required"`
	RowsEmpty              int64 `json:"rows_empty" validate:"required"`
	RowsEmptyDelta         int64 `json:"rows_empty_delta" validate:"required"`
	RowsMaxlen             int64 `json:"rows_maxlen" validate:"required"`
	RowsMaxlenDelta        int64 `json:"rows_maxlen_delta" validate:"required"`
	RowsSkipped            int64 `json:"rows_skipped" validate:"required"`
	RowsSkippedDelta       int64 `json:"rows_skipped_delta" validate:"required"`
}

type StatsHTTP struct {
	Memcap      int64 `json:"memcap" validate:"required"`
	MemcapDelta int64 `json:"memcap_delta" validate:"required"`
	Memuse      int64 `json:"memuse" validate:"required"`
	MemuseDelta int64 `json:"memuse_delta" validate:"required"`
}

type StatsStream struct {
	The3WhsACKDataInject                  int64 `json:"3whs_ack_data_inject" validate:"required"`
	The3WhsACKDataInjectDelta             int64 `json:"3whs_ack_data_inject_delta" validate:"required"`
	The3WhsACKInWrongDir                  int64 `json:"3whs_ack_in_wrong_dir" validate:"required"`
	The3WhsACKInWrongDirDelta             int64 `json:"3whs_ack_in_wrong_dir_delta" validate:"required"`
	The3WhsAsyncWrongSeq                  int64 `json:"3whs_async_wrong_seq" validate:"required"`
	The3WhsAsyncWrongSeqDelta             int64 `json:"3whs_async_wrong_seq_delta" validate:"required"`
	The3WhsRightSeqWrongACKEvasion        int64 `json:"3whs_right_seq_wrong_ack_evasion" validate:"required"`
	The3WhsRightSeqWrongACKEvasionDelta   int64 `json:"3whs_right_seq_wrong_ack_evasion_delta" validate:"required"`
	The3WhsSynResendDiffSeqOnSynRecv      int64 `json:"3whs_syn_resend_diff_seq_on_syn_recv" validate:"required"`
	The3WhsSynResendDiffSeqOnSynRecvDelta int64 `json:"3whs_syn_resend_diff_seq_on_syn_recv_delta" validate:"required"`
	The3WhsSynToclientOnSynRecv           int64 `json:"3whs_syn_toclient_on_syn_recv" validate:"required"`
	The3WhsSynToclientOnSynRecvDelta      int64 `json:"3whs_syn_toclient_on_syn_recv_delta" validate:"required"`
	The3WhsSynackFlood                    int64 `json:"3whs_synack_flood" validate:"required"`
	The3WhsSynackFloodDelta               int64 `json:"3whs_synack_flood_delta" validate:"required"`
	The3WhsSynackInWrongDirection         int64 `json:"3whs_synack_in_wrong_direction" validate:"required"`
	The3WhsSynackInWrongDirectionDelta    int64 `json:"3whs_synack_in_wrong_direction_delta" validate:"required"`
	The3WhsSynackResendWithDiffACK        int64 `json:"3whs_synack_resend_with_diff_ack" validate:"required"`
	The3WhsSynackResendWithDiffACKDelta   int64 `json:"3whs_synack_resend_with_diff_ack_delta" validate:"required"`
	The3WhsSynackResendWithDiffSeq        int64 `json:"3whs_synack_resend_with_diff_seq" validate:"required"`
	The3WhsSynackResendWithDiffSeqDelta   int64 `json:"3whs_synack_resend_with_diff_seq_delta" validate:"required"`
	The3WhsSynackToserverOnSynRecv        int64 `json:"3whs_synack_toserver_on_syn_recv" validate:"required"`
	The3WhsSynackToserverOnSynRecvDelta   int64 `json:"3whs_synack_toserver_on_syn_recv_delta" validate:"required"`
	The3WhsSynackWithWrongACK             int64 `json:"3whs_synack_with_wrong_ack" validate:"required"`
	The3WhsSynackWithWrongACKDelta        int64 `json:"3whs_synack_with_wrong_ack_delta" validate:"required"`
	The3WhsWrongSeqWrongACK               int64 `json:"3whs_wrong_seq_wrong_ack" validate:"required"`
	The3WhsWrongSeqWrongACKDelta          int64 `json:"3whs_wrong_seq_wrong_ack_delta" validate:"required"`
	The4WhsInvalidACK                     int64 `json:"4whs_invalid_ack" validate:"required"`
	The4WhsInvalidACKDelta                int64 `json:"4whs_invalid_ack_delta" validate:"required"`
	The4WhsSynackWithWrongACK             int64 `json:"4whs_synack_with_wrong_ack" validate:"required"`
	The4WhsSynackWithWrongACKDelta        int64 `json:"4whs_synack_with_wrong_ack_delta" validate:"required"`
	The4WhsSynackWithWrongSyn             int64 `json:"4whs_synack_with_wrong_syn" validate:"required"`
	The4WhsSynackWithWrongSynDelta        int64 `json:"4whs_synack_with_wrong_syn_delta" validate:"required"`
	The4WhsWrongSeq                       int64 `json:"4whs_wrong_seq" validate:"required"`
	The4WhsWrongSeqDelta                  int64 `json:"4whs_wrong_seq_delta" validate:"required"`
	ClosewaitACKOutOfWindow               int64 `json:"closewait_ack_out_of_window" validate:"required"`
	ClosewaitACKOutOfWindowDelta          int64 `json:"closewait_ack_out_of_window_delta" validate:"required"`
	ClosewaitFinOutOfWindow               int64 `json:"closewait_fin_out_of_window" validate:"required"`
	ClosewaitFinOutOfWindowDelta          int64 `json:"closewait_fin_out_of_window_delta" validate:"required"`
	ClosewaitInvalidACK                   int64 `json:"closewait_invalid_ack" validate:"required"`
	ClosewaitInvalidACKDelta              int64 `json:"closewait_invalid_ack_delta" validate:"required"`
	ClosewaitPktBeforeLastACK             int64 `json:"closewait_pkt_before_last_ack" validate:"required"`
	ClosewaitPktBeforeLastACKDelta        int64 `json:"closewait_pkt_before_last_ack_delta" validate:"required"`
	ClosingACKWrongSeq                    int64 `json:"closing_ack_wrong_seq" validate:"required"`
	ClosingACKWrongSeqDelta               int64 `json:"closing_ack_wrong_seq_delta" validate:"required"`
	ClosingInvalidACK                     int64 `json:"closing_invalid_ack" validate:"required"`
	ClosingInvalidACKDelta                int64 `json:"closing_invalid_ack_delta" validate:"required"`
	EstInvalidACK                         int64 `json:"est_invalid_ack" validate:"required"`
	EstInvalidACKDelta                    int64 `json:"est_invalid_ack_delta" validate:"required"`
	EstPacketOutOfWindow                  int64 `json:"est_packet_out_of_window" validate:"required"`
	EstPacketOutOfWindowDelta             int64 `json:"est_packet_out_of_window_delta" validate:"required"`
	EstPktBeforeLastACK                   int64 `json:"est_pkt_before_last_ack" validate:"required"`
	EstPktBeforeLastACKDelta              int64 `json:"est_pkt_before_last_ack_delta" validate:"required"`
	EstSynResend                          int64 `json:"est_syn_resend" validate:"required"`
	EstSynResendDelta                     int64 `json:"est_syn_resend_delta" validate:"required"`
	EstSynResendDiffSeq                   int64 `json:"est_syn_resend_diff_seq" validate:"required"`
	EstSynResendDiffSeqDelta              int64 `json:"est_syn_resend_diff_seq_delta" validate:"required"`
	EstSynToclient                        int64 `json:"est_syn_toclient" validate:"required"`
	EstSynToclientDelta                   int64 `json:"est_syn_toclient_delta" validate:"required"`
	EstSynackResend                       int64 `json:"est_synack_resend" validate:"required"`
	EstSynackResendDelta                  int64 `json:"est_synack_resend_delta" validate:"required"`
	EstSynackResendWithDiffACK            int64 `json:"est_synack_resend_with_diff_ack" validate:"required"`
	EstSynackResendWithDiffACKDelta       int64 `json:"est_synack_resend_with_diff_ack_delta" validate:"required"`
	EstSynackResendWithDiffSeq            int64 `json:"est_synack_resend_with_diff_seq" validate:"required"`
	EstSynackResendWithDiffSeqDelta       int64 `json:"est_synack_resend_with_diff_seq_delta" validate:"required"`
	EstSynackToserver                     int64 `json:"est_synack_toserver" validate:"required"`
	EstSynackToserverDelta                int64 `json:"est_synack_toserver_delta" validate:"required"`
	Fin1ACKWrongSeq                       int64 `json:"fin1_ack_wrong_seq" validate:"required"`
	Fin1ACKWrongSeqDelta                  int64 `json:"fin1_ack_wrong_seq_delta" validate:"required"`
	Fin1FinWrongSeq                       int64 `json:"fin1_fin_wrong_seq" validate:"required"`
	Fin1FinWrongSeqDelta                  int64 `json:"fin1_fin_wrong_seq_delta" validate:"required"`
	Fin1InvalidACK                        int64 `json:"fin1_invalid_ack" validate:"required"`
	Fin1InvalidACKDelta                   int64 `json:"fin1_invalid_ack_delta" validate:"required"`
	Fin2ACKWrongSeq                       int64 `json:"fin2_ack_wrong_seq" validate:"required"`
	Fin2ACKWrongSeqDelta                  int64 `json:"fin2_ack_wrong_seq_delta" validate:"required"`
	Fin2FinWrongSeq                       int64 `json:"fin2_fin_wrong_seq" validate:"required"`
	Fin2FinWrongSeqDelta                  int64 `json:"fin2_fin_wrong_seq_delta" validate:"required"`
	Fin2InvalidACK                        int64 `json:"fin2_invalid_ack" validate:"required"`
	Fin2InvalidACKDelta                   int64 `json:"fin2_invalid_ack_delta" validate:"required"`
	FinButNoSession                       int64 `json:"fin_but_no_session" validate:"required"`
	FinButNoSessionDelta                  int64 `json:"fin_but_no_session_delta" validate:"required"`
	FinInvalidACK                         int64 `json:"fin_invalid_ack" validate:"required"`
	FinInvalidACKDelta                    int64 `json:"fin_invalid_ack_delta" validate:"required"`
	FinOutOfWindow                        int64 `json:"fin_out_of_window" validate:"required"`
	FinOutOfWindowDelta                   int64 `json:"fin_out_of_window_delta" validate:"required"`
	LastackACKWrongSeq                    int64 `json:"lastack_ack_wrong_seq" validate:"required"`
	LastackACKWrongSeqDelta               int64 `json:"lastack_ack_wrong_seq_delta" validate:"required"`
	LastackInvalidACK                     int64 `json:"lastack_invalid_ack" validate:"required"`
	LastackInvalidACKDelta                int64 `json:"lastack_invalid_ack_delta" validate:"required"`
	PktBadWindowUpdate                    int64 `json:"pkt_bad_window_update" validate:"required"`
	PktBadWindowUpdateDelta               int64 `json:"pkt_bad_window_update_delta" validate:"required"`
	PktBrokenACK                          int64 `json:"pkt_broken_ack" validate:"required"`
	PktBrokenACKDelta                     int64 `json:"pkt_broken_ack_delta" validate:"required"`
	PktInvalidACK                         int64 `json:"pkt_invalid_ack" validate:"required"`
	PktInvalidACKDelta                    int64 `json:"pkt_invalid_ack_delta" validate:"required"`
	PktInvalidTimestamp                   int64 `json:"pkt_invalid_timestamp" validate:"required"`
	PktInvalidTimestampDelta              int64 `json:"pkt_invalid_timestamp_delta" validate:"required"`
	PktRetransmission                     int64 `json:"pkt_retransmission" validate:"required"`
	PktRetransmissionDelta                int64 `json:"pkt_retransmission_delta" validate:"required"`
	ReassemblyNoSegment                   int64 `json:"reassembly_no_segment" validate:"required"`
	ReassemblyNoSegmentDelta              int64 `json:"reassembly_no_segment_delta" validate:"required"`
	ReassemblyOverlapDifferentData        int64 `json:"reassembly_overlap_different_data" validate:"required"`
	ReassemblyOverlapDifferentDataDelta   int64 `json:"reassembly_overlap_different_data_delta" validate:"required"`
	ReassemblySegmentBeforeBaseSeq        int64 `json:"reassembly_segment_before_base_seq" validate:"required"`
	ReassemblySegmentBeforeBaseSeqDelta   int64 `json:"reassembly_segment_before_base_seq_delta" validate:"required"`
	ReassemblySeqGap                      int64 `json:"reassembly_seq_gap" validate:"required"`
	ReassemblySeqGapDelta                 int64 `json:"reassembly_seq_gap_delta" validate:"required"`
	RstButNoSession                       int64 `json:"rst_but_no_session" validate:"required"`
	RstButNoSessionDelta                  int64 `json:"rst_but_no_session_delta" validate:"required"`
	RstInvalidACK                         int64 `json:"rst_invalid_ack" validate:"required"`
	RstInvalidACKDelta                    int64 `json:"rst_invalid_ack_delta" validate:"required"`
	ShutdownSynResend                     int64 `json:"shutdown_syn_resend" validate:"required"`
	ShutdownSynResendDelta                int64 `json:"shutdown_syn_resend_delta" validate:"required"`
	SuspectedRstInject                    int64 `json:"suspected_rst_inject" validate:"required"`
	SuspectedRstInjectDelta               int64 `json:"suspected_rst_inject_delta" validate:"required"`
	TimewaitACKWrongSeq                   int64 `json:"timewait_ack_wrong_seq" validate:"required"`
	TimewaitACKWrongSeqDelta              int64 `json:"timewait_ack_wrong_seq_delta" validate:"required"`
	TimewaitInvalidACK                    int64 `json:"timewait_invalid_ack" validate:"required"`
	TimewaitInvalidACKDelta               int64 `json:"timewait_invalid_ack_delta" validate:"required"`
	WrongThread                           int64 `json:"wrong_thread" validate:"required"`
	WrongThreadDelta                      int64 `json:"wrong_thread_delta" validate:"required"`
}

type StatsTCP struct {
	InsertDataNormalFail       int64 `json:"insert_data_normal_fail" validate:"required"`
	InsertDataNormalFailDelta  int64 `json:"insert_data_normal_fail_delta" validate:"required"`
	InsertDataOverlapFail      int64 `json:"insert_data_overlap_fail" validate:"required"`
	InsertDataOverlapFailDelta int64 `json:"insert_data_overlap_fail_delta" validate:"required"`
	InsertListFail             int64 `json:"insert_list_fail" validate:"required"`
	InsertListFailDelta        int64 `json:"insert_list_fail_delta" validate:"required"`
	InvalidChecksum            int64 `json:"invalid_checksum" validate:"required"`
	InvalidChecksumDelta       int64 `json:"invalid_checksum_delta" validate:"required"`
	Memuse                     int64 `json:"memuse" validate:"required"`
	MemuseDelta                int64 `json:"memuse_delta" validate:"required"`
	MidstreamPickups           int64 `json:"midstream_pickups" validate:"required"`
	MidstreamPickupsDelta      int64 `json:"midstream_pickups_delta" validate:"required"`
	NoFlow                     int64 `json:"no_flow" validate:"required"`
	NoFlowDelta                int64 `json:"no_flow_delta" validate:"required"`
	Overlap                    int64 `json:"overlap" validate:"required"`
	OverlapDelta               int64 `json:"overlap_delta" validate:"required"`
	OverlapDiffData            int64 `json:"overlap_diff_data" validate:"required"`
	OverlapDiffDataDelta       int64 `json:"overlap_diff_data_delta" validate:"required"`
	PktOnWrongThread           int64 `json:"pkt_on_wrong_thread" validate:"required"`
	PktOnWrongThreadDelta      int64 `json:"pkt_on_wrong_thread_delta" validate:"required"`
	Pseudo                     int64 `json:"pseudo" validate:"required"`
	PseudoDelta                int64 `json:"pseudo_delta" validate:"required"`
	PseudoFailed               int64 `json:"pseudo_failed" validate:"required"`
	PseudoFailedDelta          int64 `json:"pseudo_failed_delta" validate:"required"`
	ReassemblyGap              int64 `json:"reassembly_gap" validate:"required"`
	ReassemblyGapDelta         int64 `json:"reassembly_gap_delta" validate:"required"`
	ReassemblyMemuse           int64 `json:"reassembly_memuse" validate:"required"`
	ReassemblyMemuseDelta      int64 `json:"reassembly_memuse_delta" validate:"required"`
	Rst                        int64 `json:"rst" validate:"required"`
	RstDelta                   int64 `json:"rst_delta" validate:"required"`
	SegmentMemcapDrop          int64 `json:"segment_memcap_drop" validate:"required"`
	SegmentMemcapDropDelta     int64 `json:"segment_memcap_drop_delta" validate:"required"`
	Sessions                   int64 `json:"sessions" validate:"required"`
	SessionsDelta              int64 `json:"sessions_delta" validate:"required"`
	SsnMemcapDrop              int64 `json:"ssn_memcap_drop" validate:"required"`
	SsnMemcapDropDelta         int64 `json:"ssn_memcap_drop_delta" validate:"required"`
	StreamDepthReached         int64 `json:"stream_depth_reached" validate:"required"`
	StreamDepthReachedDelta    int64 `json:"stream_depth_reached_delta" validate:"required"`
	Syn                        int64 `json:"syn" validate:"required"`
	SynDelta                   int64 `json:"syn_delta" validate:"required"`
	Synack                     int64 `json:"synack" validate:"required"`
	SynackDelta                int64 `json:"synack_delta" validate:"required"`
}

type Thread struct {
	AppLayer     *ThreadAppLayer     `json:"app_layer,omitempty"`
	Decoder      *ThreadDecoder      `json:"decoder,omitempty"`
	Defrag       *ThreadDefrag       `json:"defrag,omitempty"`
	Detect       *ThreadDetect       `json:"detect,omitempty"`
	FileStore    *ThreadFileStore    `json:"file_store,omitempty"`
	Flow         ThreadFlow          `json:"flow" validate:"required"`
	FlowBypassed *ThreadFlowBypassed `json:"flow_bypassed,omitempty"`
	FlowMgr      *ThreadFlowMgr      `json:"flow_mgr,omitempty"`
	FTP          *ThreadFTP          `json:"ftp,omitempty"`
	HTTP         *ThreadHTTP         `json:"http,omitempty"`
	Stream       *ThreadStream       `json:"stream,omitempty"`
	TCP          *ThreadTCP          `json:"tcp,omitempty"`
}

type ThreadAppLayer struct {
	Expectations      *int64      `json:"expectations,omitempty"`
	ExpectationsDelta *int64      `json:"expectations_delta,omitempty"`
	Flow              *FluffyFlow `json:"flow,omitempty"`
	Tx                *FluffyTx   `json:"tx,omitempty"`
}

type FluffyFlow struct {
	DcerpcTCP      int64  `json:"dcerpc_tcp" validate:"required"`
	DcerpcTCPDelta int64  `json:"dcerpc_tcp_delta" validate:"required"`
	DcerpcUDP      int64  `json:"dcerpc_udp" validate:"required"`
	DcerpcUDPDelta int64  `json:"dcerpc_udp_delta" validate:"required"`
	DHCP           int64  `json:"dhcp" validate:"required"`
	DHCPDelta      int64  `json:"dhcp_delta" validate:"required"`
	Dnp3           int64  `json:"dnp3" validate:"required"`
	Dnp3Delta      int64  `json:"dnp3_delta" validate:"required"`
	DNSTCP         int64  `json:"dns_tcp" validate:"required"`
	DNSTCPDelta    int64  `json:"dns_tcp_delta" validate:"required"`
	DNSUDP         int64  `json:"dns_udp" validate:"required"`
	DNSUDPDelta    int64  `json:"dns_udp_delta" validate:"required"`
	EnipTCP        int64  `json:"enip_tcp" validate:"required"`
	EnipTCPDelta   int64  `json:"enip_tcp_delta" validate:"required"`
	EnipUDP        int64  `json:"enip_udp" validate:"required"`
	EnipUDPDelta   int64  `json:"enip_udp_delta" validate:"required"`
	FailedTCP      int64  `json:"failed_tcp" validate:"required"`
	FailedTCPDelta int64  `json:"failed_tcp_delta" validate:"required"`
	FailedUDP      int64  `json:"failed_udp" validate:"required"`
	FailedUDPDelta int64  `json:"failed_udp_delta" validate:"required"`
	FTP            int64  `json:"ftp" validate:"required"`
	FTPData        int64  `json:"ftp-data" validate:"required"`
	FTPDataDelta   int64  `json:"ftp-data_delta" validate:"required"`
	FTPDelta       int64  `json:"ftp_delta" validate:"required"`
	HTTP           int64  `json:"http" validate:"required"`
	HTTPDelta      int64  `json:"http_delta" validate:"required"`
	Ikev2          int64  `json:"ikev2" validate:"required"`
	Ikev2Delta     int64  `json:"ikev2_delta" validate:"required"`
	IMAP           int64  `json:"imap" validate:"required"`
	IMAPDelta      int64  `json:"imap_delta" validate:"required"`
	Krb5TCP        int64  `json:"krb5_tcp" validate:"required"`
	Krb5TCPDelta   int64  `json:"krb5_tcp_delta" validate:"required"`
	Krb5UDP        int64  `json:"krb5_udp" validate:"required"`
	Krb5UDPDelta   int64  `json:"krb5_udp_delta" validate:"required"`
	Modbus         int64  `json:"modbus" validate:"required"`
	ModbusDelta    int64  `json:"modbus_delta" validate:"required"`
	MSN            *int64 `json:"msn,omitempty"`
	MSNDelta       *int64 `json:"msn_delta,omitempty"`
	NFSTCP         int64  `json:"nfs_tcp" validate:"required"`
	NFSTCPDelta    int64  `json:"nfs_tcp_delta" validate:"required"`
	NFSUDP         int64  `json:"nfs_udp" validate:"required"`
	NFSUDPDelta    int64  `json:"nfs_udp_delta" validate:"required"`
	NTP            int64  `json:"ntp" validate:"required"`
	NTPDelta       int64  `json:"ntp_delta" validate:"required"`
	RDP            int64  `json:"rdp" validate:"required"`
	RDPDelta       int64  `json:"rdp_delta" validate:"required"`
	SIP            int64  `json:"sip" validate:"required"`
	SIPDelta       int64  `json:"sip_delta" validate:"required"`
	SMB            int64  `json:"smb" validate:"required"`
	SMBDelta       int64  `json:"smb_delta" validate:"required"`
	SMTP           int64  `json:"smtp" validate:"required"`
	SMTPDelta      int64  `json:"smtp_delta" validate:"required"`
	SNMP           int64  `json:"snmp" validate:"required"`
	SNMPDelta      int64  `json:"snmp_delta" validate:"required"`
	SSH            int64  `json:"ssh" validate:"required"`
	SSHDelta       int64  `json:"ssh_delta" validate:"required"`
	TFTP           int64  `json:"tftp" validate:"required"`
	TFTPDelta      int64  `json:"tftp_delta" validate:"required"`
	TLS            int64  `json:"tls" validate:"required"`
	TLSDelta       int64  `json:"tls_delta" validate:"required"`
}

type FluffyTx struct {
	DcerpcTCP      int64  `json:"dcerpc_tcp" validate:"required"`
	DcerpcTCPDelta int64  `json:"dcerpc_tcp_delta" validate:"required"`
	DcerpcUDP      int64  `json:"dcerpc_udp" validate:"required"`
	DcerpcUDPDelta int64  `json:"dcerpc_udp_delta" validate:"required"`
	DHCP           int64  `json:"dhcp" validate:"required"`
	DHCPDelta      int64  `json:"dhcp_delta" validate:"required"`
	Dnp3           int64  `json:"dnp3" validate:"required"`
	Dnp3Delta      int64  `json:"dnp3_delta" validate:"required"`
	DNSTCP         int64  `json:"dns_tcp" validate:"required"`
	DNSTCPDelta    int64  `json:"dns_tcp_delta" validate:"required"`
	DNSUDP         int64  `json:"dns_udp" validate:"required"`
	DNSUDPDelta    int64  `json:"dns_udp_delta" validate:"required"`
	EnipTCP        int64  `json:"enip_tcp" validate:"required"`
	EnipTCPDelta   int64  `json:"enip_tcp_delta" validate:"required"`
	EnipUDP        int64  `json:"enip_udp" validate:"required"`
	EnipUDPDelta   int64  `json:"enip_udp_delta" validate:"required"`
	FTP            int64  `json:"ftp" validate:"required"`
	FTPData        int64  `json:"ftp-data" validate:"required"`
	FTPDataDelta   int64  `json:"ftp-data_delta" validate:"required"`
	FTPDelta       int64  `json:"ftp_delta" validate:"required"`
	HTTP           int64  `json:"http" validate:"required"`
	HTTPDelta      int64  `json:"http_delta" validate:"required"`
	Ikev2          int64  `json:"ikev2" validate:"required"`
	Ikev2Delta     int64  `json:"ikev2_delta" validate:"required"`
	IMAP           int64  `json:"imap" validate:"required"`
	IMAPDelta      int64  `json:"imap_delta" validate:"required"`
	Krb5TCP        int64  `json:"krb5_tcp" validate:"required"`
	Krb5TCPDelta   int64  `json:"krb5_tcp_delta" validate:"required"`
	Krb5UDP        int64  `json:"krb5_udp" validate:"required"`
	Krb5UDPDelta   int64  `json:"krb5_udp_delta" validate:"required"`
	Modbus         int64  `json:"modbus" validate:"required"`
	ModbusDelta    int64  `json:"modbus_delta" validate:"required"`
	MSN            *int64 `json:"msn,omitempty"`
	MSNDelta       *int64 `json:"msn_delta,omitempty"`
	NFSTCP         int64  `json:"nfs_tcp" validate:"required"`
	NFSTCPDelta    int64  `json:"nfs_tcp_delta" validate:"required"`
	NFSUDP         int64  `json:"nfs_udp" validate:"required"`
	NFSUDPDelta    int64  `json:"nfs_udp_delta" validate:"required"`
	NTP            int64  `json:"ntp" validate:"required"`
	NTPDelta       int64  `json:"ntp_delta" validate:"required"`
	RDP            int64  `json:"rdp" validate:"required"`
	RDPDelta       int64  `json:"rdp_delta" validate:"required"`
	SIP            int64  `json:"sip" validate:"required"`
	SIPDelta       int64  `json:"sip_delta" validate:"required"`
	SMB            int64  `json:"smb" validate:"required"`
	SMBDelta       int64  `json:"smb_delta" validate:"required"`
	SMTP           int64  `json:"smtp" validate:"required"`
	SMTPDelta      int64  `json:"smtp_delta" validate:"required"`
	SNMP           int64  `json:"snmp" validate:"required"`
	SNMPDelta      int64  `json:"snmp_delta" validate:"required"`
	SSH            int64  `json:"ssh" validate:"required"`
	SSHDelta       int64  `json:"ssh_delta" validate:"required"`
	TFTP           int64  `json:"tftp" validate:"required"`
	TFTPDelta      int64  `json:"tftp_delta" validate:"required"`
	TLS            int64  `json:"tls" validate:"required"`
	TLSDelta       int64  `json:"tls_delta" validate:"required"`
}

type ThreadDecoder struct {
	AvgPktSize      int64       `json:"avg_pkt_size" validate:"required"`
	AvgPktSizeDelta int64       `json:"avg_pkt_size_delta" validate:"required"`
	Bytes           int64       `json:"bytes" validate:"required"`
	BytesDelta      int64       `json:"bytes_delta" validate:"required"`
	Dce             FluffyDce   `json:"dce" validate:"required"`
	Erspan          int64       `json:"erspan" validate:"required"`
	ErspanDelta     int64       `json:"erspan_delta" validate:"required"`
	Ethernet        int64       `json:"ethernet" validate:"required"`
	EthernetDelta   int64       `json:"ethernet_delta" validate:"required"`
	Event           FluffyEvent `json:"event" validate:"required"`
	Gre             int64       `json:"gre" validate:"required"`
	GreDelta        int64       `json:"gre_delta" validate:"required"`
	Icmpv4          int64       `json:"icmpv4" validate:"required"`
	Icmpv4Delta     int64       `json:"icmpv4_delta" validate:"required"`
	Icmpv6          int64       `json:"icmpv6" validate:"required"`
	Icmpv6Delta     int64       `json:"icmpv6_delta" validate:"required"`
	Ieee8021Ah      int64       `json:"ieee8021ah" validate:"required"`
	Ieee8021AhDelta int64       `json:"ieee8021ah_delta" validate:"required"`
	Invalid         int64       `json:"invalid" validate:"required"`
	InvalidDelta    int64       `json:"invalid_delta" validate:"required"`
	Ipv4            int64       `json:"ipv4" validate:"required"`
	Ipv4Delta       int64       `json:"ipv4_delta" validate:"required"`
	Ipv4InIpv6      int64       `json:"ipv4_in_ipv6" validate:"required"`
	Ipv4InIpv6Delta int64       `json:"ipv4_in_ipv6_delta" validate:"required"`
	Ipv6            int64       `json:"ipv6" validate:"required"`
	Ipv6Delta       int64       `json:"ipv6_delta" validate:"required"`
	Ipv6InIpv6      int64       `json:"ipv6_in_ipv6" validate:"required"`
	Ipv6InIpv6Delta int64       `json:"ipv6_in_ipv6_delta" validate:"required"`
	MaxPktSize      int64       `json:"max_pkt_size" validate:"required"`
	MaxPktSizeDelta int64       `json:"max_pkt_size_delta" validate:"required"`
	MPLS            int64       `json:"mpls" validate:"required"`
	MPLSDelta       int64       `json:"mpls_delta" validate:"required"`
	Null            int64       `json:"null" validate:"required"`
	NullDelta       int64       `json:"null_delta" validate:"required"`
	Pkts            int64       `json:"pkts" validate:"required"`
	PktsDelta       int64       `json:"pkts_delta" validate:"required"`
	PPP             int64       `json:"ppp" validate:"required"`
	PPPDelta        int64       `json:"ppp_delta" validate:"required"`
	Pppoe           int64       `json:"pppoe" validate:"required"`
	PppoeDelta      int64       `json:"pppoe_delta" validate:"required"`
	Raw             int64       `json:"raw" validate:"required"`
	RawDelta        int64       `json:"raw_delta" validate:"required"`
	SCTP            int64       `json:"sctp" validate:"required"`
	SCTPDelta       int64       `json:"sctp_delta" validate:"required"`
	Sll             int64       `json:"sll" validate:"required"`
	SllDelta        int64       `json:"sll_delta" validate:"required"`
	TCP             int64       `json:"tcp" validate:"required"`
	TCPDelta        int64       `json:"tcp_delta" validate:"required"`
	Teredo          int64       `json:"teredo" validate:"required"`
	TeredoDelta     int64       `json:"teredo_delta" validate:"required"`
	UDP             int64       `json:"udp" validate:"required"`
	UDPDelta        int64       `json:"udp_delta" validate:"required"`
	VLAN            int64       `json:"vlan" validate:"required"`
	VLANDelta       int64       `json:"vlan_delta" validate:"required"`
	VLANQinq        int64       `json:"vlan_qinq" validate:"required"`
	VLANQinqDelta   int64       `json:"vlan_qinq_delta" validate:"required"`
	Vxlan           int64       `json:"vxlan" validate:"required"`
	VxlanDelta      int64       `json:"vxlan_delta" validate:"required"`
}

type FluffyDce struct {
	PktTooSmall      int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta int64 `json:"pkt_too_small_delta" validate:"required"`
}

type FluffyEvent struct {
	Erspan     FluffyErspan     `json:"erspan" validate:"required"`
	Ethernet   FluffyEthernet   `json:"ethernet" validate:"required"`
	Gre        FluffyGre        `json:"gre" validate:"required"`
	Icmpv4     FluffyIcmpv4     `json:"icmpv4" validate:"required"`
	Icmpv6     FluffyIcmpv6     `json:"icmpv6" validate:"required"`
	Ieee8021Ah FluffyIeee8021Ah `json:"ieee8021ah" validate:"required"`
	Ipraw      FluffyIpraw      `json:"ipraw" validate:"required"`
	Ipv4       TentacledIpv4    `json:"ipv4" validate:"required"`
	Ipv6       TentacledIpv6    `json:"ipv6" validate:"required"`
	Ltnull     FluffyLtnull     `json:"ltnull" validate:"required"`
	MPLS       FluffyMPLS       `json:"mpls" validate:"required"`
	PPP        FluffyPPP        `json:"ppp" validate:"required"`
	Pppoe      FluffyPppoe      `json:"pppoe" validate:"required"`
	SCTP       FluffySCTP       `json:"sctp" validate:"required"`
	Sll        FluffySll        `json:"sll" validate:"required"`
	TCP        FluffyTCP        `json:"tcp" validate:"required"`
	UDP        FluffyUDP        `json:"udp" validate:"required"`
	VLAN       FluffyVLAN       `json:"vlan" validate:"required"`
}

type FluffyErspan struct {
	HeaderTooSmall          int64 `json:"header_too_small" validate:"required"`
	HeaderTooSmallDelta     int64 `json:"header_too_small_delta" validate:"required"`
	TooManyVLANLayers       int64 `json:"too_many_vlan_layers" validate:"required"`
	TooManyVLANLayersDelta  int64 `json:"too_many_vlan_layers_delta" validate:"required"`
	UnsupportedVersion      int64 `json:"unsupported_version" validate:"required"`
	UnsupportedVersionDelta int64 `json:"unsupported_version_delta" validate:"required"`
}

type FluffyEthernet struct {
	PktTooSmall      int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta int64 `json:"pkt_too_small_delta" validate:"required"`
}

type FluffyGre struct {
	PktTooSmall                  int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta             int64 `json:"pkt_too_small_delta" validate:"required"`
	Version0Flags                int64 `json:"version0_flags" validate:"required"`
	Version0FlagsDelta           int64 `json:"version0_flags_delta" validate:"required"`
	Version0HdrTooBig            int64 `json:"version0_hdr_too_big" validate:"required"`
	Version0HdrTooBigDelta       int64 `json:"version0_hdr_too_big_delta" validate:"required"`
	Version0MalformedSreHdr      int64 `json:"version0_malformed_sre_hdr" validate:"required"`
	Version0MalformedSreHdrDelta int64 `json:"version0_malformed_sre_hdr_delta" validate:"required"`
	Version0Recur                int64 `json:"version0_recur" validate:"required"`
	Version0RecurDelta           int64 `json:"version0_recur_delta" validate:"required"`
	Version1Chksum               int64 `json:"version1_chksum" validate:"required"`
	Version1ChksumDelta          int64 `json:"version1_chksum_delta" validate:"required"`
	Version1Flags                int64 `json:"version1_flags" validate:"required"`
	Version1FlagsDelta           int64 `json:"version1_flags_delta" validate:"required"`
	Version1HdrTooBig            int64 `json:"version1_hdr_too_big" validate:"required"`
	Version1HdrTooBigDelta       int64 `json:"version1_hdr_too_big_delta" validate:"required"`
	Version1MalformedSreHdr      int64 `json:"version1_malformed_sre_hdr" validate:"required"`
	Version1MalformedSreHdrDelta int64 `json:"version1_malformed_sre_hdr_delta" validate:"required"`
	Version1NoKey                int64 `json:"version1_no_key" validate:"required"`
	Version1NoKeyDelta           int64 `json:"version1_no_key_delta" validate:"required"`
	Version1Recur                int64 `json:"version1_recur" validate:"required"`
	Version1RecurDelta           int64 `json:"version1_recur_delta" validate:"required"`
	Version1Route                int64 `json:"version1_route" validate:"required"`
	Version1RouteDelta           int64 `json:"version1_route_delta" validate:"required"`
	Version1Ssr                  int64 `json:"version1_ssr" validate:"required"`
	Version1SsrDelta             int64 `json:"version1_ssr_delta" validate:"required"`
	Version1WrongProtocol        int64 `json:"version1_wrong_protocol" validate:"required"`
	Version1WrongProtocolDelta   int64 `json:"version1_wrong_protocol_delta" validate:"required"`
	WrongVersion                 int64 `json:"wrong_version" validate:"required"`
	WrongVersionDelta            int64 `json:"wrong_version_delta" validate:"required"`
}

type FluffyIcmpv4 struct {
	Ipv4TruncPkt        int64 `json:"ipv4_trunc_pkt" validate:"required"`
	Ipv4TruncPktDelta   int64 `json:"ipv4_trunc_pkt_delta" validate:"required"`
	Ipv4UnknownVer      int64 `json:"ipv4_unknown_ver" validate:"required"`
	Ipv4UnknownVerDelta int64 `json:"ipv4_unknown_ver_delta" validate:"required"`
	PktTooSmall         int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta    int64 `json:"pkt_too_small_delta" validate:"required"`
	UnknownCode         int64 `json:"unknown_code" validate:"required"`
	UnknownCodeDelta    int64 `json:"unknown_code_delta" validate:"required"`
	UnknownType         int64 `json:"unknown_type" validate:"required"`
	UnknownTypeDelta    int64 `json:"unknown_type_delta" validate:"required"`
}

type FluffyIcmpv6 struct {
	ExperimentationType          int64 `json:"experimentation_type" validate:"required"`
	ExperimentationTypeDelta     int64 `json:"experimentation_type_delta" validate:"required"`
	Ipv6TruncPkt                 int64 `json:"ipv6_trunc_pkt" validate:"required"`
	Ipv6TruncPktDelta            int64 `json:"ipv6_trunc_pkt_delta" validate:"required"`
	Ipv6UnknownVersion           int64 `json:"ipv6_unknown_version" validate:"required"`
	Ipv6UnknownVersionDelta      int64 `json:"ipv6_unknown_version_delta" validate:"required"`
	MldMessageWithInvalidHl      int64 `json:"mld_message_with_invalid_hl" validate:"required"`
	MldMessageWithInvalidHlDelta int64 `json:"mld_message_with_invalid_hl_delta" validate:"required"`
	PktTooSmall                  int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta             int64 `json:"pkt_too_small_delta" validate:"required"`
	UnassignedType               int64 `json:"unassigned_type" validate:"required"`
	UnassignedTypeDelta          int64 `json:"unassigned_type_delta" validate:"required"`
	UnknownCode                  int64 `json:"unknown_code" validate:"required"`
	UnknownCodeDelta             int64 `json:"unknown_code_delta" validate:"required"`
	UnknownType                  int64 `json:"unknown_type" validate:"required"`
	UnknownTypeDelta             int64 `json:"unknown_type_delta" validate:"required"`
}

type FluffyIeee8021Ah struct {
	HeaderTooSmall      int64 `json:"header_too_small" validate:"required"`
	HeaderTooSmallDelta int64 `json:"header_too_small_delta" validate:"required"`
}

type FluffyIpraw struct {
	InvalidIPVersion      int64 `json:"invalid_ip_version" validate:"required"`
	InvalidIPVersionDelta int64 `json:"invalid_ip_version_delta" validate:"required"`
}

type TentacledIpv4 struct {
	FragIgnored               int64 `json:"frag_ignored" validate:"required"`
	FragIgnoredDelta          int64 `json:"frag_ignored_delta" validate:"required"`
	FragOverlap               int64 `json:"frag_overlap" validate:"required"`
	FragOverlapDelta          int64 `json:"frag_overlap_delta" validate:"required"`
	FragPktTooLarge           int64 `json:"frag_pkt_too_large" validate:"required"`
	FragPktTooLargeDelta      int64 `json:"frag_pkt_too_large_delta" validate:"required"`
	HlenTooSmall              int64 `json:"hlen_too_small" validate:"required"`
	HlenTooSmallDelta         int64 `json:"hlen_too_small_delta" validate:"required"`
	Icmpv6                    int64 `json:"icmpv6" validate:"required"`
	Icmpv6Delta               int64 `json:"icmpv6_delta" validate:"required"`
	IplenSmallerThanHlen      int64 `json:"iplen_smaller_than_hlen" validate:"required"`
	IplenSmallerThanHlenDelta int64 `json:"iplen_smaller_than_hlen_delta" validate:"required"`
	OptDuplicate              int64 `json:"opt_duplicate" validate:"required"`
	OptDuplicateDelta         int64 `json:"opt_duplicate_delta" validate:"required"`
	OptEOLRequired            int64 `json:"opt_eol_required" validate:"required"`
	OptEOLRequiredDelta       int64 `json:"opt_eol_required_delta" validate:"required"`
	OptInvalid                int64 `json:"opt_invalid" validate:"required"`
	OptInvalidDelta           int64 `json:"opt_invalid_delta" validate:"required"`
	OptInvalidLen             int64 `json:"opt_invalid_len" validate:"required"`
	OptInvalidLenDelta        int64 `json:"opt_invalid_len_delta" validate:"required"`
	OptMalformed              int64 `json:"opt_malformed" validate:"required"`
	OptMalformedDelta         int64 `json:"opt_malformed_delta" validate:"required"`
	OptPadRequired            int64 `json:"opt_pad_required" validate:"required"`
	OptPadRequiredDelta       int64 `json:"opt_pad_required_delta" validate:"required"`
	OptUnknown                int64 `json:"opt_unknown" validate:"required"`
	OptUnknownDelta           int64 `json:"opt_unknown_delta" validate:"required"`
	PktTooSmall               int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta          int64 `json:"pkt_too_small_delta" validate:"required"`
	TruncPkt                  int64 `json:"trunc_pkt" validate:"required"`
	TruncPktDelta             int64 `json:"trunc_pkt_delta" validate:"required"`
	WrongIPVersion            int64 `json:"wrong_ip_version" validate:"required"`
	WrongIPVersionDelta       int64 `json:"wrong_ip_version_delta" validate:"required"`
}

type TentacledIpv6 struct {
	DataAfterNoneHeader         int64 `json:"data_after_none_header" validate:"required"`
	DataAfterNoneHeaderDelta    int64 `json:"data_after_none_header_delta" validate:"required"`
	DstoptsOnlyPadding          int64 `json:"dstopts_only_padding" validate:"required"`
	DstoptsOnlyPaddingDelta     int64 `json:"dstopts_only_padding_delta" validate:"required"`
	DstoptsUnknownOpt           int64 `json:"dstopts_unknown_opt" validate:"required"`
	DstoptsUnknownOptDelta      int64 `json:"dstopts_unknown_opt_delta" validate:"required"`
	ExthdrAhResNotNull          int64 `json:"exthdr_ah_res_not_null" validate:"required"`
	ExthdrAhResNotNullDelta     int64 `json:"exthdr_ah_res_not_null_delta" validate:"required"`
	ExthdrDuplAh                int64 `json:"exthdr_dupl_ah" validate:"required"`
	ExthdrDuplAhDelta           int64 `json:"exthdr_dupl_ah_delta" validate:"required"`
	ExthdrDuplDh                int64 `json:"exthdr_dupl_dh" validate:"required"`
	ExthdrDuplDhDelta           int64 `json:"exthdr_dupl_dh_delta" validate:"required"`
	ExthdrDuplEh                int64 `json:"exthdr_dupl_eh" validate:"required"`
	ExthdrDuplEhDelta           int64 `json:"exthdr_dupl_eh_delta" validate:"required"`
	ExthdrDuplFh                int64 `json:"exthdr_dupl_fh" validate:"required"`
	ExthdrDuplFhDelta           int64 `json:"exthdr_dupl_fh_delta" validate:"required"`
	ExthdrDuplHh                int64 `json:"exthdr_dupl_hh" validate:"required"`
	ExthdrDuplHhDelta           int64 `json:"exthdr_dupl_hh_delta" validate:"required"`
	ExthdrDuplRh                int64 `json:"exthdr_dupl_rh" validate:"required"`
	ExthdrDuplRhDelta           int64 `json:"exthdr_dupl_rh_delta" validate:"required"`
	ExthdrInvalidOptlen         int64 `json:"exthdr_invalid_optlen" validate:"required"`
	ExthdrInvalidOptlenDelta    int64 `json:"exthdr_invalid_optlen_delta" validate:"required"`
	ExthdrUselessFh             int64 `json:"exthdr_useless_fh" validate:"required"`
	ExthdrUselessFhDelta        int64 `json:"exthdr_useless_fh_delta" validate:"required"`
	FhNonZeroReservedField      int64 `json:"fh_non_zero_reserved_field" validate:"required"`
	FhNonZeroReservedFieldDelta int64 `json:"fh_non_zero_reserved_field_delta" validate:"required"`
	FragIgnored                 int64 `json:"frag_ignored" validate:"required"`
	FragIgnoredDelta            int64 `json:"frag_ignored_delta" validate:"required"`
	FragOverlap                 int64 `json:"frag_overlap" validate:"required"`
	FragOverlapDelta            int64 `json:"frag_overlap_delta" validate:"required"`
	FragPktTooLarge             int64 `json:"frag_pkt_too_large" validate:"required"`
	FragPktTooLargeDelta        int64 `json:"frag_pkt_too_large_delta" validate:"required"`
	HopoptsOnlyPadding          int64 `json:"hopopts_only_padding" validate:"required"`
	HopoptsOnlyPaddingDelta     int64 `json:"hopopts_only_padding_delta" validate:"required"`
	HopoptsUnknownOpt           int64 `json:"hopopts_unknown_opt" validate:"required"`
	HopoptsUnknownOptDelta      int64 `json:"hopopts_unknown_opt_delta" validate:"required"`
	Icmpv4                      int64 `json:"icmpv4" validate:"required"`
	Icmpv4Delta                 int64 `json:"icmpv4_delta" validate:"required"`
	Ipv4InIpv6TooSmall          int64 `json:"ipv4_in_ipv6_too_small" validate:"required"`
	Ipv4InIpv6TooSmallDelta     int64 `json:"ipv4_in_ipv6_too_small_delta" validate:"required"`
	Ipv4InIpv6WrongVersion      int64 `json:"ipv4_in_ipv6_wrong_version" validate:"required"`
	Ipv4InIpv6WrongVersionDelta int64 `json:"ipv4_in_ipv6_wrong_version_delta" validate:"required"`
	Ipv6InIpv6TooSmall          int64 `json:"ipv6_in_ipv6_too_small" validate:"required"`
	Ipv6InIpv6TooSmallDelta     int64 `json:"ipv6_in_ipv6_too_small_delta" validate:"required"`
	Ipv6InIpv6WrongVersion      int64 `json:"ipv6_in_ipv6_wrong_version" validate:"required"`
	Ipv6InIpv6WrongVersionDelta int64 `json:"ipv6_in_ipv6_wrong_version_delta" validate:"required"`
	PktTooSmall                 int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta            int64 `json:"pkt_too_small_delta" validate:"required"`
	RhType0                     int64 `json:"rh_type_0" validate:"required"`
	RhType0_Delta               int64 `json:"rh_type_0_delta" validate:"required"`
	TruncExthdr                 int64 `json:"trunc_exthdr" validate:"required"`
	TruncExthdrDelta            int64 `json:"trunc_exthdr_delta" validate:"required"`
	TruncPkt                    int64 `json:"trunc_pkt" validate:"required"`
	TruncPktDelta               int64 `json:"trunc_pkt_delta" validate:"required"`
	UnknownNextHeader           int64 `json:"unknown_next_header" validate:"required"`
	UnknownNextHeaderDelta      int64 `json:"unknown_next_header_delta" validate:"required"`
	WrongIPVersion              int64 `json:"wrong_ip_version" validate:"required"`
	WrongIPVersionDelta         int64 `json:"wrong_ip_version_delta" validate:"required"`
	ZeroLenPadn                 int64 `json:"zero_len_padn" validate:"required"`
	ZeroLenPadnDelta            int64 `json:"zero_len_padn_delta" validate:"required"`
}

type FluffyLtnull struct {
	PktTooSmall          int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta     int64 `json:"pkt_too_small_delta" validate:"required"`
	UnsupportedType      int64 `json:"unsupported_type" validate:"required"`
	UnsupportedTypeDelta int64 `json:"unsupported_type_delta" validate:"required"`
}

type FluffyMPLS struct {
	BadLabelImplicitNull      int64 `json:"bad_label_implicit_null" validate:"required"`
	BadLabelImplicitNullDelta int64 `json:"bad_label_implicit_null_delta" validate:"required"`
	BadLabelReserved          int64 `json:"bad_label_reserved" validate:"required"`
	BadLabelReservedDelta     int64 `json:"bad_label_reserved_delta" validate:"required"`
	BadLabelRouterAlert       int64 `json:"bad_label_router_alert" validate:"required"`
	BadLabelRouterAlertDelta  int64 `json:"bad_label_router_alert_delta" validate:"required"`
	HeaderTooSmall            int64 `json:"header_too_small" validate:"required"`
	HeaderTooSmallDelta       int64 `json:"header_too_small_delta" validate:"required"`
	PktTooSmall               int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta          int64 `json:"pkt_too_small_delta" validate:"required"`
	UnknownPayloadType        int64 `json:"unknown_payload_type" validate:"required"`
	UnknownPayloadTypeDelta   int64 `json:"unknown_payload_type_delta" validate:"required"`
}

type FluffyPPP struct {
	Ip4PktTooSmall      int64 `json:"ip4_pkt_too_small" validate:"required"`
	Ip4PktTooSmallDelta int64 `json:"ip4_pkt_too_small_delta" validate:"required"`
	Ip6PktTooSmall      int64 `json:"ip6_pkt_too_small" validate:"required"`
	Ip6PktTooSmallDelta int64 `json:"ip6_pkt_too_small_delta" validate:"required"`
	PktTooSmall         int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta    int64 `json:"pkt_too_small_delta" validate:"required"`
	UnsupProto          int64 `json:"unsup_proto" validate:"required"`
	UnsupProtoDelta     int64 `json:"unsup_proto_delta" validate:"required"`
	VjuPktTooSmall      int64 `json:"vju_pkt_too_small" validate:"required"`
	VjuPktTooSmallDelta int64 `json:"vju_pkt_too_small_delta" validate:"required"`
	WrongType           int64 `json:"wrong_type" validate:"required"`
	WrongTypeDelta      int64 `json:"wrong_type_delta" validate:"required"`
}

type FluffyPppoe struct {
	MalformedTags      int64 `json:"malformed_tags" validate:"required"`
	MalformedTagsDelta int64 `json:"malformed_tags_delta" validate:"required"`
	PktTooSmall        int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta   int64 `json:"pkt_too_small_delta" validate:"required"`
	WrongCode          int64 `json:"wrong_code" validate:"required"`
	WrongCodeDelta     int64 `json:"wrong_code_delta" validate:"required"`
}

type FluffySCTP struct {
	PktTooSmall      int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta int64 `json:"pkt_too_small_delta" validate:"required"`
}

type FluffySll struct {
	PktTooSmall      int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta int64 `json:"pkt_too_small_delta" validate:"required"`
}

type FluffyTCP struct {
	HlenTooSmall       int64 `json:"hlen_too_small" validate:"required"`
	HlenTooSmallDelta  int64 `json:"hlen_too_small_delta" validate:"required"`
	InvalidOptlen      int64 `json:"invalid_optlen" validate:"required"`
	InvalidOptlenDelta int64 `json:"invalid_optlen_delta" validate:"required"`
	OptDuplicate       int64 `json:"opt_duplicate" validate:"required"`
	OptDuplicateDelta  int64 `json:"opt_duplicate_delta" validate:"required"`
	OptInvalidLen      int64 `json:"opt_invalid_len" validate:"required"`
	OptInvalidLenDelta int64 `json:"opt_invalid_len_delta" validate:"required"`
	PktTooSmall        int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta   int64 `json:"pkt_too_small_delta" validate:"required"`
}

type FluffyUDP struct {
	HlenInvalid       int64 `json:"hlen_invalid" validate:"required"`
	HlenInvalidDelta  int64 `json:"hlen_invalid_delta" validate:"required"`
	HlenTooSmall      int64 `json:"hlen_too_small" validate:"required"`
	HlenTooSmallDelta int64 `json:"hlen_too_small_delta" validate:"required"`
	PktTooSmall       int64 `json:"pkt_too_small" validate:"required"`
	PktTooSmallDelta  int64 `json:"pkt_too_small_delta" validate:"required"`
}

type FluffyVLAN struct {
	HeaderTooSmall      int64 `json:"header_too_small" validate:"required"`
	HeaderTooSmallDelta int64 `json:"header_too_small_delta" validate:"required"`
	TooManyLayers       int64 `json:"too_many_layers" validate:"required"`
	TooManyLayersDelta  int64 `json:"too_many_layers_delta" validate:"required"`
	UnknownType         int64 `json:"unknown_type" validate:"required"`
	UnknownTypeDelta    int64 `json:"unknown_type_delta" validate:"required"`
}

type ThreadDefrag struct {
	Ipv4             StickyIpv4 `json:"ipv4" validate:"required"`
	Ipv6             StickyIpv6 `json:"ipv6" validate:"required"`
	MaxFragHits      int64      `json:"max_frag_hits" validate:"required"`
	MaxFragHitsDelta int64      `json:"max_frag_hits_delta" validate:"required"`
}

type StickyIpv4 struct {
	Fragments        int64 `json:"fragments" validate:"required"`
	FragmentsDelta   int64 `json:"fragments_delta" validate:"required"`
	Reassembled      int64 `json:"reassembled" validate:"required"`
	ReassembledDelta int64 `json:"reassembled_delta" validate:"required"`
	Timeouts         int64 `json:"timeouts" validate:"required"`
	TimeoutsDelta    int64 `json:"timeouts_delta" validate:"required"`
}

type StickyIpv6 struct {
	Fragments        int64 `json:"fragments" validate:"required"`
	FragmentsDelta   int64 `json:"fragments_delta" validate:"required"`
	Reassembled      int64 `json:"reassembled" validate:"required"`
	ReassembledDelta int64 `json:"reassembled_delta" validate:"required"`
	Timeouts         int64 `json:"timeouts" validate:"required"`
	TimeoutsDelta    int64 `json:"timeouts_delta" validate:"required"`
}

type ThreadDetect struct {
	Alert      int64          `json:"alert" validate:"required"`
	AlertDelta int64          `json:"alert_delta" validate:"required"`
	Engines    []FluffyEngine `json:"engines" validate:"required"`
}

type FluffyEngine struct {
	ID          int64  `json:"id" validate:"required"`
	LastReload  string `json:"last_reload" validate:"required"`
	RulesFailed int64  `json:"rules_failed" validate:"required"`
	RulesLoaded int64  `json:"rules_loaded" validate:"required"`
}

type ThreadFTP struct {
	Memcap      int64 `json:"memcap" validate:"required"`
	MemcapDelta int64 `json:"memcap_delta" validate:"required"`
	Memuse      int64 `json:"memuse" validate:"required"`
	MemuseDelta int64 `json:"memuse_delta" validate:"required"`
}

type ThreadFileStore struct {
	FSErrors             *int64 `json:"fs_errors,omitempty"`
	FSErrorsDelta        *int64 `json:"fs_errors_delta,omitempty"`
	OpenFiles            *int64 `json:"open_files,omitempty"`
	OpenFilesDelta       *int64 `json:"open_files_delta,omitempty"`
	OpenFilesMaxHit      *int64 `json:"open_files_max_hit,omitempty"`
	OpenFilesMaxHitDelta *int64 `json:"open_files_max_hit_delta,omitempty"`
}

type ThreadFlow struct {
	EmergModeEntered      *int64 `json:"emerg_mode_entered,omitempty"`
	EmergModeEnteredDelta *int64 `json:"emerg_mode_entered_delta,omitempty"`
	EmergModeOver         *int64 `json:"emerg_mode_over,omitempty"`
	EmergModeOverDelta    *int64 `json:"emerg_mode_over_delta,omitempty"`
	Icmpv4                *int64 `json:"icmpv4,omitempty"`
	Icmpv4Delta           *int64 `json:"icmpv4_delta,omitempty"`
	Icmpv6                *int64 `json:"icmpv6,omitempty"`
	Icmpv6Delta           *int64 `json:"icmpv6_delta,omitempty"`
	Memcap                *int64 `json:"memcap,omitempty"`
	MemcapDelta           *int64 `json:"memcap_delta,omitempty"`
	Memuse                *int64 `json:"memuse,omitempty"`
	MemuseDelta           *int64 `json:"memuse_delta,omitempty"`
	Spare                 *int64 `json:"spare,omitempty"`
	SpareDelta            *int64 `json:"spare_delta,omitempty"`
	TCP                   *int64 `json:"tcp,omitempty"`
	TCPDelta              *int64 `json:"tcp_delta,omitempty"`
	TCPReuse              *int64 `json:"tcp_reuse,omitempty"`
	TCPReuseDelta         *int64 `json:"tcp_reuse_delta,omitempty"`
	UDP                   *int64 `json:"udp,omitempty"`
	UDPDelta              *int64 `json:"udp_delta,omitempty"`
}

type ThreadFlowBypassed struct {
	Bytes                  *int64 `json:"bytes,omitempty"`
	BytesDelta             *int64 `json:"bytes_delta,omitempty"`
	Closed                 *int64 `json:"closed,omitempty"`
	ClosedDelta            *int64 `json:"closed_delta,omitempty"`
	LocalBytes             *int64 `json:"local_bytes,omitempty"`
	LocalBytesDelta        *int64 `json:"local_bytes_delta,omitempty"`
	LocalCaptureBytes      *int64 `json:"local_capture_bytes,omitempty"`
	LocalCaptureBytesDelta *int64 `json:"local_capture_bytes_delta,omitempty"`
	LocalCapturePkts       *int64 `json:"local_capture_pkts,omitempty"`
	LocalCapturePktsDelta  *int64 `json:"local_capture_pkts_delta,omitempty"`
	LocalPkts              *int64 `json:"local_pkts,omitempty"`
	LocalPktsDelta         *int64 `json:"local_pkts_delta,omitempty"`
	Pkts                   *int64 `json:"pkts,omitempty"`
	PktsDelta              *int64 `json:"pkts_delta,omitempty"`
}

type ThreadFlowMgr struct {
	BypassedPruned         int64 `json:"bypassed_pruned" validate:"required"`
	BypassedPrunedDelta    int64 `json:"bypassed_pruned_delta" validate:"required"`
	ClosedPruned           int64 `json:"closed_pruned" validate:"required"`
	ClosedPrunedDelta      int64 `json:"closed_pruned_delta" validate:"required"`
	EstPruned              int64 `json:"est_pruned" validate:"required"`
	EstPrunedDelta         int64 `json:"est_pruned_delta" validate:"required"`
	FlowsChecked           int64 `json:"flows_checked" validate:"required"`
	FlowsCheckedDelta      int64 `json:"flows_checked_delta" validate:"required"`
	FlowsNotimeout         int64 `json:"flows_notimeout" validate:"required"`
	FlowsNotimeoutDelta    int64 `json:"flows_notimeout_delta" validate:"required"`
	FlowsRemoved           int64 `json:"flows_removed" validate:"required"`
	FlowsRemovedDelta      int64 `json:"flows_removed_delta" validate:"required"`
	FlowsTimeout           int64 `json:"flows_timeout" validate:"required"`
	FlowsTimeoutDelta      int64 `json:"flows_timeout_delta" validate:"required"`
	FlowsTimeoutInuse      int64 `json:"flows_timeout_inuse" validate:"required"`
	FlowsTimeoutInuseDelta int64 `json:"flows_timeout_inuse_delta" validate:"required"`
	NewPruned              int64 `json:"new_pruned" validate:"required"`
	NewPrunedDelta         int64 `json:"new_pruned_delta" validate:"required"`
	RowsBusy               int64 `json:"rows_busy" validate:"required"`
	RowsBusyDelta          int64 `json:"rows_busy_delta" validate:"required"`
	RowsChecked            int64 `json:"rows_checked" validate:"required"`
	RowsCheckedDelta       int64 `json:"rows_checked_delta" validate:"required"`
	RowsEmpty              int64 `json:"rows_empty" validate:"required"`
	RowsEmptyDelta         int64 `json:"rows_empty_delta" validate:"required"`
	RowsMaxlen             int64 `json:"rows_maxlen" validate:"required"`
	RowsMaxlenDelta        int64 `json:"rows_maxlen_delta" validate:"required"`
	RowsSkipped            int64 `json:"rows_skipped" validate:"required"`
	RowsSkippedDelta       int64 `json:"rows_skipped_delta" validate:"required"`
}

type ThreadHTTP struct {
	Memcap      int64 `json:"memcap" validate:"required"`
	MemcapDelta int64 `json:"memcap_delta" validate:"required"`
	Memuse      int64 `json:"memuse" validate:"required"`
	MemuseDelta int64 `json:"memuse_delta" validate:"required"`
}

type ThreadStream struct {
	The3WhsACKDataInject                  int64 `json:"3whs_ack_data_inject" validate:"required"`
	The3WhsACKDataInjectDelta             int64 `json:"3whs_ack_data_inject_delta" validate:"required"`
	The3WhsACKInWrongDir                  int64 `json:"3whs_ack_in_wrong_dir" validate:"required"`
	The3WhsACKInWrongDirDelta             int64 `json:"3whs_ack_in_wrong_dir_delta" validate:"required"`
	The3WhsAsyncWrongSeq                  int64 `json:"3whs_async_wrong_seq" validate:"required"`
	The3WhsAsyncWrongSeqDelta             int64 `json:"3whs_async_wrong_seq_delta" validate:"required"`
	The3WhsRightSeqWrongACKEvasion        int64 `json:"3whs_right_seq_wrong_ack_evasion" validate:"required"`
	The3WhsRightSeqWrongACKEvasionDelta   int64 `json:"3whs_right_seq_wrong_ack_evasion_delta" validate:"required"`
	The3WhsSynResendDiffSeqOnSynRecv      int64 `json:"3whs_syn_resend_diff_seq_on_syn_recv" validate:"required"`
	The3WhsSynResendDiffSeqOnSynRecvDelta int64 `json:"3whs_syn_resend_diff_seq_on_syn_recv_delta" validate:"required"`
	The3WhsSynToclientOnSynRecv           int64 `json:"3whs_syn_toclient_on_syn_recv" validate:"required"`
	The3WhsSynToclientOnSynRecvDelta      int64 `json:"3whs_syn_toclient_on_syn_recv_delta" validate:"required"`
	The3WhsSynackFlood                    int64 `json:"3whs_synack_flood" validate:"required"`
	The3WhsSynackFloodDelta               int64 `json:"3whs_synack_flood_delta" validate:"required"`
	The3WhsSynackInWrongDirection         int64 `json:"3whs_synack_in_wrong_direction" validate:"required"`
	The3WhsSynackInWrongDirectionDelta    int64 `json:"3whs_synack_in_wrong_direction_delta" validate:"required"`
	The3WhsSynackResendWithDiffACK        int64 `json:"3whs_synack_resend_with_diff_ack" validate:"required"`
	The3WhsSynackResendWithDiffACKDelta   int64 `json:"3whs_synack_resend_with_diff_ack_delta" validate:"required"`
	The3WhsSynackResendWithDiffSeq        int64 `json:"3whs_synack_resend_with_diff_seq" validate:"required"`
	The3WhsSynackResendWithDiffSeqDelta   int64 `json:"3whs_synack_resend_with_diff_seq_delta" validate:"required"`
	The3WhsSynackToserverOnSynRecv        int64 `json:"3whs_synack_toserver_on_syn_recv" validate:"required"`
	The3WhsSynackToserverOnSynRecvDelta   int64 `json:"3whs_synack_toserver_on_syn_recv_delta" validate:"required"`
	The3WhsSynackWithWrongACK             int64 `json:"3whs_synack_with_wrong_ack" validate:"required"`
	The3WhsSynackWithWrongACKDelta        int64 `json:"3whs_synack_with_wrong_ack_delta" validate:"required"`
	The3WhsWrongSeqWrongACK               int64 `json:"3whs_wrong_seq_wrong_ack" validate:"required"`
	The3WhsWrongSeqWrongACKDelta          int64 `json:"3whs_wrong_seq_wrong_ack_delta" validate:"required"`
	The4WhsInvalidACK                     int64 `json:"4whs_invalid_ack" validate:"required"`
	The4WhsInvalidACKDelta                int64 `json:"4whs_invalid_ack_delta" validate:"required"`
	The4WhsSynackWithWrongACK             int64 `json:"4whs_synack_with_wrong_ack" validate:"required"`
	The4WhsSynackWithWrongACKDelta        int64 `json:"4whs_synack_with_wrong_ack_delta" validate:"required"`
	The4WhsSynackWithWrongSyn             int64 `json:"4whs_synack_with_wrong_syn" validate:"required"`
	The4WhsSynackWithWrongSynDelta        int64 `json:"4whs_synack_with_wrong_syn_delta" validate:"required"`
	The4WhsWrongSeq                       int64 `json:"4whs_wrong_seq" validate:"required"`
	The4WhsWrongSeqDelta                  int64 `json:"4whs_wrong_seq_delta" validate:"required"`
	ClosewaitACKOutOfWindow               int64 `json:"closewait_ack_out_of_window" validate:"required"`
	ClosewaitACKOutOfWindowDelta          int64 `json:"closewait_ack_out_of_window_delta" validate:"required"`
	ClosewaitFinOutOfWindow               int64 `json:"closewait_fin_out_of_window" validate:"required"`
	ClosewaitFinOutOfWindowDelta          int64 `json:"closewait_fin_out_of_window_delta" validate:"required"`
	ClosewaitInvalidACK                   int64 `json:"closewait_invalid_ack" validate:"required"`
	ClosewaitInvalidACKDelta              int64 `json:"closewait_invalid_ack_delta" validate:"required"`
	ClosewaitPktBeforeLastACK             int64 `json:"closewait_pkt_before_last_ack" validate:"required"`
	ClosewaitPktBeforeLastACKDelta        int64 `json:"closewait_pkt_before_last_ack_delta" validate:"required"`
	ClosingACKWrongSeq                    int64 `json:"closing_ack_wrong_seq" validate:"required"`
	ClosingACKWrongSeqDelta               int64 `json:"closing_ack_wrong_seq_delta" validate:"required"`
	ClosingInvalidACK                     int64 `json:"closing_invalid_ack" validate:"required"`
	ClosingInvalidACKDelta                int64 `json:"closing_invalid_ack_delta" validate:"required"`
	EstInvalidACK                         int64 `json:"est_invalid_ack" validate:"required"`
	EstInvalidACKDelta                    int64 `json:"est_invalid_ack_delta" validate:"required"`
	EstPacketOutOfWindow                  int64 `json:"est_packet_out_of_window" validate:"required"`
	EstPacketOutOfWindowDelta             int64 `json:"est_packet_out_of_window_delta" validate:"required"`
	EstPktBeforeLastACK                   int64 `json:"est_pkt_before_last_ack" validate:"required"`
	EstPktBeforeLastACKDelta              int64 `json:"est_pkt_before_last_ack_delta" validate:"required"`
	EstSynResend                          int64 `json:"est_syn_resend" validate:"required"`
	EstSynResendDelta                     int64 `json:"est_syn_resend_delta" validate:"required"`
	EstSynResendDiffSeq                   int64 `json:"est_syn_resend_diff_seq" validate:"required"`
	EstSynResendDiffSeqDelta              int64 `json:"est_syn_resend_diff_seq_delta" validate:"required"`
	EstSynToclient                        int64 `json:"est_syn_toclient" validate:"required"`
	EstSynToclientDelta                   int64 `json:"est_syn_toclient_delta" validate:"required"`
	EstSynackResend                       int64 `json:"est_synack_resend" validate:"required"`
	EstSynackResendDelta                  int64 `json:"est_synack_resend_delta" validate:"required"`
	EstSynackResendWithDiffACK            int64 `json:"est_synack_resend_with_diff_ack" validate:"required"`
	EstSynackResendWithDiffACKDelta       int64 `json:"est_synack_resend_with_diff_ack_delta" validate:"required"`
	EstSynackResendWithDiffSeq            int64 `json:"est_synack_resend_with_diff_seq" validate:"required"`
	EstSynackResendWithDiffSeqDelta       int64 `json:"est_synack_resend_with_diff_seq_delta" validate:"required"`
	EstSynackToserver                     int64 `json:"est_synack_toserver" validate:"required"`
	EstSynackToserverDelta                int64 `json:"est_synack_toserver_delta" validate:"required"`
	Fin1ACKWrongSeq                       int64 `json:"fin1_ack_wrong_seq" validate:"required"`
	Fin1ACKWrongSeqDelta                  int64 `json:"fin1_ack_wrong_seq_delta" validate:"required"`
	Fin1FinWrongSeq                       int64 `json:"fin1_fin_wrong_seq" validate:"required"`
	Fin1FinWrongSeqDelta                  int64 `json:"fin1_fin_wrong_seq_delta" validate:"required"`
	Fin1InvalidACK                        int64 `json:"fin1_invalid_ack" validate:"required"`
	Fin1InvalidACKDelta                   int64 `json:"fin1_invalid_ack_delta" validate:"required"`
	Fin2ACKWrongSeq                       int64 `json:"fin2_ack_wrong_seq" validate:"required"`
	Fin2ACKWrongSeqDelta                  int64 `json:"fin2_ack_wrong_seq_delta" validate:"required"`
	Fin2FinWrongSeq                       int64 `json:"fin2_fin_wrong_seq" validate:"required"`
	Fin2FinWrongSeqDelta                  int64 `json:"fin2_fin_wrong_seq_delta" validate:"required"`
	Fin2InvalidACK                        int64 `json:"fin2_invalid_ack" validate:"required"`
	Fin2InvalidACKDelta                   int64 `json:"fin2_invalid_ack_delta" validate:"required"`
	FinButNoSession                       int64 `json:"fin_but_no_session" validate:"required"`
	FinButNoSessionDelta                  int64 `json:"fin_but_no_session_delta" validate:"required"`
	FinInvalidACK                         int64 `json:"fin_invalid_ack" validate:"required"`
	FinInvalidACKDelta                    int64 `json:"fin_invalid_ack_delta" validate:"required"`
	FinOutOfWindow                        int64 `json:"fin_out_of_window" validate:"required"`
	FinOutOfWindowDelta                   int64 `json:"fin_out_of_window_delta" validate:"required"`
	LastackACKWrongSeq                    int64 `json:"lastack_ack_wrong_seq" validate:"required"`
	LastackACKWrongSeqDelta               int64 `json:"lastack_ack_wrong_seq_delta" validate:"required"`
	LastackInvalidACK                     int64 `json:"lastack_invalid_ack" validate:"required"`
	LastackInvalidACKDelta                int64 `json:"lastack_invalid_ack_delta" validate:"required"`
	PktBadWindowUpdate                    int64 `json:"pkt_bad_window_update" validate:"required"`
	PktBadWindowUpdateDelta               int64 `json:"pkt_bad_window_update_delta" validate:"required"`
	PktBrokenACK                          int64 `json:"pkt_broken_ack" validate:"required"`
	PktBrokenACKDelta                     int64 `json:"pkt_broken_ack_delta" validate:"required"`
	PktInvalidACK                         int64 `json:"pkt_invalid_ack" validate:"required"`
	PktInvalidACKDelta                    int64 `json:"pkt_invalid_ack_delta" validate:"required"`
	PktInvalidTimestamp                   int64 `json:"pkt_invalid_timestamp" validate:"required"`
	PktInvalidTimestampDelta              int64 `json:"pkt_invalid_timestamp_delta" validate:"required"`
	PktRetransmission                     int64 `json:"pkt_retransmission" validate:"required"`
	PktRetransmissionDelta                int64 `json:"pkt_retransmission_delta" validate:"required"`
	ReassemblyNoSegment                   int64 `json:"reassembly_no_segment" validate:"required"`
	ReassemblyNoSegmentDelta              int64 `json:"reassembly_no_segment_delta" validate:"required"`
	ReassemblyOverlapDifferentData        int64 `json:"reassembly_overlap_different_data" validate:"required"`
	ReassemblyOverlapDifferentDataDelta   int64 `json:"reassembly_overlap_different_data_delta" validate:"required"`
	ReassemblySegmentBeforeBaseSeq        int64 `json:"reassembly_segment_before_base_seq" validate:"required"`
	ReassemblySegmentBeforeBaseSeqDelta   int64 `json:"reassembly_segment_before_base_seq_delta" validate:"required"`
	ReassemblySeqGap                      int64 `json:"reassembly_seq_gap" validate:"required"`
	ReassemblySeqGapDelta                 int64 `json:"reassembly_seq_gap_delta" validate:"required"`
	RstButNoSession                       int64 `json:"rst_but_no_session" validate:"required"`
	RstButNoSessionDelta                  int64 `json:"rst_but_no_session_delta" validate:"required"`
	RstInvalidACK                         int64 `json:"rst_invalid_ack" validate:"required"`
	RstInvalidACKDelta                    int64 `json:"rst_invalid_ack_delta" validate:"required"`
	ShutdownSynResend                     int64 `json:"shutdown_syn_resend" validate:"required"`
	ShutdownSynResendDelta                int64 `json:"shutdown_syn_resend_delta" validate:"required"`
	SuspectedRstInject                    int64 `json:"suspected_rst_inject" validate:"required"`
	SuspectedRstInjectDelta               int64 `json:"suspected_rst_inject_delta" validate:"required"`
	TimewaitACKWrongSeq                   int64 `json:"timewait_ack_wrong_seq" validate:"required"`
	TimewaitACKWrongSeqDelta              int64 `json:"timewait_ack_wrong_seq_delta" validate:"required"`
	TimewaitInvalidACK                    int64 `json:"timewait_invalid_ack" validate:"required"`
	TimewaitInvalidACKDelta               int64 `json:"timewait_invalid_ack_delta" validate:"required"`
	WrongThread                           int64 `json:"wrong_thread" validate:"required"`
	WrongThreadDelta                      int64 `json:"wrong_thread_delta" validate:"required"`
}

type ThreadTCP struct {
	InsertDataNormalFail       *int64 `json:"insert_data_normal_fail,omitempty"`
	InsertDataNormalFailDelta  *int64 `json:"insert_data_normal_fail_delta,omitempty"`
	InsertDataOverlapFail      *int64 `json:"insert_data_overlap_fail,omitempty"`
	InsertDataOverlapFailDelta *int64 `json:"insert_data_overlap_fail_delta,omitempty"`
	InsertListFail             *int64 `json:"insert_list_fail,omitempty"`
	InsertListFailDelta        *int64 `json:"insert_list_fail_delta,omitempty"`
	InvalidChecksum            *int64 `json:"invalid_checksum,omitempty"`
	InvalidChecksumDelta       *int64 `json:"invalid_checksum_delta,omitempty"`
	Memuse                     *int64 `json:"memuse,omitempty"`
	MemuseDelta                *int64 `json:"memuse_delta,omitempty"`
	MidstreamPickups           *int64 `json:"midstream_pickups,omitempty"`
	MidstreamPickupsDelta      *int64 `json:"midstream_pickups_delta,omitempty"`
	NoFlow                     *int64 `json:"no_flow,omitempty"`
	NoFlowDelta                *int64 `json:"no_flow_delta,omitempty"`
	Overlap                    *int64 `json:"overlap,omitempty"`
	OverlapDelta               *int64 `json:"overlap_delta,omitempty"`
	OverlapDiffData            *int64 `json:"overlap_diff_data,omitempty"`
	OverlapDiffDataDelta       *int64 `json:"overlap_diff_data_delta,omitempty"`
	PktOnWrongThread           *int64 `json:"pkt_on_wrong_thread,omitempty"`
	PktOnWrongThreadDelta      *int64 `json:"pkt_on_wrong_thread_delta,omitempty"`
	Pseudo                     *int64 `json:"pseudo,omitempty"`
	PseudoDelta                *int64 `json:"pseudo_delta,omitempty"`
	PseudoFailed               *int64 `json:"pseudo_failed,omitempty"`
	PseudoFailedDelta          *int64 `json:"pseudo_failed_delta,omitempty"`
	ReassemblyGap              *int64 `json:"reassembly_gap,omitempty"`
	ReassemblyGapDelta         *int64 `json:"reassembly_gap_delta,omitempty"`
	ReassemblyMemuse           *int64 `json:"reassembly_memuse,omitempty"`
	ReassemblyMemuseDelta      *int64 `json:"reassembly_memuse_delta,omitempty"`
	Rst                        *int64 `json:"rst,omitempty"`
	RstDelta                   *int64 `json:"rst_delta,omitempty"`
	SegmentMemcapDrop          *int64 `json:"segment_memcap_drop,omitempty"`
	SegmentMemcapDropDelta     *int64 `json:"segment_memcap_drop_delta,omitempty"`
	Sessions                   *int64 `json:"sessions,omitempty"`
	SessionsDelta              *int64 `json:"sessions_delta,omitempty"`
	SsnMemcapDrop              *int64 `json:"ssn_memcap_drop,omitempty"`
	SsnMemcapDropDelta         *int64 `json:"ssn_memcap_drop_delta,omitempty"`
	StreamDepthReached         *int64 `json:"stream_depth_reached,omitempty"`
	StreamDepthReachedDelta    *int64 `json:"stream_depth_reached_delta,omitempty"`
	Syn                        *int64 `json:"syn,omitempty"`
	SynDelta                   *int64 `json:"syn_delta,omitempty"`
	Synack                     *int64 `json:"synack,omitempty"`
	SynackDelta                *int64 `json:"synack_delta,omitempty"`
}

type EveTCP struct {
	ACK        *bool   `json:"ack,omitempty"`
	Cwr        *bool   `json:"cwr,omitempty"`
	ECN        *bool   `json:"ecn,omitempty"`
	Fin        *bool   `json:"fin,omitempty"`
	Psh        *bool   `json:"psh,omitempty"`
	Rst        *bool   `json:"rst,omitempty"`
	State      *string `json:"state,omitempty"`
	Syn        *bool   `json:"syn,omitempty"`
	TCPFlags   string  `json:"tcp_flags" validate:"required"`
	TCPFlagsTc *string `json:"tcp_flags_tc,omitempty"`
	TCPFlagsTs *string `json:"tcp_flags_ts,omitempty"`
	Urg        *bool   `json:"urg,omitempty"`
}

type TFTP struct {
	File   string `json:"file" validate:"required"`
	Mode   string `json:"mode" validate:"required"`
	Packet string `json:"packet" validate:"required"`
}

type TLS struct {
	Fingerprint    *string `json:"fingerprint,omitempty"`
	FromProto      *string `json:"from_proto,omitempty"`
	Issuerdn       *string `json:"issuerdn,omitempty"`
	Ja3            Ja3     `json:"ja3" validate:"required"`
	Ja3S           Ja3S    `json:"ja3s" validate:"required"`
	Notafter       *string `json:"notafter,omitempty"`
	Notbefore      *string `json:"notbefore,omitempty"`
	Serial         *string `json:"serial,omitempty"`
	SessionResumed *bool   `json:"session_resumed,omitempty"`
	Sni            *string `json:"sni,omitempty"`
	Subject        *string `json:"subject,omitempty"`
	Version        string  `json:"version" validate:"required"`
}

type Ja3 struct {
	Hash   *string `json:"hash,omitempty"`
	String *string `json:"string,omitempty"`
}

type Ja3S struct {
	Hash   *string `json:"hash,omitempty"`
	String *string `json:"string,omitempty"`
}

type Tunnel struct {
	Depth    int64  `json:"depth" validate:"required"`
	DestIP   string `json:"dest_ip" validate:"required"`
	DestPort *int64 `json:"dest_port,omitempty"`
	Proto    string `json:"proto" validate:"required"`
	SrcIP    string `json:"src_ip" validate:"required"`
	SrcPort  *int64 `json:"src_port,omitempty"`
}

type Vars struct {
	Flowbits interface{} `json:"flowbits" validate:"required"`
	Flowints interface{} `json:"flowints" validate:"required"`
}
