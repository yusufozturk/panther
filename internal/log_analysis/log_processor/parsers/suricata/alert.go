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
	"time"

	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var AlertDesc = `Suricata parser for the Alert event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Alert struct {
	Alert            *AlertDetails    `json:"alert" validate:"required,dive"`
	AppProto         *string          `json:"app_proto,omitempty"`
	AppProtoOrig     *string          `json:"app_proto_orig,omitempty"`
	AppProtoTc       *string          `json:"app_proto_tc,omitempty"`
	AppProtoTs       *string          `json:"app_proto_ts,omitempty"`
	CommunityID      *string          `json:"community_id,omitempty"`
	DNS              *AlertDNS        `json:"dns,omitempty" validate:"omitempty,dive"`
	DestIP           *string          `json:"dest_ip" validate:"required"`
	DestPort         *int             `json:"dest_port,omitempty"`
	Dnp3             *AlertDnp3       `json:"dnp3,omitempty" validate:"omitempty,dive"`
	Email            *AlertEmail      `json:"email,omitempty" validate:"omitempty,dive"`
	EventType        *string          `json:"event_type" validate:"required"`
	Flow             *AlertFlow       `json:"flow,omitempty" validate:"omitempty,dive"`
	FlowID           *int             `json:"flow_id,omitempty"`
	HTTP             *AlertHTTP       `json:"http,omitempty" validate:"omitempty,dive"`
	IcmpCode         *int             `json:"icmp_code,omitempty"`
	IcmpType         *int             `json:"icmp_type,omitempty"`
	Metadata         *AlertMetadata   `json:"metadata,omitempty" validate:"omitempty,dive"`
	Nfs              *AlertNfs        `json:"nfs,omitempty" validate:"omitempty,dive"`
	Packet           *string          `json:"packet" validate:"required"`
	PacketInfo       *AlertPacketInfo `json:"packet_info" validate:"required,dive"`
	Payload          *string          `json:"payload,omitempty"`
	PayloadPrintable *string          `json:"payload_printable,omitempty"`
	PcapCnt          *int             `json:"pcap_cnt,omitempty"`
	PcapFilename     *string          `json:"pcap_filename" validate:"required"`
	Proto            *string          `json:"proto" validate:"required"`
	RPC              *AlertRPC        `json:"rpc,omitempty" validate:"omitempty,dive"`
	SIP              *AlertSIP        `json:"sip,omitempty" validate:"omitempty,dive"`
	SMTP             *AlertSMTP       `json:"smtp,omitempty" validate:"omitempty,dive"`
	SSH              *AlertSSH        `json:"ssh,omitempty" validate:"omitempty,dive"`
	Smb              *AlertSmb        `json:"smb,omitempty" validate:"omitempty,dive"`
	SrcIP            *string          `json:"src_ip" validate:"required"`
	SrcPort          *int             `json:"src_port,omitempty"`
	Stream           *int             `json:"stream" validate:"required"`
	TLS              *AlertTLS        `json:"tls,omitempty" validate:"omitempty,dive"`
	Timestamp        *string          `json:"timestamp" validate:"required"`
	Tunnel           *AlertTunnel     `json:"tunnel,omitempty" validate:"omitempty,dive"`
	TxID             *int             `json:"tx_id,omitempty"`
	Vlan             []int            `json:"vlan,omitempty"`

	parsers.PantherLog
}

type AlertMetadata struct {
	Flowbits []string               `json:"flowbits,omitempty"`
	Flowints *AlertMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive"`
}

type AlertMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty"`
	TLSAnomalyCount        *int `json:"tls.anomaly.count,omitempty"`
}

type AlertDetails struct {
	Action      *string               `json:"action" validate:"required"`
	Category    *string               `json:"category" validate:"required"`
	GID         *int                  `json:"gid" validate:"required"`
	Metadata    *AlertDetailsMetadata `json:"metadata,omitempty" validate:"omitempty,dive"`
	Rev         *int                  `json:"rev" validate:"required"`
	Severity    *int                  `json:"severity" validate:"required"`
	Signature   *string               `json:"signature" validate:"required"`
	SignatureID *int                  `json:"signature_id" validate:"required"`
}

type AlertDetailsMetadata struct {
	AffectedProduct   []string `json:"affected_product,omitempty"`
	AttackTarget      []string `json:"attack_target,omitempty"`
	CreatedAt         []string `json:"created_at" validate:"required"`
	Deployment        []string `json:"deployment,omitempty"`
	FormerCategory    []string `json:"former_category,omitempty"`
	MalwareFamily     []string `json:"malware_family,omitempty"`
	PerformanceImpact []string `json:"performance_impact,omitempty"`
	SignatureSeverity []string `json:"signature_severity,omitempty"`
	Tag               []string `json:"tag,omitempty"`
	UpdatedAt         []string `json:"updated_at" validate:"required"`
}

type AlertFlow struct {
	BytesToclient *int    `json:"bytes_toclient" validate:"required"`
	BytesToserver *int    `json:"bytes_toserver" validate:"required"`
	PktsToclient  *int    `json:"pkts_toclient" validate:"required"`
	PktsToserver  *int    `json:"pkts_toserver" validate:"required"`
	Start         *string `json:"start" validate:"required"`
}

type AlertPacketInfo struct {
	Linktype *int `json:"linktype" validate:"required"`
}

type AlertSIP struct {
	Method      *string `json:"method" validate:"required"`
	RequestLine *string `json:"request_line" validate:"required"`
	URI         *string `json:"uri" validate:"required"`
	Version     *string `json:"version" validate:"required"`
}

type AlertDNS struct {
	Query []AlertDNSQuery `json:"query" validate:"required,dive"`
}

type AlertDNSQuery struct {
	ID     *int    `json:"id" validate:"required"`
	Rrname *string `json:"rrname" validate:"required"`
	Rrtype *string `json:"rrtype" validate:"required"`
	TxID   *int    `json:"tx_id" validate:"required"`
	Type   *string `json:"type" validate:"required"`
}

type AlertHTTP struct {
	ContentRange              *AlertHTTPContentRange `json:"content_range,omitempty" validate:"omitempty,dive"`
	HTTPContentType           *string                `json:"http_content_type,omitempty"`
	HTTPMethod                *string                `json:"http_method,omitempty"`
	HTTPPort                  *int                   `json:"http_port,omitempty"`
	HTTPRefer                 *string                `json:"http_refer,omitempty"`
	HTTPRequestBody           *string                `json:"http_request_body,omitempty"`
	HTTPRequestBodyPrintable  *string                `json:"http_request_body_printable,omitempty"`
	HTTPResponseBody          *string                `json:"http_response_body,omitempty"`
	HTTPResponseBodyPrintable *string                `json:"http_response_body_printable,omitempty"`
	HTTPUserAgent             *string                `json:"http_user_agent,omitempty"`
	Hostname                  *string                `json:"hostname,omitempty"`
	Length                    *int                   `json:"length" validate:"required"`
	Protocol                  *string                `json:"protocol,omitempty"`
	Redirect                  *string                `json:"redirect,omitempty"`
	Status                    *int                   `json:"status,omitempty"`
	URL                       *string                `json:"url,omitempty"`
}

type AlertHTTPContentRange struct {
	End   *int    `json:"end,omitempty"`
	Raw   *string `json:"raw" validate:"required"`
	Size  *int    `json:"size,omitempty"`
	Start *int    `json:"start,omitempty"`
}

type AlertSmb struct {
	ClientDialects []string `json:"client_dialects,omitempty"`
	ClientGUID     *string  `json:"client_guid,omitempty"`
	Command        *string  `json:"command" validate:"required"`
	Dialect        *string  `json:"dialect" validate:"required"`
	Filename       *string  `json:"filename,omitempty"`
	Fuid           *string  `json:"fuid,omitempty"`
	ID             *int     `json:"id" validate:"required"`
	ServerGUID     *string  `json:"server_guid,omitempty"`
	SessionID      *int     `json:"session_id" validate:"required"`
	Share          *string  `json:"share,omitempty"`
	Status         *string  `json:"status,omitempty"`
	StatusCode     *string  `json:"status_code,omitempty"`
	TreeID         *int     `json:"tree_id" validate:"required"`
}

type AlertTLS struct {
	Fingerprint    *string       `json:"fingerprint,omitempty"`
	Issuerdn       *string       `json:"issuerdn,omitempty"`
	Ja3            *AlertTLSJa3  `json:"ja3" validate:"required,dive"`
	Ja3S           *AlertTLSJa3S `json:"ja3s" validate:"required,dive"`
	Notafter       *string       `json:"notafter,omitempty"`
	Notbefore      *string       `json:"notbefore,omitempty"`
	Serial         *string       `json:"serial,omitempty"`
	SessionResumed *bool         `json:"session_resumed,omitempty"`
	Sni            *string       `json:"sni,omitempty"`
	Subject        *string       `json:"subject,omitempty"`
	Version        *string       `json:"version" validate:"required"`
}

type AlertTLSJa3 struct {
	Hash   *string `json:"hash,omitempty"`
	String *string `json:"string,omitempty"`
}

type AlertTLSJa3S struct {
	Hash   *string `json:"hash,omitempty"`
	String *string `json:"string,omitempty"`
}

type AlertTunnel struct {
	Depth    *int    `json:"depth" validate:"required"`
	DestIP   *string `json:"dest_ip" validate:"required"`
	DestPort *int    `json:"dest_port,omitempty"`
	Proto    *string `json:"proto" validate:"required"`
	SrcIP    *string `json:"src_ip" validate:"required"`
	SrcPort  *int    `json:"src_port,omitempty"`
}

type AlertSSH struct {
	Client *AlertSSHClient `json:"client" validate:"required,dive"`
	Server *AlertSSHServer `json:"server" validate:"required,dive"`
}

type AlertSSHClient struct {
	ProtoVersion    *string `json:"proto_version,omitempty"`
	SoftwareVersion *string `json:"software_version,omitempty"`
}

type AlertSSHServer struct {
	ProtoVersion    *string `json:"proto_version,omitempty"`
	SoftwareVersion *string `json:"software_version,omitempty"`
}

type AlertSMTP struct {
	Helo     *string  `json:"helo" validate:"required"`
	MailFrom *string  `json:"mail_from,omitempty"`
	RcptTo   []string `json:"rcpt_to,omitempty"`
}

type AlertEmail struct {
	From   *string  `json:"from" validate:"required"`
	Status *string  `json:"status" validate:"required"`
	To     []string `json:"to" validate:"required"`
}

type AlertDnp3 struct {
	Request  *AlertDnp3Request  `json:"request,omitempty" validate:"omitempty,dive"`
	Response *AlertDnp3Response `json:"response,omitempty" validate:"omitempty,dive"`
}

type AlertDnp3Request struct {
	Application *AlertDnp3RequestApplication `json:"application" validate:"required,dive"`
	Control     *AlertDnp3RequestControl     `json:"control" validate:"required,dive"`
	Dst         *int                         `json:"dst" validate:"required"`
	Src         *int                         `json:"src" validate:"required"`
	Type        *string                      `json:"type" validate:"required"`
}

type AlertDnp3RequestControl struct {
	Dir          *bool `json:"dir" validate:"required"`
	Fcb          *bool `json:"fcb" validate:"required"`
	Fcv          *bool `json:"fcv" validate:"required"`
	FunctionCode *int  `json:"function_code" validate:"required"`
	Pri          *bool `json:"pri" validate:"required"`
}

type AlertDnp3RequestApplication struct {
	Complete     *bool                                `json:"complete" validate:"required"`
	Control      *AlertDnp3RequestApplicationControl  `json:"control" validate:"required,dive"`
	FunctionCode *int                                 `json:"function_code" validate:"required"`
	Objects      []AlertDnp3RequestApplicationObjects `json:"objects" validate:"required,dive"`
}

type AlertDnp3RequestApplicationControl struct {
	Con      *bool `json:"con" validate:"required"`
	Fin      *bool `json:"fin" validate:"required"`
	Fir      *bool `json:"fir" validate:"required"`
	Sequence *int  `json:"sequence" validate:"required"`
	Uns      *bool `json:"uns" validate:"required"`
}

type AlertDnp3RequestApplicationObjects struct {
	Count      *int                                       `json:"count" validate:"required"`
	Group      *int                                       `json:"group" validate:"required"`
	Points     []AlertDnp3RequestApplicationObjectsPoints `json:"points,omitempty" validate:"omitempty,dive"`
	PrefixCode *int                                       `json:"prefix_code" validate:"required"`
	Qualifier  *int                                       `json:"qualifier" validate:"required"`
	RangeCode  *int                                       `json:"range_code" validate:"required"`
	Start      *int                                       `json:"start" validate:"required"`
	Stop       *int                                       `json:"stop" validate:"required"`
	Variation  *int                                       `json:"variation" validate:"required"`
}

type AlertDnp3RequestApplicationObjectsPoints struct {
	Count      *int `json:"count,omitempty"`
	Cr         *int `json:"cr,omitempty"`
	Index      *int `json:"index" validate:"required"`
	Offtime    *int `json:"offtime,omitempty"`
	Ontime     *int `json:"ontime,omitempty"`
	OpType     *int `json:"op_type,omitempty"`
	Prefix     *int `json:"prefix" validate:"required"`
	Qu         *int `json:"qu,omitempty"`
	Reserved   *int `json:"reserved,omitempty"`
	StatusCode *int `json:"status_code,omitempty"`
	Tcc        *int `json:"tcc,omitempty"`
	Timestamp  *int `json:"timestamp,omitempty"`
}

type AlertDnp3Response struct {
	Application *AlertDnp3ResponseApplication `json:"application" validate:"required,dive"`
	Control     *AlertDnp3ResponseControl     `json:"control" validate:"required,dive"`
	Dst         *int                          `json:"dst" validate:"required"`
	Iin         *AlertDnp3ResponseIin         `json:"iin" validate:"required,dive"`
	Src         *int                          `json:"src" validate:"required"`
	Type        *string                       `json:"type" validate:"required"`
}

type AlertDnp3ResponseControl struct {
	Dir          *bool `json:"dir" validate:"required"`
	Fcb          *bool `json:"fcb" validate:"required"`
	Fcv          *bool `json:"fcv" validate:"required"`
	FunctionCode *int  `json:"function_code" validate:"required"`
	Pri          *bool `json:"pri" validate:"required"`
}

type AlertDnp3ResponseApplication struct {
	Complete     *bool                                `json:"complete" validate:"required"`
	Control      *AlertDnp3ResponseApplicationControl `json:"control" validate:"required,dive"`
	FunctionCode *int                                 `json:"function_code" validate:"required"`
	Objects      []string                             `json:"objects" validate:"required"`
}

type AlertDnp3ResponseApplicationControl struct {
	Con      *bool `json:"con" validate:"required"`
	Fin      *bool `json:"fin" validate:"required"`
	Fir      *bool `json:"fir" validate:"required"`
	Sequence *int  `json:"sequence" validate:"required"`
	Uns      *bool `json:"uns" validate:"required"`
}

type AlertDnp3ResponseIin struct {
	Indicators []string `json:"indicators" validate:"required"`
}

type AlertRPC struct {
	AuthType *string `json:"auth_type" validate:"required"`
	Status   *string `json:"status" validate:"required"`
	Xid      *int    `json:"xid" validate:"required"`
}

type AlertNfs struct {
	FileTx    *bool   `json:"file_tx" validate:"required"`
	Filename  *string `json:"filename" validate:"required"`
	ID        *int    `json:"id" validate:"required"`
	Procedure *string `json:"procedure" validate:"required"`
	Status    *string `json:"status" validate:"required"`
	Type      *string `json:"type" validate:"required"`
	Version   *int    `json:"version" validate:"required"`
}

// AlertParser parses Suricata Alert alerts in the JSON format
type AlertParser struct{}

func (p *AlertParser) New() parsers.LogParser {
	return &AlertParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *AlertParser) Parse(log string) []interface{} {
	event := &Alert{}

	err := jsoniter.UnmarshalFromString(log, event)
	if err != nil {
		zap.L().Debug("failed to parse log", zap.Error(err))
		return nil
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *AlertParser) LogType() string {
	return "Suricata.Alert"
}

func (event *Alert) updatePantherFields(p *AlertParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
