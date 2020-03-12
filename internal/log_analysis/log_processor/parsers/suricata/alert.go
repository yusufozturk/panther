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

//nolint:lll
type Alert struct {
	Alert            *AlertDetails    `json:"alert" validate:"required,dive" description:"Suricata Alert Alert"`
	AppProto         *string          `json:"app_proto,omitempty" description:"Suricata Alert AppProto"`
	AppProtoOrig     *string          `json:"app_proto_orig,omitempty" description:"Suricata Alert AppProtoOrig"`
	AppProtoTc       *string          `json:"app_proto_tc,omitempty" description:"Suricata Alert AppProtoTc"`
	AppProtoTs       *string          `json:"app_proto_ts,omitempty" description:"Suricata Alert AppProtoTs"`
	CommunityID      *string          `json:"community_id,omitempty" description:"Suricata Alert CommunityID"`
	DNS              *AlertDNS        `json:"dns,omitempty" validate:"omitempty,dive" description:"Suricata Alert DNS"`
	DestIP           *string          `json:"dest_ip" validate:"required" description:"Suricata Alert DestIP"`
	DestPort         *int             `json:"dest_port,omitempty" description:"Suricata Alert DestPort"`
	Dnp3             *AlertDnp3       `json:"dnp3,omitempty" validate:"omitempty,dive" description:"Suricata Alert Dnp3"`
	Email            *AlertEmail      `json:"email,omitempty" validate:"omitempty,dive" description:"Suricata Alert Email"`
	EventType        *string          `json:"event_type" validate:"required" description:"Suricata Alert EventType"`
	Flow             *AlertFlow       `json:"flow,omitempty" validate:"omitempty,dive" description:"Suricata Alert Flow"`
	FlowID           *int             `json:"flow_id,omitempty" description:"Suricata Alert FlowID"`
	HTTP             *AlertHTTP       `json:"http,omitempty" validate:"omitempty,dive" description:"Suricata Alert HTTP"`
	IcmpCode         *int             `json:"icmp_code,omitempty" description:"Suricata Alert IcmpCode"`
	IcmpType         *int             `json:"icmp_type,omitempty" description:"Suricata Alert IcmpType"`
	Metadata         *AlertMetadata   `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata Alert Metadata"`
	Nfs              *AlertNfs        `json:"nfs,omitempty" validate:"omitempty,dive" description:"Suricata Alert Nfs"`
	Packet           *string          `json:"packet,omitempty" description:"Suricata Alert Packet"`
	PacketInfo       *AlertPacketInfo `json:"packet_info,omitempty" validate:"omitempty,dive" description:"Suricata Alert PacketInfo"`
	Payload          *string          `json:"payload,omitempty" description:"Suricata Alert Payload"`
	PayloadPrintable *string          `json:"payload_printable,omitempty" description:"Suricata Alert PayloadPrintable"`
	PcapCnt          *int             `json:"pcap_cnt,omitempty" description:"Suricata Alert PcapCnt"`
	PcapFilename     *string          `json:"pcap_filename,omitempty" description:"Suricata Alert PcapFilename"`
	Proto            *string          `json:"proto" validate:"required" description:"Suricata Alert Proto"`
	RPC              *AlertRPC        `json:"rpc,omitempty" validate:"omitempty,dive" description:"Suricata Alert RPC"`
	SIP              *AlertSIP        `json:"sip,omitempty" validate:"omitempty,dive" description:"Suricata Alert SIP"`
	SMTP             *AlertSMTP       `json:"smtp,omitempty" validate:"omitempty,dive" description:"Suricata Alert SMTP"`
	SSH              *AlertSSH        `json:"ssh,omitempty" validate:"omitempty,dive" description:"Suricata Alert SSH"`
	Smb              *AlertSmb        `json:"smb,omitempty" validate:"omitempty,dive" description:"Suricata Alert Smb"`
	SrcIP            *string          `json:"src_ip" validate:"required" description:"Suricata Alert SrcIP"`
	SrcPort          *int             `json:"src_port,omitempty" description:"Suricata Alert SrcPort"`
	Stream           *int             `json:"stream,omitempty" description:"Suricata Alert Stream"`
	TLS              *AlertTLS        `json:"tls,omitempty" validate:"omitempty,dive" description:"Suricata Alert TLS"`
	Timestamp        *string          `json:"timestamp" validate:"required" description:"Suricata Alert Timestamp"`
	Tunnel           *AlertTunnel     `json:"tunnel,omitempty" validate:"omitempty,dive" description:"Suricata Alert Tunnel"`
	TxID             *int             `json:"tx_id,omitempty" description:"Suricata Alert TxID"`
	Vlan             []int            `json:"vlan,omitempty" description:"Suricata Alert Vlan"`

	parsers.PantherLog
}

//nolint:lll
type AlertMetadata struct {
	Flowbits []string               `json:"flowbits,omitempty" description:"Suricata AlertMetadata Flowbits"`
	Flowints *AlertMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata AlertMetadata Flowints"`
}

//nolint:lll
type AlertMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty" description:"Suricata AlertMetadataFlowints ApplayerAnomalyCount"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty" description:"Suricata AlertMetadataFlowints HTTPAnomalyCount"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty" description:"Suricata AlertMetadataFlowints TCPRetransmissionCount"`
	TLSAnomalyCount        *int `json:"tls.anomaly.count,omitempty" description:"Suricata AlertMetadataFlowints TLSAnomalyCount"`
}

//nolint:lll
type AlertDetails struct {
	Action      *string               `json:"action,omitempty" description:"Suricata AlertDetails Action"`
	Category    *string               `json:"category,omitempty" description:"Suricata AlertDetails Category"`
	GID         *int                  `json:"gid,omitempty" description:"Suricata AlertDetails GID"`
	Metadata    *AlertDetailsMetadata `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata AlertDetails Metadata"`
	Rev         *int                  `json:"rev,omitempty" description:"Suricata AlertDetails Rev"`
	Severity    *int                  `json:"severity,omitempty" description:"Suricata AlertDetails Severity"`
	Signature   *string               `json:"signature,omitempty" description:"Suricata AlertDetails Signature"`
	SignatureID *int                  `json:"signature_id,omitempty" description:"Suricata AlertDetails SignatureID"`
}

//nolint:lll
type AlertDetailsMetadata struct {
	AffectedProduct   []string `json:"affected_product,omitempty" description:"Suricata AlertDetailsMetadata AffectedProduct"`
	AttackTarget      []string `json:"attack_target,omitempty" description:"Suricata AlertDetailsMetadata AttackTarget"`
	CreatedAt         []string `json:"created_at,omitempty" description:"Suricata AlertDetailsMetadata CreatedAt"`
	Deployment        []string `json:"deployment,omitempty" description:"Suricata AlertDetailsMetadata Deployment"`
	FormerCategory    []string `json:"former_category,omitempty" description:"Suricata AlertDetailsMetadata FormerCategory"`
	MalwareFamily     []string `json:"malware_family,omitempty" description:"Suricata AlertDetailsMetadata MalwareFamily"`
	PerformanceImpact []string `json:"performance_impact,omitempty" description:"Suricata AlertDetailsMetadata PerformanceImpact"`
	SignatureSeverity []string `json:"signature_severity,omitempty" description:"Suricata AlertDetailsMetadata SignatureSeverity"`
	Tag               []string `json:"tag,omitempty" description:"Suricata AlertDetailsMetadata Tag"`
	UpdatedAt         []string `json:"updated_at,omitempty" description:"Suricata AlertDetailsMetadata UpdatedAt"`
}

//nolint:lll
type AlertFlow struct {
	BytesToclient *int    `json:"bytes_toclient,omitempty" description:"Suricata AlertFlow BytesToclient"`
	BytesToserver *int    `json:"bytes_toserver,omitempty" description:"Suricata AlertFlow BytesToserver"`
	PktsToclient  *int    `json:"pkts_toclient,omitempty" description:"Suricata AlertFlow PktsToclient"`
	PktsToserver  *int    `json:"pkts_toserver,omitempty" description:"Suricata AlertFlow PktsToserver"`
	Start         *string `json:"start,omitempty" description:"Suricata AlertFlow Start"`
}

//nolint:lll
type AlertPacketInfo struct {
	Linktype *int `json:"linktype,omitempty" description:"Suricata AlertPacketInfo Linktype"`
}

//nolint:lll
type AlertSIP struct {
	Method      *string `json:"method,omitempty" description:"Suricata AlertSIP Method"`
	RequestLine *string `json:"request_line,omitempty" description:"Suricata AlertSIP RequestLine"`
	URI         *string `json:"uri,omitempty" description:"Suricata AlertSIP URI"`
	Version     *string `json:"version,omitempty" description:"Suricata AlertSIP Version"`
}

//nolint:lll
type AlertDNS struct {
	Query []AlertDNSQuery `json:"query,omitempty" validate:"omitempty,dive" description:"Suricata AlertDNS Query"`
}

//nolint:lll
type AlertDNSQuery struct {
	ID     *int    `json:"id,omitempty" description:"Suricata AlertDNSQuery ID"`
	Rrname *string `json:"rrname,omitempty" description:"Suricata AlertDNSQuery Rrname"`
	Rrtype *string `json:"rrtype,omitempty" description:"Suricata AlertDNSQuery Rrtype"`
	TxID   *int    `json:"tx_id,omitempty" description:"Suricata AlertDNSQuery TxID"`
	Type   *string `json:"type,omitempty" description:"Suricata AlertDNSQuery Type"`
}

//nolint:lll
type AlertHTTP struct {
	ContentRange              *AlertHTTPContentRange `json:"content_range,omitempty" validate:"omitempty,dive" description:"Suricata AlertHTTP ContentRange"`
	HTTPContentType           *string                `json:"http_content_type,omitempty" description:"Suricata AlertHTTP HTTPContentType"`
	HTTPMethod                *string                `json:"http_method,omitempty" description:"Suricata AlertHTTP HTTPMethod"`
	HTTPPort                  *int                   `json:"http_port,omitempty" description:"Suricata AlertHTTP HTTPPort"`
	HTTPRefer                 *string                `json:"http_refer,omitempty" description:"Suricata AlertHTTP HTTPRefer"`
	HTTPRequestBody           *string                `json:"http_request_body,omitempty" description:"Suricata AlertHTTP HTTPRequestBody"`
	HTTPRequestBodyPrintable  *string                `json:"http_request_body_printable,omitempty" description:"Suricata AlertHTTP HTTPRequestBodyPrintable"`
	HTTPResponseBody          *string                `json:"http_response_body,omitempty" description:"Suricata AlertHTTP HTTPResponseBody"`
	HTTPResponseBodyPrintable *string                `json:"http_response_body_printable,omitempty" description:"Suricata AlertHTTP HTTPResponseBodyPrintable"`
	HTTPUserAgent             *string                `json:"http_user_agent,omitempty" description:"Suricata AlertHTTP HTTPUserAgent"`
	Hostname                  *string                `json:"hostname,omitempty" description:"Suricata AlertHTTP Hostname"`
	Length                    *int                   `json:"length,omitempty" description:"Suricata AlertHTTP Length"`
	Protocol                  *string                `json:"protocol,omitempty" description:"Suricata AlertHTTP Protocol"`
	Redirect                  *string                `json:"redirect,omitempty" description:"Suricata AlertHTTP Redirect"`
	Status                    *int                   `json:"status,omitempty" description:"Suricata AlertHTTP Status"`
	URL                       *string                `json:"url,omitempty" description:"Suricata AlertHTTP URL"`
}

//nolint:lll
type AlertHTTPContentRange struct {
	End   *int    `json:"end,omitempty" description:"Suricata AlertHTTPContentRange End"`
	Raw   *string `json:"raw,omitempty" description:"Suricata AlertHTTPContentRange Raw"`
	Size  *int    `json:"size,omitempty" description:"Suricata AlertHTTPContentRange Size"`
	Start *int    `json:"start,omitempty" description:"Suricata AlertHTTPContentRange Start"`
}

//nolint:lll
type AlertSmb struct {
	ClientDialects []string `json:"client_dialects,omitempty" description:"Suricata AlertSmb ClientDialects"`
	ClientGUID     *string  `json:"client_guid,omitempty" description:"Suricata AlertSmb ClientGUID"`
	Command        *string  `json:"command,omitempty" description:"Suricata AlertSmb Command"`
	Dialect        *string  `json:"dialect,omitempty" description:"Suricata AlertSmb Dialect"`
	Filename       *string  `json:"filename,omitempty" description:"Suricata AlertSmb Filename"`
	Fuid           *string  `json:"fuid,omitempty" description:"Suricata AlertSmb Fuid"`
	ID             *int     `json:"id,omitempty" description:"Suricata AlertSmb ID"`
	ServerGUID     *string  `json:"server_guid,omitempty" description:"Suricata AlertSmb ServerGUID"`
	SessionID      *int     `json:"session_id,omitempty" description:"Suricata AlertSmb SessionID"`
	Share          *string  `json:"share,omitempty" description:"Suricata AlertSmb Share"`
	Status         *string  `json:"status,omitempty" description:"Suricata AlertSmb Status"`
	StatusCode     *string  `json:"status_code,omitempty" description:"Suricata AlertSmb StatusCode"`
	TreeID         *int     `json:"tree_id,omitempty" description:"Suricata AlertSmb TreeID"`
}

//nolint:lll
type AlertTLS struct {
	Fingerprint    *string       `json:"fingerprint,omitempty" description:"Suricata AlertTLS Fingerprint"`
	Issuerdn       *string       `json:"issuerdn,omitempty" description:"Suricata AlertTLS Issuerdn"`
	Ja3            *AlertTLSJa3  `json:"ja3,omitempty" validate:"omitempty,dive" description:"Suricata AlertTLS Ja3"`
	Ja3S           *AlertTLSJa3S `json:"ja3s,omitempty" validate:"omitempty,dive" description:"Suricata AlertTLS Ja3S"`
	Notafter       *string       `json:"notafter,omitempty" description:"Suricata AlertTLS Notafter"`
	Notbefore      *string       `json:"notbefore,omitempty" description:"Suricata AlertTLS Notbefore"`
	Serial         *string       `json:"serial,omitempty" description:"Suricata AlertTLS Serial"`
	SessionResumed *bool         `json:"session_resumed,omitempty" description:"Suricata AlertTLS SessionResumed"`
	Sni            *string       `json:"sni,omitempty" description:"Suricata AlertTLS Sni"`
	Subject        *string       `json:"subject,omitempty" description:"Suricata AlertTLS Subject"`
	Version        *string       `json:"version,omitempty" description:"Suricata AlertTLS Version"`
}

//nolint:lll
type AlertTLSJa3 struct {
	Hash   *string `json:"hash,omitempty" description:"Suricata AlertTLSJa3 Hash"`
	String *string `json:"string,omitempty" description:"Suricata AlertTLSJa3 String"`
}

//nolint:lll
type AlertTLSJa3S struct {
	Hash   *string `json:"hash,omitempty" description:"Suricata AlertTLSJa3S Hash"`
	String *string `json:"string,omitempty" description:"Suricata AlertTLSJa3S String"`
}

//nolint:lll
type AlertTunnel struct {
	Depth    *int    `json:"depth,omitempty" description:"Suricata AlertTunnel Depth"`
	DestIP   *string `json:"dest_ip,omitempty" description:"Suricata AlertTunnel DestIP"`
	DestPort *int    `json:"dest_port,omitempty" description:"Suricata AlertTunnel DestPort"`
	Proto    *string `json:"proto,omitempty" description:"Suricata AlertTunnel Proto"`
	SrcIP    *string `json:"src_ip,omitempty" description:"Suricata AlertTunnel SrcIP"`
	SrcPort  *int    `json:"src_port,omitempty" description:"Suricata AlertTunnel SrcPort"`
}

//nolint:lll
type AlertSSH struct {
	Client *AlertSSHClient `json:"client,omitempty" validate:"omitempty,dive" description:"Suricata AlertSSH Client"`
	Server *AlertSSHServer `json:"server,omitempty" validate:"omitempty,dive" description:"Suricata AlertSSH Server"`
}

//nolint:lll
type AlertSSHClient struct {
	ProtoVersion    *string `json:"proto_version,omitempty" description:"Suricata AlertSSHClient ProtoVersion"`
	SoftwareVersion *string `json:"software_version,omitempty" description:"Suricata AlertSSHClient SoftwareVersion"`
}

//nolint:lll
type AlertSSHServer struct {
	ProtoVersion    *string `json:"proto_version,omitempty" description:"Suricata AlertSSHServer ProtoVersion"`
	SoftwareVersion *string `json:"software_version,omitempty" description:"Suricata AlertSSHServer SoftwareVersion"`
}

//nolint:lll
type AlertSMTP struct {
	Helo     *string  `json:"helo,omitempty" description:"Suricata AlertSMTP Helo"`
	MailFrom *string  `json:"mail_from,omitempty" description:"Suricata AlertSMTP MailFrom"`
	RcptTo   []string `json:"rcpt_to,omitempty" description:"Suricata AlertSMTP RcptTo"`
}

//nolint:lll
type AlertEmail struct {
	From   *string  `json:"from,omitempty" description:"Suricata AlertEmail From"`
	Status *string  `json:"status,omitempty" description:"Suricata AlertEmail Status"`
	To     []string `json:"to,omitempty" description:"Suricata AlertEmail To"`
}

//nolint:lll
type AlertDnp3 struct {
	Request  *AlertDnp3Request  `json:"request,omitempty" validate:"omitempty,dive" description:"Suricata AlertDnp3 Request"`
	Response *AlertDnp3Response `json:"response,omitempty" validate:"omitempty,dive" description:"Suricata AlertDnp3 Response"`
}

//nolint:lll
type AlertDnp3Request struct {
	Application *jsoniter.RawMessage `json:"application,omitempty" description:"Suricata AlertDnp3Request Application"`
	Control     *jsoniter.RawMessage `json:"control,omitempty" description:"Suricata AlertDnp3Request Control"`
	Dst         *int                 `json:"dst,omitempty" description:"Suricata AlertDnp3Request Dst"`
	Src         *int                 `json:"src,omitempty" description:"Suricata AlertDnp3Request Src"`
	Type        *string              `json:"type,omitempty" description:"Suricata AlertDnp3Request Type"`
}

//nolint:lll
type AlertDnp3Response struct {
	Application *jsoniter.RawMessage `json:"application,omitempty" description:"Suricata AlertDnp3Response Application"`
	Control     *jsoniter.RawMessage `json:"control,omitempty" description:"Suricata AlertDnp3Response Control"`
	Dst         *int                 `json:"dst,omitempty" description:"Suricata AlertDnp3Response Dst"`
	Iin         *jsoniter.RawMessage `json:"iin,omitempty" description:"Suricata AlertDnp3Response Iin"`
	Src         *int                 `json:"src,omitempty" description:"Suricata AlertDnp3Response Src"`
	Type        *string              `json:"type,omitempty" description:"Suricata AlertDnp3Response Type"`
}

//nolint:lll
type AlertRPC struct {
	AuthType *string `json:"auth_type,omitempty" description:"Suricata AlertRPC AuthType"`
	Status   *string `json:"status,omitempty" description:"Suricata AlertRPC Status"`
	Xid      *int    `json:"xid,omitempty" description:"Suricata AlertRPC Xid"`
}

//nolint:lll
type AlertNfs struct {
	FileTx    *bool   `json:"file_tx,omitempty" description:"Suricata AlertNfs FileTx"`
	Filename  *string `json:"filename,omitempty" description:"Suricata AlertNfs Filename"`
	ID        *int    `json:"id,omitempty" description:"Suricata AlertNfs ID"`
	Procedure *string `json:"procedure,omitempty" description:"Suricata AlertNfs Procedure"`
	Status    *string `json:"status,omitempty" description:"Suricata AlertNfs Status"`
	Type      *string `json:"type,omitempty" description:"Suricata AlertNfs Type"`
	Version   *int    `json:"version,omitempty" description:"Suricata AlertNfs Version"`
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
