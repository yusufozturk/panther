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
	Alert            *AlertDetails        `json:"alert" validate:"required,dive" description:"Suricata Alert Alert"`
	AppProto         *string              `json:"app_proto,omitempty" description:"Suricata Alert AppProto"`
	AppProtoOrig     *string              `json:"app_proto_orig,omitempty" description:"Suricata Alert AppProtoOrig"`
	AppProtoTc       *string              `json:"app_proto_tc,omitempty" description:"Suricata Alert AppProtoTc"`
	AppProtoTs       *string              `json:"app_proto_ts,omitempty" description:"Suricata Alert AppProtoTs"`
	CommunityID      *string              `json:"community_id,omitempty" description:"Suricata Alert CommunityID"`
	DNS              *jsoniter.RawMessage `json:"dns,omitempty" description:"Suricata Alert DNS"`
	DestIP           *string              `json:"dest_ip" validate:"required" description:"Suricata Alert DestIP"`
	DestPort         *int                 `json:"dest_port,omitempty" description:"Suricata Alert DestPort"`
	Dnp3             *jsoniter.RawMessage `json:"dnp3,omitempty" description:"Suricata Alert Dnp3"`
	Email            *jsoniter.RawMessage `json:"email,omitempty" description:"Suricata Alert Email"`
	EventType        *string              `json:"event_type" validate:"required,eq=alert" description:"Suricata Alert EventType"`
	Flow             *jsoniter.RawMessage `json:"flow,omitempty" description:"Suricata Alert Flow"`
	FlowID           *int                 `json:"flow_id,omitempty" description:"Suricata Alert FlowID"`
	HTTP             *jsoniter.RawMessage `json:"http,omitempty" description:"Suricata Alert HTTP"`
	IcmpCode         *int                 `json:"icmp_code,omitempty" description:"Suricata Alert IcmpCode"`
	IcmpType         *int                 `json:"icmp_type,omitempty" description:"Suricata Alert IcmpType"`
	Metadata         *AlertMetadata       `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata Alert Metadata"`
	Nfs              *jsoniter.RawMessage `json:"nfs,omitempty" description:"Suricata Alert Nfs"`
	Packet           *string              `json:"packet,omitempty" description:"Suricata Alert Packet"`
	PacketInfo       *AlertPacketInfo     `json:"packet_info,omitempty" validate:"omitempty,dive" description:"Suricata Alert PacketInfo"`
	Payload          *string              `json:"payload,omitempty" description:"Suricata Alert Payload"`
	PayloadPrintable *string              `json:"payload_printable,omitempty" description:"Suricata Alert PayloadPrintable"`
	PcapCnt          *int                 `json:"pcap_cnt,omitempty" description:"Suricata Alert PcapCnt"`
	PcapFilename     *string              `json:"pcap_filename,omitempty" description:"Suricata Alert PcapFilename"`
	Proto            *string              `json:"proto" validate:"required" description:"Suricata Alert Proto"`
	RPC              *jsoniter.RawMessage `json:"rpc,omitempty" description:"Suricata Alert RPC"`
	SIP              *jsoniter.RawMessage `json:"sip,omitempty" description:"Suricata Alert SIP"`
	SMTP             *jsoniter.RawMessage `json:"smtp,omitempty" description:"Suricata Alert SMTP"`
	SSH              *jsoniter.RawMessage `json:"ssh,omitempty" description:"Suricata Alert SSH"`
	Smb              *jsoniter.RawMessage `json:"smb,omitempty" description:"Suricata Alert Smb"`
	SrcIP            *string              `json:"src_ip" validate:"required" description:"Suricata Alert SrcIP"`
	SrcPort          *int                 `json:"src_port,omitempty" description:"Suricata Alert SrcPort"`
	Stream           *int                 `json:"stream,omitempty" description:"Suricata Alert Stream"`
	TLS              *jsoniter.RawMessage `json:"tls,omitempty" description:"Suricata Alert TLS"`
	Timestamp        *string              `json:"timestamp" validate:"required" description:"Suricata Alert Timestamp"`
	Tunnel           *jsoniter.RawMessage `json:"tunnel,omitempty" description:"Suricata Alert Tunnel"`
	TxID             *int                 `json:"tx_id,omitempty" description:"Suricata Alert TxID"`
	Vlan             []int                `json:"vlan,omitempty" description:"Suricata Alert Vlan"`

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
type AlertPacketInfo struct {
	Linktype *int `json:"linktype,omitempty" description:"Suricata AlertPacketInfo Linktype"`
}

// AlertParser parses Suricata Alert alerts in the JSON format
type AlertParser struct{}

func (p *AlertParser) New() parsers.LogParser {
	return &AlertParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *AlertParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *AlertParser) LogType() string {
	return "Suricata.Alert"
}

func (event *Alert) updatePantherFields(p *AlertParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
