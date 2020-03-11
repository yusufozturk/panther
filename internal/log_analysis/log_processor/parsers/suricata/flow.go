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

var FlowDesc = `Suricata parser for the Flow event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Flow struct {
	AppProto         *string       `json:"app_proto,omitempty"`
	AppProtoOrig     *string       `json:"app_proto_orig,omitempty"`
	AppProtoTc       *string       `json:"app_proto_tc,omitempty"`
	AppProtoTs       *string       `json:"app_proto_ts,omitempty"`
	CommunityID      *string       `json:"community_id" validate:"required"`
	DestIP           *string       `json:"dest_ip" validate:"required"`
	DestPort         *int          `json:"dest_port,omitempty"`
	EventType        *string       `json:"event_type" validate:"required"`
	Flow             *FlowDetails  `json:"flow" validate:"required,dive"`
	FlowID           *int          `json:"flow_id" validate:"required"`
	IcmpCode         *int          `json:"icmp_code,omitempty"`
	IcmpType         *int          `json:"icmp_type,omitempty"`
	Metadata         *FlowMetadata `json:"metadata,omitempty" validate:"omitempty,dive"`
	PcapFilename     *string       `json:"pcap_filename" validate:"required"`
	Proto            *string       `json:"proto" validate:"required"`
	ResponseIcmpCode *int          `json:"response_icmp_code,omitempty"`
	ResponseIcmpType *int          `json:"response_icmp_type,omitempty"`
	SrcIP            *string       `json:"src_ip" validate:"required"`
	SrcPort          *int          `json:"src_port,omitempty"`
	TCP              *FlowTCP      `json:"tcp,omitempty" validate:"omitempty,dive"`
	Timestamp        *string       `json:"timestamp" validate:"required"`
	Vlan             []int         `json:"vlan,omitempty"`

	parsers.PantherLog
}

type FlowDetails struct {
	Age           *int    `json:"age" validate:"required"`
	Alerted       *bool   `json:"alerted" validate:"required"`
	BytesToclient *int    `json:"bytes_toclient" validate:"required"`
	BytesToserver *int    `json:"bytes_toserver" validate:"required"`
	Emergency     *bool   `json:"emergency,omitempty"`
	End           *string `json:"end" validate:"required"`
	PktsToclient  *int    `json:"pkts_toclient" validate:"required"`
	PktsToserver  *int    `json:"pkts_toserver" validate:"required"`
	Reason        *string `json:"reason" validate:"required"`
	Start         *string `json:"start" validate:"required"`
	State         *string `json:"state" validate:"required"`
}

type FlowTCP struct {
	Ack        *bool   `json:"ack,omitempty"`
	Cwr        *bool   `json:"cwr,omitempty"`
	Ecn        *bool   `json:"ecn,omitempty"`
	Fin        *bool   `json:"fin,omitempty"`
	Psh        *bool   `json:"psh,omitempty"`
	Rst        *bool   `json:"rst,omitempty"`
	State      *string `json:"state,omitempty"`
	Syn        *bool   `json:"syn,omitempty"`
	TCPFlags   *string `json:"tcp_flags" validate:"required"`
	TCPFlagsTc *string `json:"tcp_flags_tc" validate:"required"`
	TCPFlagsTs *string `json:"tcp_flags_ts" validate:"required"`
	Urg        *bool   `json:"urg,omitempty"`
}

type FlowMetadata struct {
	Flowbits []string              `json:"flowbits,omitempty"`
	Flowints *FlowMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive"`
}

type FlowMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty"`
	TLSAnomalyCount        *int `json:"tls.anomaly.count,omitempty"`
}

// FlowParser parses Suricata Flow alerts in the JSON format
type FlowParser struct{}

func (p *FlowParser) New() parsers.LogParser {
	return &FlowParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *FlowParser) Parse(log string) []interface{} {
	event := &Flow{}

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
func (p *FlowParser) LogType() string {
	return "Suricata.Flow"
}

func (event *Flow) updatePantherFields(p *FlowParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
