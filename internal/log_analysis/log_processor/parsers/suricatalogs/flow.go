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
	"time"

	jsoniter "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var FlowDesc = `Suricata parser for the Flow event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type Flow struct {
	AppProto         *string       `json:"app_proto,omitempty" description:"Suricata Flow AppProto"`
	AppProtoOrig     *string       `json:"app_proto_orig,omitempty" description:"Suricata Flow AppProtoOrig"`
	AppProtoTc       *string       `json:"app_proto_tc,omitempty" description:"Suricata Flow AppProtoTc"`
	AppProtoTs       *string       `json:"app_proto_ts,omitempty" description:"Suricata Flow AppProtoTs"`
	CommunityID      *string       `json:"community_id,omitempty" description:"Suricata Flow CommunityID"`
	DestIP           *string       `json:"dest_ip" validate:"required" description:"Suricata Flow DestIP"`
	DestPort         *int          `json:"dest_port,omitempty" description:"Suricata Flow DestPort"`
	EventType        *string       `json:"event_type" validate:"required,eq=flow" description:"Suricata Flow EventType"`
	Flow             *FlowDetails  `json:"flow" validate:"required,dive" description:"Suricata Flow Flow"`
	FlowID           *int          `json:"flow_id,omitempty" description:"Suricata Flow FlowID"`
	IcmpCode         *int          `json:"icmp_code,omitempty" description:"Suricata Flow IcmpCode"`
	IcmpType         *int          `json:"icmp_type,omitempty" description:"Suricata Flow IcmpType"`
	Metadata         *FlowMetadata `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata Flow Metadata"`
	PcapFilename     *string       `json:"pcap_filename,omitempty" description:"Suricata Flow PcapFilename"`
	Proto            *string       `json:"proto" validate:"required" description:"Suricata Flow Proto"`
	ResponseIcmpCode *int          `json:"response_icmp_code,omitempty" description:"Suricata Flow ResponseIcmpCode"`
	ResponseIcmpType *int          `json:"response_icmp_type,omitempty" description:"Suricata Flow ResponseIcmpType"`
	SrcIP            *string       `json:"src_ip" validate:"required" description:"Suricata Flow SrcIP"`
	SrcPort          *int          `json:"src_port,omitempty" description:"Suricata Flow SrcPort"`
	TCP              *FlowTCP      `json:"tcp,omitempty" validate:"omitempty,dive" description:"Suricata Flow TCP"`
	Timestamp        *string       `json:"timestamp" validate:"required" description:"Suricata Flow Timestamp"`
	Vlan             []int         `json:"vlan,omitempty" description:"Suricata Flow Vlan"`

	parsers.PantherLog
}

//nolint:lll
type FlowDetails struct {
	Age           *int    `json:"age,omitempty" description:"Suricata FlowDetails Age"`
	Alerted       *bool   `json:"alerted,omitempty" description:"Suricata FlowDetails Alerted"`
	BytesToclient *int    `json:"bytes_toclient,omitempty" description:"Suricata FlowDetails BytesToclient"`
	BytesToserver *int    `json:"bytes_toserver,omitempty" description:"Suricata FlowDetails BytesToserver"`
	Emergency     *bool   `json:"emergency,omitempty" description:"Suricata FlowDetails Emergency"`
	End           *string `json:"end,omitempty" description:"Suricata FlowDetails End"`
	PktsToclient  *int    `json:"pkts_toclient,omitempty" description:"Suricata FlowDetails PktsToclient"`
	PktsToserver  *int    `json:"pkts_toserver,omitempty" description:"Suricata FlowDetails PktsToserver"`
	Reason        *string `json:"reason,omitempty" description:"Suricata FlowDetails Reason"`
	Start         *string `json:"start,omitempty" description:"Suricata FlowDetails Start"`
	State         *string `json:"state,omitempty" description:"Suricata FlowDetails State"`
}

//nolint:lll
type FlowTCP struct {
	Ack        *bool   `json:"ack,omitempty" description:"Suricata FlowTCP Ack"`
	Cwr        *bool   `json:"cwr,omitempty" description:"Suricata FlowTCP Cwr"`
	Ecn        *bool   `json:"ecn,omitempty" description:"Suricata FlowTCP Ecn"`
	Fin        *bool   `json:"fin,omitempty" description:"Suricata FlowTCP Fin"`
	Psh        *bool   `json:"psh,omitempty" description:"Suricata FlowTCP Psh"`
	Rst        *bool   `json:"rst,omitempty" description:"Suricata FlowTCP Rst"`
	State      *string `json:"state,omitempty" description:"Suricata FlowTCP State"`
	Syn        *bool   `json:"syn,omitempty" description:"Suricata FlowTCP Syn"`
	TCPFlags   *string `json:"tcp_flags,omitempty" description:"Suricata FlowTCP TCPFlags"`
	TCPFlagsTc *string `json:"tcp_flags_tc,omitempty" description:"Suricata FlowTCP TCPFlagsTc"`
	TCPFlagsTs *string `json:"tcp_flags_ts,omitempty" description:"Suricata FlowTCP TCPFlagsTs"`
	Urg        *bool   `json:"urg,omitempty" description:"Suricata FlowTCP Urg"`
}

//nolint:lll
type FlowMetadata struct {
	Flowbits []string              `json:"flowbits,omitempty" description:"Suricata FlowMetadata Flowbits"`
	Flowints *FlowMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata FlowMetadata Flowints"`
}

//nolint:lll
type FlowMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty" description:"Suricata FlowMetadataFlowints ApplayerAnomalyCount"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty" description:"Suricata FlowMetadataFlowints HTTPAnomalyCount"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty" description:"Suricata FlowMetadataFlowints TCPRetransmissionCount"`
	TLSAnomalyCount        *int `json:"tls.anomaly.count,omitempty" description:"Suricata FlowMetadataFlowints TLSAnomalyCount"`
}

// FlowParser parses Suricata Flow alerts in the JSON format
type FlowParser struct{}

func (p *FlowParser) New() parsers.LogParser {
	return &FlowParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *FlowParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *FlowParser) LogType() string {
	return "Suricata.Flow"
}

func (event *Flow) updatePantherFields(p *FlowParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtr(event.SrcIP)
	event.AppendAnyIPAddressPtr(event.DestIP)
}
