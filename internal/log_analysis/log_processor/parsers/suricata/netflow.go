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

var NetflowDesc = `Suricata parser for the Netflow event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type Netflow struct {
	AppProto     *string          `json:"app_proto,omitempty" description:"Suricata Netflow AppProto"`
	CommunityID  *string          `json:"community_id,omitempty" description:"Suricata Netflow CommunityID"`
	DestIP       *string          `json:"dest_ip" validate:"required" description:"Suricata Netflow DestIP"`
	DestPort     *int             `json:"dest_port,omitempty" description:"Suricata Netflow DestPort"`
	EventType    *string          `json:"event_type" validate:"required" description:"Suricata Netflow EventType"`
	FlowID       *int             `json:"flow_id,omitempty" description:"Suricata Netflow FlowID"`
	IcmpCode     *int             `json:"icmp_code,omitempty" description:"Suricata Netflow IcmpCode"`
	IcmpType     *int             `json:"icmp_type,omitempty" description:"Suricata Netflow IcmpType"`
	Metadata     *NetflowMetadata `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata Netflow Metadata"`
	Netflow      *NetflowDetails  `json:"netflow" validate:"required,dive" description:"Suricata Netflow Netflow"`
	PcapFilename *string          `json:"pcap_filename,omitempty" description:"Suricata Netflow PcapFilename"`
	Proto        *string          `json:"proto" validate:"required" description:"Suricata Netflow Proto"`
	SrcIP        *string          `json:"src_ip" validate:"required" description:"Suricata Netflow SrcIP"`
	SrcPort      *int             `json:"src_port,omitempty" description:"Suricata Netflow SrcPort"`
	TCP          *NetflowTCP      `json:"tcp,omitempty" validate:"omitempty,dive" description:"Suricata Netflow TCP"`
	Timestamp    *string          `json:"timestamp" validate:"required" description:"Suricata Netflow Timestamp"`
	Vlan         []int            `json:"vlan,omitempty" description:"Suricata Netflow Vlan"`

	parsers.PantherLog
}

//nolint:lll
type NetflowDetails struct {
	Age    *int    `json:"age,omitempty" description:"Suricata NetflowDetails Age"`
	Bytes  *int    `json:"bytes,omitempty" description:"Suricata NetflowDetails Bytes"`
	End    *string `json:"end,omitempty" description:"Suricata NetflowDetails End"`
	MaxTTL *int    `json:"max_ttl,omitempty" description:"Suricata NetflowDetails MaxTTL"`
	MinTTL *int    `json:"min_ttl,omitempty" description:"Suricata NetflowDetails MinTTL"`
	Pkts   *int    `json:"pkts,omitempty" description:"Suricata NetflowDetails Pkts"`
	Start  *string `json:"start,omitempty" description:"Suricata NetflowDetails Start"`
}

//nolint:lll
type NetflowTCP struct {
	Ack      *bool   `json:"ack,omitempty" description:"Suricata NetflowTCP Ack"`
	Cwr      *bool   `json:"cwr,omitempty" description:"Suricata NetflowTCP Cwr"`
	Ecn      *bool   `json:"ecn,omitempty" description:"Suricata NetflowTCP Ecn"`
	Fin      *bool   `json:"fin,omitempty" description:"Suricata NetflowTCP Fin"`
	Psh      *bool   `json:"psh,omitempty" description:"Suricata NetflowTCP Psh"`
	Rst      *bool   `json:"rst,omitempty" description:"Suricata NetflowTCP Rst"`
	Syn      *bool   `json:"syn,omitempty" description:"Suricata NetflowTCP Syn"`
	TCPFlags *string `json:"tcp_flags,omitempty" description:"Suricata NetflowTCP TCPFlags"`
	Urg      *bool   `json:"urg,omitempty" description:"Suricata NetflowTCP Urg"`
}

//nolint:lll
type NetflowMetadata struct {
	Flowbits []string                 `json:"flowbits,omitempty" description:"Suricata NetflowMetadata Flowbits"`
	Flowints *NetflowMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata NetflowMetadata Flowints"`
}

//nolint:lll
type NetflowMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty" description:"Suricata NetflowMetadataFlowints ApplayerAnomalyCount"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty" description:"Suricata NetflowMetadataFlowints HTTPAnomalyCount"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty" description:"Suricata NetflowMetadataFlowints TCPRetransmissionCount"`
	TLSAnomalyCount        *int `json:"tls.anomaly.count,omitempty" description:"Suricata NetflowMetadataFlowints TLSAnomalyCount"`
}

// NetflowParser parses Suricata Netflow alerts in the JSON format
type NetflowParser struct{}

func (p *NetflowParser) New() parsers.LogParser {
	return &NetflowParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *NetflowParser) Parse(log string) []*parsers.PantherLog {
	event := &Netflow{}

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
func (p *NetflowParser) LogType() string {
	return "Suricata.Netflow"
}

func (event *Netflow) updatePantherFields(p *NetflowParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
