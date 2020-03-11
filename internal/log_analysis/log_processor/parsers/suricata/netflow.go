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

type Netflow struct {
	AppProto     *string          `json:"app_proto,omitempty"`
	CommunityID  *string          `json:"community_id" validate:"required"`
	DestIP       *string          `json:"dest_ip" validate:"required"`
	DestPort     *int             `json:"dest_port,omitempty"`
	EventType    *string          `json:"event_type" validate:"required"`
	FlowID       *int             `json:"flow_id" validate:"required"`
	IcmpCode     *int             `json:"icmp_code,omitempty"`
	IcmpType     *int             `json:"icmp_type,omitempty"`
	Metadata     *NetflowMetadata `json:"metadata,omitempty" validate:"omitempty,dive"`
	Netflow      *NetflowDetails  `json:"netflow" validate:"required,dive"`
	PcapFilename *string          `json:"pcap_filename" validate:"required"`
	Proto        *string          `json:"proto" validate:"required"`
	SrcIP        *string          `json:"src_ip" validate:"required"`
	SrcPort      *int             `json:"src_port,omitempty"`
	TCP          *NetflowTCP      `json:"tcp,omitempty" validate:"omitempty,dive"`
	Timestamp    *string          `json:"timestamp" validate:"required"`
	Vlan         []int            `json:"vlan,omitempty"`

	parsers.PantherLog
}

type NetflowDetails struct {
	Age    *int    `json:"age" validate:"required"`
	Bytes  *int    `json:"bytes" validate:"required"`
	End    *string `json:"end" validate:"required"`
	MaxTTL *int    `json:"max_ttl" validate:"required"`
	MinTTL *int    `json:"min_ttl" validate:"required"`
	Pkts   *int    `json:"pkts" validate:"required"`
	Start  *string `json:"start" validate:"required"`
}

type NetflowTCP struct {
	Ack      *bool   `json:"ack,omitempty"`
	Cwr      *bool   `json:"cwr,omitempty"`
	Ecn      *bool   `json:"ecn,omitempty"`
	Fin      *bool   `json:"fin,omitempty"`
	Psh      *bool   `json:"psh,omitempty"`
	Rst      *bool   `json:"rst,omitempty"`
	Syn      *bool   `json:"syn,omitempty"`
	TCPFlags *string `json:"tcp_flags" validate:"required"`
	Urg      *bool   `json:"urg,omitempty"`
}

type NetflowMetadata struct {
	Flowbits []string                 `json:"flowbits,omitempty"`
	Flowints *NetflowMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive"`
}

type NetflowMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty"`
	TLSAnomalyCount        *int `json:"tls.anomaly.count,omitempty"`
}

// NetflowParser parses Suricata Netflow alerts in the JSON format
type NetflowParser struct{}

func (p *NetflowParser) New() parsers.LogParser {
	return &NetflowParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *NetflowParser) Parse(log string) []interface{} {
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

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *NetflowParser) LogType() string {
	return "Suricata.Netflow"
}

func (event *Netflow) updatePantherFields(p *NetflowParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
