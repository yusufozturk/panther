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

var AnomalyDesc = `Suricata parser for the Anomaly event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Anomaly struct {
	Anomaly      *AnomalyDetails    `json:"anomaly" validate:"required,dive"`
	AppProto     *string            `json:"app_proto,omitempty"`
	CommunityID  *string            `json:"community_id,omitempty"`
	DestIP       *string            `json:"dest_ip,omitempty"`
	DestPort     *int               `json:"dest_port,omitempty"`
	EventType    *string            `json:"event_type" validate:"required"`
	FlowID       *int               `json:"flow_id,omitempty"`
	IcmpCode     *int               `json:"icmp_code,omitempty"`
	IcmpType     *int               `json:"icmp_type,omitempty"`
	Metadata     *AnomalyMetadata   `json:"metadata,omitempty" validate:"omitempty,dive"`
	Packet       *string            `json:"packet,omitempty"`
	PacketInfo   *AnomalyPacketInfo `json:"packet_info,omitempty" validate:"omitempty,dive"`
	PcapCnt      *int               `json:"pcap_cnt,omitempty"`
	PcapFilename *string            `json:"pcap_filename" validate:"required"`
	Proto        *string            `json:"proto,omitempty"`
	SrcIP        *string            `json:"src_ip,omitempty"`
	SrcPort      *int               `json:"src_port,omitempty"`
	Timestamp    *string            `json:"timestamp" validate:"required"`
	TxID         *int               `json:"tx_id,omitempty"`
	Vlan         []int              `json:"vlan,omitempty"`

	parsers.PantherLog
}

type AnomalyPacketInfo struct {
	Linktype *int `json:"linktype" validate:"required"`
}

type AnomalyDetails struct {
	Code  *int    `json:"code,omitempty"`
	Event *string `json:"event,omitempty"`
	Layer *string `json:"layer,omitempty"`
	Type  *string `json:"type" validate:"required"`
}

type AnomalyMetadata struct {
	Flowbits []string                 `json:"flowbits,omitempty"`
	Flowints *AnomalyMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive"`
}

type AnomalyMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty"`
	TLSAnomalyCount        *int `json:"tls.anomaly.count,omitempty"`
}

// AnomalyParser parses Suricata Anomaly alerts in the JSON format
type AnomalyParser struct{}

func (p *AnomalyParser) New() parsers.LogParser {
	return &AnomalyParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *AnomalyParser) Parse(log string) []interface{} {
	event := &Anomaly{}

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
func (p *AnomalyParser) LogType() string {
	return "Suricata.Anomaly"
}

func (event *Anomaly) updatePantherFields(p *AnomalyParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
