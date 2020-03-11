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

var TLSDesc = `Suricata parser for the TLS event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type TLS struct {
	CommunityID  *string      `json:"community_id" validate:"required"`
	DestIP       *string      `json:"dest_ip" validate:"required"`
	DestPort     *int         `json:"dest_port" validate:"required"`
	EventType    *string      `json:"event_type" validate:"required"`
	FlowID       *int         `json:"flow_id" validate:"required"`
	Metadata     *TLSMetadata `json:"metadata,omitempty" validate:"omitempty,dive"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty"`
	PcapFilename *string      `json:"pcap_filename" validate:"required"`
	Proto        *string      `json:"proto" validate:"required"`
	SrcIP        *string      `json:"src_ip" validate:"required"`
	SrcPort      *int         `json:"src_port" validate:"required"`
	TLS          *TLSDetails  `json:"tls" validate:"required,dive"`
	Timestamp    *string      `json:"timestamp" validate:"required"`
	Vlan         []int        `json:"vlan,omitempty"`

	parsers.PantherLog
}

type TLSDetails struct {
	Fingerprint    *string         `json:"fingerprint,omitempty"`
	FromProto      *string         `json:"from_proto,omitempty"`
	Issuerdn       *string         `json:"issuerdn,omitempty"`
	Ja3            *TLSDetailsJa3  `json:"ja3" validate:"required,dive"`
	Ja3S           *TLSDetailsJa3S `json:"ja3s" validate:"required,dive"`
	Notafter       *string         `json:"notafter,omitempty"`
	Notbefore      *string         `json:"notbefore,omitempty"`
	Serial         *string         `json:"serial,omitempty"`
	SessionResumed *bool           `json:"session_resumed,omitempty"`
	Sni            *string         `json:"sni,omitempty"`
	Subject        *string         `json:"subject,omitempty"`
	Version        *string         `json:"version" validate:"required"`
}

type TLSDetailsJa3 struct {
	Hash   *string `json:"hash,omitempty"`
	String *string `json:"string,omitempty"`
}

type TLSDetailsJa3S struct {
	Hash   *string `json:"hash,omitempty"`
	String *string `json:"string,omitempty"`
}

type TLSMetadata struct {
	Flowints *TLSMetadataFlowints `json:"flowints" validate:"required,dive"`
}

type TLSMetadataFlowints struct {
	ApplayerAnomalyCount *int `json:"applayer.anomaly.count,omitempty"`
	TLSAnomalyCount      *int `json:"tls.anomaly.count,omitempty"`
}

// TLSParser parses Suricata TLS alerts in the JSON format
type TLSParser struct{}

func (p *TLSParser) New() parsers.LogParser {
	return &TLSParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *TLSParser) Parse(log string) []interface{} {
	event := &TLS{}

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
func (p *TLSParser) LogType() string {
	return "Suricata.TLS"
}

func (event *TLS) updatePantherFields(p *TLSParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
