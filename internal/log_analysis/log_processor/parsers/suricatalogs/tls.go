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

var TLSDesc = `Suricata parser for the TLS event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type TLS struct {
	CommunityID  *string      `json:"community_id,omitempty" description:"Suricata TLS CommunityID"`
	DestIP       *string      `json:"dest_ip" validate:"required" description:"Suricata TLS DestIP"`
	DestPort     *int         `json:"dest_port,omitempty" description:"Suricata TLS DestPort"`
	EventType    *string      `json:"event_type" validate:"required,eq=tls" description:"Suricata TLS EventType"`
	FlowID       *int         `json:"flow_id,omitempty" description:"Suricata TLS FlowID"`
	Metadata     *TLSMetadata `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata TLS Metadata"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty" description:"Suricata TLS PcapCnt"`
	PcapFilename *string      `json:"pcap_filename,omitempty" description:"Suricata TLS PcapFilename"`
	Proto        *string      `json:"proto" validate:"required" description:"Suricata TLS Proto"`
	SrcIP        *string      `json:"src_ip" validate:"required" description:"Suricata TLS SrcIP"`
	SrcPort      *int         `json:"src_port,omitempty" description:"Suricata TLS SrcPort"`
	TLS          *TLSDetails  `json:"tls" validate:"required,dive" description:"Suricata TLS TLS"`
	Timestamp    *string      `json:"timestamp" validate:"required" description:"Suricata TLS Timestamp"`
	Vlan         []int        `json:"vlan,omitempty" description:"Suricata TLS Vlan"`

	parsers.PantherLog
}

//nolint:lll
type TLSDetails struct {
	Fingerprint    *string         `json:"fingerprint,omitempty" description:"Suricata TLSDetails Fingerprint"`
	FromProto      *string         `json:"from_proto,omitempty" description:"Suricata TLSDetails FromProto"`
	Issuerdn       *string         `json:"issuerdn,omitempty" description:"Suricata TLSDetails Issuerdn"`
	Ja3            *TLSDetailsJa3  `json:"ja3,omitempty" validate:"omitempty,dive" description:"Suricata TLSDetails Ja3"`
	Ja3S           *TLSDetailsJa3S `json:"ja3s,omitempty" validate:"omitempty,dive" description:"Suricata TLSDetails Ja3S"`
	Notafter       *string         `json:"notafter,omitempty" description:"Suricata TLSDetails Notafter"`
	Notbefore      *string         `json:"notbefore,omitempty" description:"Suricata TLSDetails Notbefore"`
	Serial         *string         `json:"serial,omitempty" description:"Suricata TLSDetails Serial"`
	SessionResumed *bool           `json:"session_resumed,omitempty" description:"Suricata TLSDetails SessionResumed"`
	Sni            *string         `json:"sni,omitempty" description:"Suricata TLSDetails Sni"`
	Subject        *string         `json:"subject,omitempty" description:"Suricata TLSDetails Subject"`
	Version        *string         `json:"version,omitempty" description:"Suricata TLSDetails Version"`
}

//nolint:lll
type TLSDetailsJa3 struct {
	Hash   *string `json:"hash,omitempty" description:"Suricata TLSDetailsJa3 Hash"`
	String *string `json:"string,omitempty" description:"Suricata TLSDetailsJa3 String"`
}

//nolint:lll
type TLSDetailsJa3S struct {
	Hash   *string `json:"hash,omitempty" description:"Suricata TLSDetailsJa3S Hash"`
	String *string `json:"string,omitempty" description:"Suricata TLSDetailsJa3S String"`
}

//nolint:lll
type TLSMetadata struct {
	Flowints *TLSMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata TLSMetadata Flowints"`
}

//nolint:lll
type TLSMetadataFlowints struct {
	ApplayerAnomalyCount *int `json:"applayer.anomaly.count,omitempty" description:"Suricata TLSMetadataFlowints ApplayerAnomalyCount"`
	TLSAnomalyCount      *int `json:"tls.anomaly.count,omitempty" description:"Suricata TLSMetadataFlowints TLSAnomalyCount"`
}

// TLSParser parses Suricata TLS alerts in the JSON format
type TLSParser struct{}

func (p *TLSParser) New() parsers.LogParser {
	return &TLSParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *TLSParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *TLSParser) LogType() string {
	return "Suricata.TLS"
}

func (event *TLS) updatePantherFields(p *TLSParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtr(event.SrcIP)
	event.AppendAnyIPAddressPtr(event.DestIP)
}
