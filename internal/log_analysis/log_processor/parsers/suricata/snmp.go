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

var SnmpDesc = `Suricata parser for the Snmp event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Snmp struct {
	CommunityID  *string      `json:"community_id" validate:"required"`
	DestIP       *string      `json:"dest_ip" validate:"required"`
	DestPort     *int         `json:"dest_port" validate:"required"`
	EventType    *string      `json:"event_type" validate:"required"`
	FlowID       *int         `json:"flow_id" validate:"required"`
	PcapCnt      *int         `json:"pcap_cnt" validate:"required"`
	PcapFilename *string      `json:"pcap_filename" validate:"required"`
	Proto        *string      `json:"proto" validate:"required"`
	Snmp         *SnmpDetails `json:"snmp" validate:"required,dive"`
	SrcIP        *string      `json:"src_ip" validate:"required"`
	SrcPort      *int         `json:"src_port" validate:"required"`
	Timestamp    *string      `json:"timestamp" validate:"required"`

	parsers.PantherLog
}

type SnmpDetails struct {
	Community   *string  `json:"community,omitempty"`
	Error       *string  `json:"error,omitempty"`
	PduType     *string  `json:"pdu_type" validate:"required"`
	TrapAddress *string  `json:"trap_address,omitempty"`
	TrapOid     *string  `json:"trap_oid,omitempty"`
	TrapType    *string  `json:"trap_type,omitempty"`
	Usm         *string  `json:"usm,omitempty"`
	Vars        []string `json:"vars,omitempty"`
	Version     *int     `json:"version" validate:"required"`
}

// SnmpParser parses Suricata Snmp alerts in the JSON format
type SnmpParser struct{}

func (p *SnmpParser) New() parsers.LogParser {
	return &SnmpParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *SnmpParser) Parse(log string) []interface{} {
	event := &Snmp{}

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
func (p *SnmpParser) LogType() string {
	return "Suricata.Snmp"
}

func (event *Snmp) updatePantherFields(p *SnmpParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
