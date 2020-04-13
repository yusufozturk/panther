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

var SnmpDesc = `Suricata parser for the Snmp event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type Snmp struct {
	CommunityID  *string      `json:"community_id,omitempty" description:"Suricata Snmp CommunityID"`
	DestIP       *string      `json:"dest_ip" validate:"required" description:"Suricata Snmp DestIP"`
	DestPort     *int         `json:"dest_port,omitempty" description:"Suricata Snmp DestPort"`
	EventType    *string      `json:"event_type" validate:"required,eq=snmp" description:"Suricata Snmp EventType"`
	FlowID       *int         `json:"flow_id,omitempty" description:"Suricata Snmp FlowID"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty" description:"Suricata Snmp PcapCnt"`
	PcapFilename *string      `json:"pcap_filename,omitempty" description:"Suricata Snmp PcapFilename"`
	Proto        *string      `json:"proto" validate:"required" description:"Suricata Snmp Proto"`
	Snmp         *SnmpDetails `json:"snmp" validate:"required,dive" description:"Suricata Snmp Snmp"`
	SrcIP        *string      `json:"src_ip" validate:"required" description:"Suricata Snmp SrcIP"`
	SrcPort      *int         `json:"src_port,omitempty" description:"Suricata Snmp SrcPort"`
	Timestamp    *string      `json:"timestamp" validate:"required" description:"Suricata Snmp Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type SnmpDetails struct {
	Community   *string  `json:"community,omitempty" description:"Suricata SnmpDetails Community"`
	Error       *string  `json:"error,omitempty" description:"Suricata SnmpDetails Error"`
	PduType     *string  `json:"pdu_type,omitempty" description:"Suricata SnmpDetails PduType"`
	TrapAddress *string  `json:"trap_address,omitempty" description:"Suricata SnmpDetails TrapAddress"`
	TrapOid     *string  `json:"trap_oid,omitempty" description:"Suricata SnmpDetails TrapOid"`
	TrapType    *string  `json:"trap_type,omitempty" description:"Suricata SnmpDetails TrapType"`
	Usm         *string  `json:"usm,omitempty" description:"Suricata SnmpDetails Usm"`
	Vars        []string `json:"vars,omitempty" description:"Suricata SnmpDetails Vars"`
	Version     *int     `json:"version,omitempty" description:"Suricata SnmpDetails Version"`
}

// SnmpParser parses Suricata Snmp alerts in the JSON format
type SnmpParser struct{}

func (p *SnmpParser) New() parsers.LogParser {
	return &SnmpParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *SnmpParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *SnmpParser) LogType() string {
	return "Suricata.Snmp"
}

func (event *Snmp) updatePantherFields(p *SnmpParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtr(event.SrcIP)
	event.AppendAnyIPAddressPtr(event.DestIP)
}
