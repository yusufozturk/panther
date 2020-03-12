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

var TFTPDesc = `Suricata parser for the TFTP event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type TFTP struct {
	DestIP       *string      `json:"dest_ip" validate:"required" description:"Suricata TFTP DestIP"`
	DestPort     *int         `json:"dest_port,omitempty" description:"Suricata TFTP DestPort"`
	EventType    *string      `json:"event_type" validate:"required" description:"Suricata TFTP EventType"`
	FlowID       *int         `json:"flow_id,omitempty" description:"Suricata TFTP FlowID"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty" description:"Suricata TFTP PcapCnt"`
	PcapFilename *string      `json:"pcap_filename,omitempty" description:"Suricata TFTP PcapFilename"`
	Proto        *string      `json:"proto" validate:"required" description:"Suricata TFTP Proto"`
	SrcIP        *string      `json:"src_ip" validate:"required" description:"Suricata TFTP SrcIP"`
	SrcPort      *int         `json:"src_port,omitempty" description:"Suricata TFTP SrcPort"`
	TFTP         *TFTPDetails `json:"tftp" validate:"required,dive" description:"Suricata TFTP TFTP"`
	Timestamp    *string      `json:"timestamp" validate:"required" description:"Suricata TFTP Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type TFTPDetails struct {
	File   *string `json:"file,omitempty" description:"Suricata TFTPDetails File"`
	Mode   *string `json:"mode,omitempty" description:"Suricata TFTPDetails Mode"`
	Packet *string `json:"packet,omitempty" description:"Suricata TFTPDetails Packet"`
}

// TFTPParser parses Suricata TFTP alerts in the JSON format
type TFTPParser struct{}

func (p *TFTPParser) New() parsers.LogParser {
	return &TFTPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *TFTPParser) Parse(log string) []interface{} {
	event := &TFTP{}

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
func (p *TFTPParser) LogType() string {
	return "Suricata.TFTP"
}

func (event *TFTP) updatePantherFields(p *TFTPParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
