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

var RdpDesc = `Suricata parser for the Rdp event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Rdp struct {
	DestIP       *string     `json:"dest_ip" validate:"required"`
	DestPort     *int        `json:"dest_port" validate:"required"`
	EventType    *string     `json:"event_type" validate:"required"`
	FlowID       *int        `json:"flow_id" validate:"required"`
	PcapCnt      *int        `json:"pcap_cnt,omitempty"`
	PcapFilename *string     `json:"pcap_filename" validate:"required"`
	Proto        *string     `json:"proto" validate:"required"`
	Rdp          *RdpDetails `json:"rdp" validate:"required,dive"`
	SrcIP        *string     `json:"src_ip" validate:"required"`
	SrcPort      *int        `json:"src_port" validate:"required"`
	Timestamp    *string     `json:"timestamp" validate:"required"`

	parsers.PantherLog
}

type RdpDetails struct {
	Channels       []string          `json:"channels,omitempty"`
	Client         *RdpDetailsClient `json:"client,omitempty" validate:"omitempty,dive"`
	Cookie         *string           `json:"cookie,omitempty"`
	ErrorCode      *int              `json:"error_code,omitempty"`
	EventType      *string           `json:"event_type" validate:"required"`
	Protocol       *string           `json:"protocol,omitempty"`
	Reason         *string           `json:"reason,omitempty"`
	ServerSupports []string          `json:"server_supports,omitempty"`
	TxID           *int              `json:"tx_id" validate:"required"`
	X509Serials    []string          `json:"x509_serials,omitempty"`
}

type RdpDetailsClient struct {
	Build          *string  `json:"build" validate:"required"`
	Capabilities   []string `json:"capabilities" validate:"required"`
	ClientName     *string  `json:"client_name" validate:"required"`
	ColorDepth     *int     `json:"color_depth" validate:"required"`
	ConnectionHint *string  `json:"connection_hint,omitempty"`
	DesktopHeight  *int     `json:"desktop_height" validate:"required"`
	DesktopWidth   *int     `json:"desktop_width" validate:"required"`
	FunctionKeys   *int     `json:"function_keys" validate:"required"`
	ID             *string  `json:"id,omitempty"`
	KeyboardLayout *string  `json:"keyboard_layout" validate:"required"`
	KeyboardType   *string  `json:"keyboard_type" validate:"required"`
	ProductID      *int     `json:"product_id" validate:"required"`
	Version        *string  `json:"version" validate:"required"`
}

// RdpParser parses Suricata Rdp alerts in the JSON format
type RdpParser struct{}

func (p *RdpParser) New() parsers.LogParser {
	return &RdpParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *RdpParser) Parse(log string) []interface{} {
	event := &Rdp{}

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
func (p *RdpParser) LogType() string {
	return "Suricata.Rdp"
}

func (event *Rdp) updatePantherFields(p *RdpParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
