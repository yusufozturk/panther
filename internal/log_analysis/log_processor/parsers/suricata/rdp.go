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

//nolint:lll
type Rdp struct {
	DestIP       *string     `json:"dest_ip" validate:"required" description:"Suricata Rdp DestIP"`
	DestPort     *int        `json:"dest_port,omitempty" description:"Suricata Rdp DestPort"`
	EventType    *string     `json:"event_type" validate:"required" description:"Suricata Rdp EventType"`
	FlowID       *int        `json:"flow_id,omitempty" description:"Suricata Rdp FlowID"`
	PcapCnt      *int        `json:"pcap_cnt,omitempty" description:"Suricata Rdp PcapCnt"`
	PcapFilename *string     `json:"pcap_filename,omitempty" description:"Suricata Rdp PcapFilename"`
	Proto        *string     `json:"proto" validate:"required" description:"Suricata Rdp Proto"`
	Rdp          *RdpDetails `json:"rdp" validate:"required,dive" description:"Suricata Rdp Rdp"`
	SrcIP        *string     `json:"src_ip" validate:"required" description:"Suricata Rdp SrcIP"`
	SrcPort      *int        `json:"src_port,omitempty" description:"Suricata Rdp SrcPort"`
	Timestamp    *string     `json:"timestamp" validate:"required" description:"Suricata Rdp Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type RdpDetails struct {
	Channels       []string          `json:"channels,omitempty" description:"Suricata RdpDetails Channels"`
	Client         *RdpDetailsClient `json:"client,omitempty" validate:"omitempty,dive" description:"Suricata RdpDetails Client"`
	Cookie         *string           `json:"cookie,omitempty" description:"Suricata RdpDetails Cookie"`
	ErrorCode      *int              `json:"error_code,omitempty" description:"Suricata RdpDetails ErrorCode"`
	EventType      *string           `json:"event_type,omitempty" description:"Suricata RdpDetails EventType"`
	Protocol       *string           `json:"protocol,omitempty" description:"Suricata RdpDetails Protocol"`
	Reason         *string           `json:"reason,omitempty" description:"Suricata RdpDetails Reason"`
	ServerSupports []string          `json:"server_supports,omitempty" description:"Suricata RdpDetails ServerSupports"`
	TxID           *int              `json:"tx_id,omitempty" description:"Suricata RdpDetails TxID"`
	X509Serials    []string          `json:"x509_serials,omitempty" description:"Suricata RdpDetails X509Serials"`
}

//nolint:lll
type RdpDetailsClient struct {
	Build          *string  `json:"build,omitempty" description:"Suricata RdpDetailsClient Build"`
	Capabilities   []string `json:"capabilities,omitempty" description:"Suricata RdpDetailsClient Capabilities"`
	ClientName     *string  `json:"client_name,omitempty" description:"Suricata RdpDetailsClient ClientName"`
	ColorDepth     *int     `json:"color_depth,omitempty" description:"Suricata RdpDetailsClient ColorDepth"`
	ConnectionHint *string  `json:"connection_hint,omitempty" description:"Suricata RdpDetailsClient ConnectionHint"`
	DesktopHeight  *int     `json:"desktop_height,omitempty" description:"Suricata RdpDetailsClient DesktopHeight"`
	DesktopWidth   *int     `json:"desktop_width,omitempty" description:"Suricata RdpDetailsClient DesktopWidth"`
	FunctionKeys   *int     `json:"function_keys,omitempty" description:"Suricata RdpDetailsClient FunctionKeys"`
	ID             *string  `json:"id,omitempty" description:"Suricata RdpDetailsClient ID"`
	KeyboardLayout *string  `json:"keyboard_layout,omitempty" description:"Suricata RdpDetailsClient KeyboardLayout"`
	KeyboardType   *string  `json:"keyboard_type,omitempty" description:"Suricata RdpDetailsClient KeyboardType"`
	ProductID      *int     `json:"product_id,omitempty" description:"Suricata RdpDetailsClient ProductID"`
	Version        *string  `json:"version,omitempty" description:"Suricata RdpDetailsClient Version"`
}

// RdpParser parses Suricata Rdp alerts in the JSON format
type RdpParser struct{}

func (p *RdpParser) New() parsers.LogParser {
	return &RdpParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *RdpParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *RdpParser) LogType() string {
	return "Suricata.Rdp"
}

func (event *Rdp) updatePantherFields(p *RdpParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
