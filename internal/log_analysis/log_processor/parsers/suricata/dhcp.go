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

var DHCPDesc = `Suricata parser for the DHCP event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type DHCP struct {
	DHCP         *DHCPDetails `json:"dhcp" validate:"required,dive"`
	DestIP       *string      `json:"dest_ip" validate:"required"`
	DestPort     *int         `json:"dest_port" validate:"required"`
	EventType    *string      `json:"event_type" validate:"required"`
	FlowID       *int         `json:"flow_id" validate:"required"`
	PcapCnt      *int         `json:"pcap_cnt" validate:"required"`
	PcapFilename *string      `json:"pcap_filename" validate:"required"`
	Proto        *string      `json:"proto" validate:"required"`
	SrcIP        *string      `json:"src_ip" validate:"required"`
	SrcPort      *int         `json:"src_port" validate:"required"`
	Timestamp    *string      `json:"timestamp" validate:"required"`

	parsers.PantherLog
}

type DHCPDetails struct {
	AssignedIP    *string  `json:"assigned_ip" validate:"required"`
	ClientID      *string  `json:"client_id,omitempty"`
	ClientIP      *string  `json:"client_ip" validate:"required"`
	ClientMac     *string  `json:"client_mac" validate:"required"`
	DHCPType      *string  `json:"dhcp_type,omitempty"`
	DNSServers    []string `json:"dns_servers,omitempty"`
	Hostname      *string  `json:"hostname,omitempty"`
	ID            *int     `json:"id" validate:"required"`
	LeaseTime     *int     `json:"lease_time,omitempty"`
	NextServerIP  *string  `json:"next_server_ip,omitempty"`
	Params        []string `json:"params,omitempty"`
	RebindingTime *int     `json:"rebinding_time,omitempty"`
	RelayIP       *string  `json:"relay_ip,omitempty"`
	RenewalTime   *int     `json:"renewal_time,omitempty"`
	RequestedIP   *string  `json:"requested_ip,omitempty"`
	Routers       []string `json:"routers,omitempty"`
	SubnetMask    *string  `json:"subnet_mask,omitempty"`
	Type          *string  `json:"type" validate:"required"`
}

// DHCPParser parses Suricata DHCP alerts in the JSON format
type DHCPParser struct{}

func (p *DHCPParser) New() parsers.LogParser {
	return &DHCPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *DHCPParser) Parse(log string) []interface{} {
	event := &DHCP{}

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
func (p *DHCPParser) LogType() string {
	return "Suricata.DHCP"
}

func (event *DHCP) updatePantherFields(p *DHCPParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
