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

var DHCPDesc = `Suricata parser for the DHCP event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type DHCP struct {
	DHCP         *DHCPDetails `json:"dhcp" validate:"required,dive" description:"Suricata DHCP DHCP"`
	DestIP       *string      `json:"dest_ip" validate:"required" description:"Suricata DHCP DestIP"`
	DestPort     *int         `json:"dest_port,omitempty" description:"Suricata DHCP DestPort"`
	EventType    *string      `json:"event_type" validate:"required,eq=dhcp" description:"Suricata DHCP EventType"`
	FlowID       *int         `json:"flow_id,omitempty" description:"Suricata DHCP FlowID"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty" description:"Suricata DHCP PcapCnt"`
	PcapFilename *string      `json:"pcap_filename,omitempty" description:"Suricata DHCP PcapFilename"`
	Proto        *string      `json:"proto" validate:"required" description:"Suricata DHCP Proto"`
	SrcIP        *string      `json:"src_ip" validate:"required" description:"Suricata DHCP SrcIP"`
	SrcPort      *int         `json:"src_port,omitempty" description:"Suricata DHCP SrcPort"`
	Timestamp    *string      `json:"timestamp" validate:"required" description:"Suricata DHCP Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type DHCPDetails struct {
	AssignedIP    *string  `json:"assigned_ip,omitempty" description:"Suricata DHCPDetails AssignedIP"`
	ClientID      *string  `json:"client_id,omitempty" description:"Suricata DHCPDetails ClientID"`
	ClientIP      *string  `json:"client_ip,omitempty" description:"Suricata DHCPDetails ClientIP"`
	ClientMac     *string  `json:"client_mac,omitempty" description:"Suricata DHCPDetails ClientMac"`
	DHCPType      *string  `json:"dhcp_type,omitempty" description:"Suricata DHCPDetails DHCPType"`
	DNSServers    []string `json:"dns_servers,omitempty" description:"Suricata DHCPDetails DNSServers"`
	Hostname      *string  `json:"hostname,omitempty" description:"Suricata DHCPDetails Hostname"`
	ID            *int     `json:"id,omitempty" description:"Suricata DHCPDetails ID"`
	LeaseTime     *int     `json:"lease_time,omitempty" description:"Suricata DHCPDetails LeaseTime"`
	NextServerIP  *string  `json:"next_server_ip,omitempty" description:"Suricata DHCPDetails NextServerIP"`
	Params        []string `json:"params,omitempty" description:"Suricata DHCPDetails Params"`
	RebindingTime *int     `json:"rebinding_time,omitempty" description:"Suricata DHCPDetails RebindingTime"`
	RelayIP       *string  `json:"relay_ip,omitempty" description:"Suricata DHCPDetails RelayIP"`
	RenewalTime   *int     `json:"renewal_time,omitempty" description:"Suricata DHCPDetails RenewalTime"`
	RequestedIP   *string  `json:"requested_ip,omitempty" description:"Suricata DHCPDetails RequestedIP"`
	Routers       []string `json:"routers,omitempty" description:"Suricata DHCPDetails Routers"`
	SubnetMask    *string  `json:"subnet_mask,omitempty" description:"Suricata DHCPDetails SubnetMask"`
	Type          *string  `json:"type,omitempty" description:"Suricata DHCPDetails Type"`
}

// DHCPParser parses Suricata DHCP alerts in the JSON format
type DHCPParser struct{}

func (p *DHCPParser) New() parsers.LogParser {
	return &DHCPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *DHCPParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *DHCPParser) LogType() string {
	return "Suricata.DHCP"
}

func (event *DHCP) updatePantherFields(p *DHCPParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtr(event.SrcIP)
	event.AppendAnyIPAddressPtr(event.DestIP)
}
