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

var SSHDesc = `Suricata parser for the SSH event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type SSH struct {
	CommunityID  *string      `json:"community_id,omitempty" description:"Suricata SSH CommunityID"`
	DestIP       *string      `json:"dest_ip" validate:"required" description:"Suricata SSH DestIP"`
	DestPort     *int         `json:"dest_port,omitempty" description:"Suricata SSH DestPort"`
	EventType    *string      `json:"event_type" validate:"required" description:"Suricata SSH EventType"`
	FlowID       *int         `json:"flow_id,omitempty" description:"Suricata SSH FlowID"`
	Metadata     *SSHMetadata `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata SSH Metadata"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty" description:"Suricata SSH PcapCnt"`
	PcapFilename *string      `json:"pcap_filename,omitempty" description:"Suricata SSH PcapFilename"`
	Proto        *string      `json:"proto" validate:"required" description:"Suricata SSH Proto"`
	SSH          *SSHDetails  `json:"ssh" validate:"required,dive" description:"Suricata SSH SSH"`
	SrcIP        *string      `json:"src_ip" validate:"required" description:"Suricata SSH SrcIP"`
	SrcPort      *int         `json:"src_port,omitempty" description:"Suricata SSH SrcPort"`
	Timestamp    *string      `json:"timestamp" validate:"required" description:"Suricata SSH Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type SSHDetails struct {
	Client *SSHDetailsClient `json:"client,omitempty" validate:"omitempty,dive" description:"Suricata SSHDetails Client"`
	Server *SSHDetailsServer `json:"server,omitempty" validate:"omitempty,dive" description:"Suricata SSHDetails Server"`
}

//nolint:lll
type SSHDetailsClient struct {
	ProtoVersion    *string `json:"proto_version,omitempty" description:"Suricata SSHDetailsClient ProtoVersion"`
	SoftwareVersion *string `json:"software_version,omitempty" description:"Suricata SSHDetailsClient SoftwareVersion"`
}

//nolint:lll
type SSHDetailsServer struct {
	ProtoVersion    *string `json:"proto_version,omitempty" description:"Suricata SSHDetailsServer ProtoVersion"`
	SoftwareVersion *string `json:"software_version,omitempty" description:"Suricata SSHDetailsServer SoftwareVersion"`
}

//nolint:lll
type SSHMetadata struct {
	Flowints *SSHMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata SSHMetadata Flowints"`
}

//nolint:lll
type SSHMetadataFlowints struct {
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty" description:"Suricata SSHMetadataFlowints TCPRetransmissionCount"`
}

// SSHParser parses Suricata SSH alerts in the JSON format
type SSHParser struct{}

func (p *SSHParser) New() parsers.LogParser {
	return &SSHParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *SSHParser) Parse(log string) []*parsers.PantherLog {
	event := &SSH{}

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
func (p *SSHParser) LogType() string {
	return "Suricata.SSH"
}

func (event *SSH) updatePantherFields(p *SSHParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
