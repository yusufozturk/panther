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

type SSH struct {
	CommunityID  *string      `json:"community_id" validate:"required"`
	DestIP       *string      `json:"dest_ip" validate:"required"`
	DestPort     *int         `json:"dest_port" validate:"required"`
	EventType    *string      `json:"event_type" validate:"required"`
	FlowID       *int         `json:"flow_id" validate:"required"`
	Metadata     *SSHMetadata `json:"metadata,omitempty" validate:"omitempty,dive"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty"`
	PcapFilename *string      `json:"pcap_filename" validate:"required"`
	Proto        *string      `json:"proto" validate:"required"`
	SSH          *SSHDetails  `json:"ssh" validate:"required,dive"`
	SrcIP        *string      `json:"src_ip" validate:"required"`
	SrcPort      *int         `json:"src_port" validate:"required"`
	Timestamp    *string      `json:"timestamp" validate:"required"`

	parsers.PantherLog
}

type SSHDetails struct {
	Client *SSHDetailsClient `json:"client" validate:"required,dive"`
	Server *SSHDetailsServer `json:"server" validate:"required,dive"`
}

type SSHDetailsClient struct {
	ProtoVersion    *string `json:"proto_version" validate:"required"`
	SoftwareVersion *string `json:"software_version" validate:"required"`
}

type SSHDetailsServer struct {
	ProtoVersion    *string `json:"proto_version" validate:"required"`
	SoftwareVersion *string `json:"software_version" validate:"required"`
}

type SSHMetadata struct {
	Flowints *SSHMetadataFlowints `json:"flowints" validate:"required,dive"`
}

type SSHMetadataFlowints struct {
	TCPRetransmissionCount *int `json:"tcp.retransmission.count" validate:"required"`
}

// SSHParser parses Suricata SSH alerts in the JSON format
type SSHParser struct{}

func (p *SSHParser) New() parsers.LogParser {
	return &SSHParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *SSHParser) Parse(log string) []interface{} {
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

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *SSHParser) LogType() string {
	return "Suricata.SSH"
}

func (event *SSH) updatePantherFields(p *SSHParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
