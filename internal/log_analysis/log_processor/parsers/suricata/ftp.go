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

var FTPDesc = `Suricata parser for the FTP event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type FTP struct {
	CommunityID  *string      `json:"community_id" validate:"required"`
	DestIP       *string      `json:"dest_ip" validate:"required"`
	DestPort     *int         `json:"dest_port" validate:"required"`
	EventType    *string      `json:"event_type" validate:"required"`
	FTP          *FTPDetails  `json:"ftp" validate:"required,dive"`
	FlowID       *int         `json:"flow_id" validate:"required"`
	Metadata     *FTPMetadata `json:"metadata" validate:"required,dive"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty"`
	PcapFilename *string      `json:"pcap_filename" validate:"required"`
	Proto        *string      `json:"proto" validate:"required"`
	SrcIP        *string      `json:"src_ip" validate:"required"`
	SrcPort      *int         `json:"src_port" validate:"required"`
	Timestamp    *string      `json:"timestamp" validate:"required"`
	TxID         *int         `json:"tx_id" validate:"required"`

	parsers.PantherLog
}

type FTPMetadata struct {
	Flowbits []string             `json:"flowbits,omitempty"`
	Flowints *FTPMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive"`
}

type FTPMetadataFlowints struct {
	ApplayerAnomalyCount *int `json:"applayer.anomaly.count" validate:"required"`
}

type FTPDetails struct {
	Command        *string  `json:"command,omitempty"`
	CommandData    *string  `json:"command_data,omitempty"`
	CompletionCode []string `json:"completion_code,omitempty"`
	DynamicPort    *int     `json:"dynamic_port,omitempty"`
	Reply          []string `json:"reply,omitempty"`
	ReplyReceived  *string  `json:"reply_received" validate:"required"`
}

// FTPParser parses Suricata FTP alerts in the JSON format
type FTPParser struct{}

func (p *FTPParser) New() parsers.LogParser {
	return &FTPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *FTPParser) Parse(log string) []interface{} {
	event := &FTP{}

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
func (p *FTPParser) LogType() string {
	return "Suricata.FTP"
}

func (event *FTP) updatePantherFields(p *FTPParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
