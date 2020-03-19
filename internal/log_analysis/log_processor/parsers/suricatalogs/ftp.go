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

//nolint:lll
type FTP struct {
	CommunityID  *string      `json:"community_id,omitempty" description:"Suricata FTP CommunityID"`
	DestIP       *string      `json:"dest_ip" validate:"required" description:"Suricata FTP DestIP"`
	DestPort     *int         `json:"dest_port,omitempty" description:"Suricata FTP DestPort"`
	EventType    *string      `json:"event_type" validate:"required,eq=ftp" description:"Suricata FTP EventType"`
	FTP          *FTPDetails  `json:"ftp" validate:"required,dive" description:"Suricata FTP FTP"`
	FlowID       *int         `json:"flow_id,omitempty" description:"Suricata FTP FlowID"`
	Metadata     *FTPMetadata `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata FTP Metadata"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty" description:"Suricata FTP PcapCnt"`
	PcapFilename *string      `json:"pcap_filename,omitempty" description:"Suricata FTP PcapFilename"`
	Proto        *string      `json:"proto" validate:"required" description:"Suricata FTP Proto"`
	SrcIP        *string      `json:"src_ip" validate:"required" description:"Suricata FTP SrcIP"`
	SrcPort      *int         `json:"src_port,omitempty" description:"Suricata FTP SrcPort"`
	Timestamp    *string      `json:"timestamp" validate:"required" description:"Suricata FTP Timestamp"`
	TxID         *int         `json:"tx_id,omitempty" description:"Suricata FTP TxID"`

	parsers.PantherLog
}

//nolint:lll
type FTPMetadata struct {
	Flowbits []string             `json:"flowbits,omitempty" description:"Suricata FTPMetadata Flowbits"`
	Flowints *FTPMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata FTPMetadata Flowints"`
}

//nolint:lll
type FTPMetadataFlowints struct {
	ApplayerAnomalyCount *int `json:"applayer.anomaly.count,omitempty" description:"Suricata FTPMetadataFlowints ApplayerAnomalyCount"`
}

//nolint:lll
type FTPDetails struct {
	Command        *string  `json:"command,omitempty" description:"Suricata FTPDetails Command"`
	CommandData    *string  `json:"command_data,omitempty" description:"Suricata FTPDetails CommandData"`
	CompletionCode []string `json:"completion_code,omitempty" description:"Suricata FTPDetails CompletionCode"`
	DynamicPort    *int     `json:"dynamic_port,omitempty" description:"Suricata FTPDetails DynamicPort"`
	Reply          []string `json:"reply,omitempty" description:"Suricata FTPDetails Reply"`
	ReplyReceived  *string  `json:"reply_received,omitempty" description:"Suricata FTPDetails ReplyReceived"`
}

// FTPParser parses Suricata FTP alerts in the JSON format
type FTPParser struct{}

func (p *FTPParser) New() parsers.LogParser {
	return &FTPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *FTPParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *FTPParser) LogType() string {
	return "Suricata.FTP"
}

func (event *FTP) updatePantherFields(p *FTPParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
