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

var Krb5Desc = `Suricata parser for the Krb5 event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Krb5 struct {
	CommunityID  *string       `json:"community_id" validate:"required"`
	DestIP       *string       `json:"dest_ip" validate:"required"`
	DestPort     *int          `json:"dest_port" validate:"required"`
	EventType    *string       `json:"event_type" validate:"required"`
	FlowID       *int          `json:"flow_id" validate:"required"`
	Krb5         *Krb5Details  `json:"krb5" validate:"required,dive"`
	Metadata     *Krb5Metadata `json:"metadata,omitempty" validate:"omitempty,dive"`
	PcapCnt      *int          `json:"pcap_cnt" validate:"required"`
	PcapFilename *string       `json:"pcap_filename" validate:"required"`
	Proto        *string       `json:"proto" validate:"required"`
	SrcIP        *string       `json:"src_ip" validate:"required"`
	SrcPort      *int          `json:"src_port" validate:"required"`
	Timestamp    *string       `json:"timestamp" validate:"required"`

	parsers.PantherLog
}

type Krb5Details struct {
	Cname          *string `json:"cname" validate:"required"`
	Encryption     *string `json:"encryption" validate:"required"`
	ErrorCode      *string `json:"error_code,omitempty"`
	FailedRequest  *string `json:"failed_request,omitempty"`
	MsgType        *string `json:"msg_type" validate:"required"`
	Realm          *string `json:"realm" validate:"required"`
	Sname          *string `json:"sname" validate:"required"`
	WeakEncryption *bool   `json:"weak_encryption" validate:"required"`
}

type Krb5Metadata struct {
	Flowints *Krb5MetadataFlowints `json:"flowints" validate:"required,dive"`
}

type Krb5MetadataFlowints struct {
	ApplayerAnomalyCount *int `json:"applayer.anomaly.count" validate:"required"`
}

// Krb5Parser parses Suricata Krb5 alerts in the JSON format
type Krb5Parser struct{}

func (p *Krb5Parser) New() parsers.LogParser {
	return &Krb5Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *Krb5Parser) Parse(log string) []interface{} {
	event := &Krb5{}

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
func (p *Krb5Parser) LogType() string {
	return "Suricata.Krb5"
}

func (event *Krb5) updatePantherFields(p *Krb5Parser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
