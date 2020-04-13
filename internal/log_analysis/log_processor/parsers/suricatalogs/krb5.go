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

var Krb5Desc = `Suricata parser for the Krb5 event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type Krb5 struct {
	CommunityID  *string       `json:"community_id,omitempty" description:"Suricata Krb5 CommunityID"`
	DestIP       *string       `json:"dest_ip" validate:"required" description:"Suricata Krb5 DestIP"`
	DestPort     *int          `json:"dest_port,omitempty" description:"Suricata Krb5 DestPort"`
	EventType    *string       `json:"event_type" validate:"required,eq=krb5" description:"Suricata Krb5 EventType"`
	FlowID       *int          `json:"flow_id,omitempty" description:"Suricata Krb5 FlowID"`
	Krb5         *Krb5Details  `json:"krb5" validate:"required,dive" description:"Suricata Krb5 Krb5"`
	Metadata     *Krb5Metadata `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata Krb5 Metadata"`
	PcapCnt      *int          `json:"pcap_cnt,omitempty" description:"Suricata Krb5 PcapCnt"`
	PcapFilename *string       `json:"pcap_filename,omitempty" description:"Suricata Krb5 PcapFilename"`
	Proto        *string       `json:"proto" validate:"required" description:"Suricata Krb5 Proto"`
	SrcIP        *string       `json:"src_ip" validate:"required" description:"Suricata Krb5 SrcIP"`
	SrcPort      *int          `json:"src_port,omitempty" description:"Suricata Krb5 SrcPort"`
	Timestamp    *string       `json:"timestamp" validate:"required" description:"Suricata Krb5 Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type Krb5Details struct {
	Cname          *string `json:"cname,omitempty" description:"Suricata Krb5Details Cname"`
	Encryption     *string `json:"encryption,omitempty" description:"Suricata Krb5Details Encryption"`
	ErrorCode      *string `json:"error_code,omitempty" description:"Suricata Krb5Details ErrorCode"`
	FailedRequest  *string `json:"failed_request,omitempty" description:"Suricata Krb5Details FailedRequest"`
	MsgType        *string `json:"msg_type,omitempty" description:"Suricata Krb5Details MsgType"`
	Realm          *string `json:"realm,omitempty" description:"Suricata Krb5Details Realm"`
	Sname          *string `json:"sname,omitempty" description:"Suricata Krb5Details Sname"`
	WeakEncryption *bool   `json:"weak_encryption,omitempty" description:"Suricata Krb5Details WeakEncryption"`
}

//nolint:lll
type Krb5Metadata struct {
	Flowints *Krb5MetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata Krb5Metadata Flowints"`
}

//nolint:lll
type Krb5MetadataFlowints struct {
	ApplayerAnomalyCount *int `json:"applayer.anomaly.count,omitempty" description:"Suricata Krb5MetadataFlowints ApplayerAnomalyCount"`
}

// Krb5Parser parses Suricata Krb5 alerts in the JSON format
type Krb5Parser struct{}

func (p *Krb5Parser) New() parsers.LogParser {
	return &Krb5Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *Krb5Parser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *Krb5Parser) LogType() string {
	return "Suricata.Krb5"
}

func (event *Krb5) updatePantherFields(p *Krb5Parser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtr(event.SrcIP)
	event.AppendAnyIPAddressPtr(event.DestIP)
}
