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

var DropDesc = `Suricata parser for the Drop event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type Drop struct {
	Alert        *DropAlert   `json:"alert,omitempty" validate:"omitempty,dive" description:"Suricata Drop Alert"`
	CommunityID  *string      `json:"community_id,omitempty" description:"Suricata Drop CommunityID"`
	DestIP       *string      `json:"dest_ip" validate:"required" description:"Suricata Drop DestIP"`
	DestPort     *int         `json:"dest_port,omitempty" description:"Suricata Drop DestPort"`
	Drop         *DropDetails `json:"drop" validate:"required,dive" description:"Suricata Drop Drop"`
	EventType    *string      `json:"event_type" validate:"required,eq=drop" description:"Suricata Drop EventType"`
	FlowID       *int         `json:"flow_id,omitempty" description:"Suricata Drop FlowID"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty" description:"Suricata Drop PcapCnt"`
	PcapFilename *string      `json:"pcap_filename,omitempty" description:"Suricata Drop PcapFilename"`
	Proto        *string      `json:"proto" validate:"required" description:"Suricata Drop Proto"`
	SrcIP        *string      `json:"src_ip" validate:"required" description:"Suricata Drop SrcIP"`
	SrcPort      *int         `json:"src_port,omitempty" description:"Suricata Drop SrcPort"`
	Timestamp    *string      `json:"timestamp" validate:"required" description:"Suricata Drop Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type DropDetails struct {
	Ack     *bool `json:"ack,omitempty" description:"Suricata DropDetails Ack"`
	Fin     *bool `json:"fin,omitempty" description:"Suricata DropDetails Fin"`
	Ipid    *int  `json:"ipid,omitempty" description:"Suricata DropDetails Ipid"`
	Len     *int  `json:"len,omitempty" description:"Suricata DropDetails Len"`
	Psh     *bool `json:"psh,omitempty" description:"Suricata DropDetails Psh"`
	Rst     *bool `json:"rst,omitempty" description:"Suricata DropDetails Rst"`
	Syn     *bool `json:"syn,omitempty" description:"Suricata DropDetails Syn"`
	TTL     *int  `json:"ttl,omitempty" description:"Suricata DropDetails TTL"`
	Tcpack  *int  `json:"tcpack,omitempty" description:"Suricata DropDetails Tcpack"`
	Tcpres  *int  `json:"tcpres,omitempty" description:"Suricata DropDetails Tcpres"`
	Tcpseq  *int  `json:"tcpseq,omitempty" description:"Suricata DropDetails Tcpseq"`
	Tcpurgp *int  `json:"tcpurgp,omitempty" description:"Suricata DropDetails Tcpurgp"`
	Tcpwin  *int  `json:"tcpwin,omitempty" description:"Suricata DropDetails Tcpwin"`
	Tos     *int  `json:"tos,omitempty" description:"Suricata DropDetails Tos"`
	Urg     *bool `json:"urg,omitempty" description:"Suricata DropDetails Urg"`
}

//nolint:lll
type DropAlert struct {
	Action      *string `json:"action,omitempty" description:"Suricata DropAlert Action"`
	Category    *string `json:"category,omitempty" description:"Suricata DropAlert Category"`
	GID         *int    `json:"gid,omitempty" description:"Suricata DropAlert GID"`
	Rev         *int    `json:"rev,omitempty" description:"Suricata DropAlert Rev"`
	Severity    *int    `json:"severity,omitempty" description:"Suricata DropAlert Severity"`
	Signature   *string `json:"signature,omitempty" description:"Suricata DropAlert Signature"`
	SignatureID *int    `json:"signature_id,omitempty" description:"Suricata DropAlert SignatureID"`
}

// DropParser parses Suricata Drop alerts in the JSON format
type DropParser struct{}

func (p *DropParser) New() parsers.LogParser {
	return &DropParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *DropParser) Parse(log string) []*parsers.PantherLog {
	event := &Drop{}

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
func (p *DropParser) LogType() string {
	return "Suricata.Drop"
}

func (event *Drop) updatePantherFields(p *DropParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtr(event.SrcIP)
	event.AppendAnyIPAddressPtr(event.DestIP)
}
