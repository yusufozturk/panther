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

var DropDesc = `Suricata parser for the Drop event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Drop struct {
	Alert        *DropAlert   `json:"alert,omitempty" validate:"omitempty,dive"`
	CommunityID  *string      `json:"community_id" validate:"required"`
	DestIP       *string      `json:"dest_ip" validate:"required"`
	DestPort     *int         `json:"dest_port" validate:"required"`
	Drop         *DropDetails `json:"drop" validate:"required,dive"`
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

type DropDetails struct {
	Ack     *bool `json:"ack" validate:"required"`
	Fin     *bool `json:"fin" validate:"required"`
	Ipid    *int  `json:"ipid" validate:"required"`
	Len     *int  `json:"len" validate:"required"`
	Psh     *bool `json:"psh" validate:"required"`
	Rst     *bool `json:"rst" validate:"required"`
	Syn     *bool `json:"syn" validate:"required"`
	TTL     *int  `json:"ttl" validate:"required"`
	Tcpack  *int  `json:"tcpack" validate:"required"`
	Tcpres  *int  `json:"tcpres" validate:"required"`
	Tcpseq  *int  `json:"tcpseq" validate:"required"`
	Tcpurgp *int  `json:"tcpurgp" validate:"required"`
	Tcpwin  *int  `json:"tcpwin" validate:"required"`
	Tos     *int  `json:"tos" validate:"required"`
	Urg     *bool `json:"urg" validate:"required"`
}

type DropAlert struct {
	Action      *string `json:"action" validate:"required"`
	Category    *string `json:"category" validate:"required"`
	GID         *int    `json:"gid" validate:"required"`
	Rev         *int    `json:"rev" validate:"required"`
	Severity    *int    `json:"severity" validate:"required"`
	Signature   *string `json:"signature" validate:"required"`
	SignatureID *int    `json:"signature_id" validate:"required"`
}

// DropParser parses Suricata Drop alerts in the JSON format
type DropParser struct{}

func (p *DropParser) New() parsers.LogParser {
	return &DropParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *DropParser) Parse(log string) []interface{} {
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

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *DropParser) LogType() string {
	return "Suricata.Drop"
}

func (event *Drop) updatePantherFields(p *DropParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
