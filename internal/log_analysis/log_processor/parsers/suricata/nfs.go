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

var NfsDesc = `Suricata parser for the Nfs event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Nfs struct {
	CommunityID  *string     `json:"community_id" validate:"required"`
	DestIP       *string     `json:"dest_ip" validate:"required"`
	DestPort     *int        `json:"dest_port" validate:"required"`
	EventType    *string     `json:"event_type" validate:"required"`
	FlowID       *int        `json:"flow_id" validate:"required"`
	Nfs          *NfsDetails `json:"nfs" validate:"required,dive"`
	PcapCnt      *int        `json:"pcap_cnt,omitempty"`
	PcapFilename *string     `json:"pcap_filename" validate:"required"`
	Proto        *string     `json:"proto" validate:"required"`
	RPC          *NfsRPC     `json:"rpc" validate:"required,dive"`
	SrcIP        *string     `json:"src_ip" validate:"required"`
	SrcPort      *int        `json:"src_port" validate:"required"`
	Timestamp    *string     `json:"timestamp" validate:"required"`

	parsers.PantherLog
}

type NfsRPC struct {
	AuthType *string      `json:"auth_type" validate:"required"`
	Creds    *NfsRPCCreds `json:"creds,omitempty" validate:"omitempty,dive"`
	Status   *string      `json:"status" validate:"required"`
	Xid      *int         `json:"xid" validate:"required"`
}

type NfsRPCCreds struct {
	GID         *int    `json:"gid" validate:"required"`
	MachineName *string `json:"machine_name" validate:"required"`
	UID         *int    `json:"uid" validate:"required"`
}

type NfsDetails struct {
	FileTx    *bool             `json:"file_tx" validate:"required"`
	Filename  *string           `json:"filename" validate:"required"`
	Hhash     *string           `json:"hhash,omitempty"`
	ID        *int              `json:"id" validate:"required"`
	Procedure *string           `json:"procedure" validate:"required"`
	Rename    *NfsDetailsRename `json:"rename,omitempty" validate:"omitempty,dive"`
	Status    *string           `json:"status" validate:"required"`
	Type      *string           `json:"type" validate:"required"`
	Version   *int              `json:"version" validate:"required"`
}

type NfsDetailsRename struct {
	From *string `json:"from" validate:"required"`
	To   *string `json:"to" validate:"required"`
}

// NfsParser parses Suricata Nfs alerts in the JSON format
type NfsParser struct{}

func (p *NfsParser) New() parsers.LogParser {
	return &NfsParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *NfsParser) Parse(log string) []interface{} {
	event := &Nfs{}

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
func (p *NfsParser) LogType() string {
	return "Suricata.Nfs"
}

func (event *Nfs) updatePantherFields(p *NfsParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
