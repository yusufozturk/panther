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

var NfsDesc = `Suricata parser for the Nfs event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type Nfs struct {
	CommunityID  *string     `json:"community_id,omitempty" description:"Suricata Nfs CommunityID"`
	DestIP       *string     `json:"dest_ip" validate:"required" description:"Suricata Nfs DestIP"`
	DestPort     *int        `json:"dest_port,omitempty" description:"Suricata Nfs DestPort"`
	EventType    *string     `json:"event_type" validate:"required,eq=nfs" description:"Suricata Nfs EventType"`
	FlowID       *int        `json:"flow_id,omitempty" description:"Suricata Nfs FlowID"`
	Nfs          *NfsDetails `json:"nfs" validate:"required,dive" description:"Suricata Nfs Nfs"`
	PcapCnt      *int        `json:"pcap_cnt,omitempty" description:"Suricata Nfs PcapCnt"`
	PcapFilename *string     `json:"pcap_filename,omitempty" description:"Suricata Nfs PcapFilename"`
	Proto        *string     `json:"proto" validate:"required" description:"Suricata Nfs Proto"`
	RPC          *NfsRPC     `json:"rpc,omitempty" validate:"omitempty,dive" description:"Suricata Nfs RPC"`
	SrcIP        *string     `json:"src_ip" validate:"required" description:"Suricata Nfs SrcIP"`
	SrcPort      *int        `json:"src_port,omitempty" description:"Suricata Nfs SrcPort"`
	Timestamp    *string     `json:"timestamp" validate:"required" description:"Suricata Nfs Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type NfsRPC struct {
	AuthType *string      `json:"auth_type,omitempty" description:"Suricata NfsRPC AuthType"`
	Creds    *NfsRPCCreds `json:"creds,omitempty" validate:"omitempty,dive" description:"Suricata NfsRPC Creds"`
	Status   *string      `json:"status,omitempty" description:"Suricata NfsRPC Status"`
	Xid      *int         `json:"xid,omitempty" description:"Suricata NfsRPC Xid"`
}

//nolint:lll
type NfsRPCCreds struct {
	GID         *int    `json:"gid,omitempty" description:"Suricata NfsRPCCreds GID"`
	MachineName *string `json:"machine_name,omitempty" description:"Suricata NfsRPCCreds MachineName"`
	UID         *int    `json:"uid,omitempty" description:"Suricata NfsRPCCreds UID"`
}

//nolint:lll
type NfsDetails struct {
	FileTx    *bool             `json:"file_tx,omitempty" description:"Suricata NfsDetails FileTx"`
	Filename  *string           `json:"filename,omitempty" description:"Suricata NfsDetails Filename"`
	Hhash     *string           `json:"hhash,omitempty" description:"Suricata NfsDetails Hhash"`
	ID        *int              `json:"id,omitempty" description:"Suricata NfsDetails ID"`
	Procedure *string           `json:"procedure,omitempty" description:"Suricata NfsDetails Procedure"`
	Rename    *NfsDetailsRename `json:"rename,omitempty" validate:"omitempty,dive" description:"Suricata NfsDetails Rename"`
	Status    *string           `json:"status,omitempty" description:"Suricata NfsDetails Status"`
	Type      *string           `json:"type,omitempty" description:"Suricata NfsDetails Type"`
	Version   *int              `json:"version,omitempty" description:"Suricata NfsDetails Version"`
}

//nolint:lll
type NfsDetailsRename struct {
	From *string `json:"from,omitempty" description:"Suricata NfsDetailsRename From"`
	To   *string `json:"to,omitempty" description:"Suricata NfsDetailsRename To"`
}

// NfsParser parses Suricata Nfs alerts in the JSON format
type NfsParser struct{}

func (p *NfsParser) New() parsers.LogParser {
	return &NfsParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *NfsParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *NfsParser) LogType() string {
	return "Suricata.Nfs"
}

func (event *Nfs) updatePantherFields(p *NfsParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtr(event.SrcIP)
	event.AppendAnyIPAddressPtr(event.DestIP)
}
