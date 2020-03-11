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

var SmbDesc = `Suricata parser for the Smb event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Smb struct {
	DestIP       *string     `json:"dest_ip" validate:"required"`
	DestPort     *int        `json:"dest_port" validate:"required"`
	EventType    *string     `json:"event_type" validate:"required"`
	FlowID       *int        `json:"flow_id" validate:"required"`
	PcapCnt      *int        `json:"pcap_cnt,omitempty"`
	PcapFilename *string     `json:"pcap_filename" validate:"required"`
	Proto        *string     `json:"proto" validate:"required"`
	Smb          *SmbDetails `json:"smb" validate:"required,dive"`
	SrcIP        *string     `json:"src_ip" validate:"required"`
	SrcPort      *int        `json:"src_port" validate:"required"`
	Timestamp    *string     `json:"timestamp" validate:"required"`

	parsers.PantherLog
}

type SmbDetails struct {
	Access         *string             `json:"access,omitempty"`
	Accessed       *int                `json:"accessed,omitempty"`
	Changed        *int                `json:"changed,omitempty"`
	ClientDialects []string            `json:"client_dialects,omitempty"`
	ClientGUID     *string             `json:"client_guid,omitempty"`
	Command        *string             `json:"command" validate:"required"`
	Created        *int                `json:"created,omitempty"`
	Dcerpc         *SmbDetailsDcerpc   `json:"dcerpc,omitempty" validate:"omitempty,dive"`
	Dialect        *string             `json:"dialect" validate:"required"`
	Directory      *string             `json:"directory,omitempty"`
	Disposition    *string             `json:"disposition,omitempty"`
	Filename       *string             `json:"filename,omitempty"`
	Fuid           *string             `json:"fuid,omitempty"`
	Function       *string             `json:"function,omitempty"`
	ID             *int                `json:"id" validate:"required"`
	Kerberos       *SmbDetailsKerberos `json:"kerberos,omitempty" validate:"omitempty,dive"`
	Modified       *int                `json:"modified,omitempty"`
	NamedPipe      *string             `json:"named_pipe,omitempty"`
	Ntlmssp        *SmbDetailsNtlmssp  `json:"ntlmssp,omitempty" validate:"omitempty,dive"`
	Rename         *SmbDetailsRename   `json:"rename,omitempty" validate:"omitempty,dive"`
	Request        *SmbDetailsRequest  `json:"request,omitempty" validate:"omitempty,dive"`
	Response       *SmbDetailsResponse `json:"response,omitempty" validate:"omitempty,dive"`
	ServerGUID     *string             `json:"server_guid,omitempty"`
	Service        *SmbDetailsService  `json:"service,omitempty" validate:"omitempty,dive"`
	SessionID      *int                `json:"session_id" validate:"required"`
	SetInfo        *SmbDetailsSetInfo  `json:"set_info,omitempty" validate:"omitempty,dive"`
	Share          *string             `json:"share,omitempty"`
	ShareType      *string             `json:"share_type,omitempty"`
	Size           *int                `json:"size,omitempty"`
	Status         *string             `json:"status,omitempty"`
	StatusCode     *string             `json:"status_code,omitempty"`
	TreeID         *int                `json:"tree_id" validate:"required"`
}

type SmbDetailsNtlmssp struct {
	Domain *string `json:"domain" validate:"required"`
	Host   *string `json:"host" validate:"required"`
	User   *string `json:"user" validate:"required"`
}

type SmbDetailsDcerpc struct {
	CallID     *int                         `json:"call_id" validate:"required"`
	Interfaces []SmbDetailsDcerpcInterfaces `json:"interfaces,omitempty" validate:"omitempty,dive"`
	Opnum      *int                         `json:"opnum,omitempty"`
	Req        *SmbDetailsDcerpcReq         `json:"req,omitempty" validate:"omitempty,dive"`
	Request    *string                      `json:"request" validate:"required"`
	Res        *SmbDetailsDcerpcRes         `json:"res,omitempty" validate:"omitempty,dive"`
	Response   *string                      `json:"response" validate:"required"`
}

type SmbDetailsDcerpcInterfaces struct {
	AckReason *int    `json:"ack_reason,omitempty"`
	AckResult *int    `json:"ack_result,omitempty"`
	UUID      *string `json:"uuid" validate:"required"`
	Version   *string `json:"version" validate:"required"`
}

type SmbDetailsDcerpcReq struct {
	FragCnt      *int `json:"frag_cnt" validate:"required"`
	StubDataSize *int `json:"stub_data_size" validate:"required"`
}

type SmbDetailsDcerpcRes struct {
	FragCnt      *int `json:"frag_cnt" validate:"required"`
	StubDataSize *int `json:"stub_data_size" validate:"required"`
}

type SmbDetailsRequest struct {
	NativeLm *string `json:"native_lm" validate:"required"`
	NativeOs *string `json:"native_os" validate:"required"`
}

type SmbDetailsResponse struct {
	NativeLm *string `json:"native_lm" validate:"required"`
	NativeOs *string `json:"native_os" validate:"required"`
}

type SmbDetailsService struct {
	Request  *string `json:"request" validate:"required"`
	Response *string `json:"response,omitempty"`
}

type SmbDetailsKerberos struct {
	Realm  *string  `json:"realm" validate:"required"`
	Snames []string `json:"snames" validate:"required"`
}

type SmbDetailsSetInfo struct {
	Class     *string `json:"class" validate:"required"`
	InfoLevel *string `json:"info_level" validate:"required"`
}

type SmbDetailsRename struct {
	From *string `json:"from" validate:"required"`
	To   *string `json:"to" validate:"required"`
}

// SmbParser parses Suricata Smb alerts in the JSON format
type SmbParser struct{}

func (p *SmbParser) New() parsers.LogParser {
	return &SmbParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *SmbParser) Parse(log string) []interface{} {
	event := &Smb{}

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
func (p *SmbParser) LogType() string {
	return "Suricata.Smb"
}

func (event *Smb) updatePantherFields(p *SmbParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
