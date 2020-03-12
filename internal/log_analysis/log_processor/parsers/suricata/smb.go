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

//nolint:lll
type Smb struct {
	DestIP       *string     `json:"dest_ip" validate:"required" description:"Suricata Smb DestIP"`
	DestPort     *int        `json:"dest_port,omitempty" description:"Suricata Smb DestPort"`
	EventType    *string     `json:"event_type" validate:"required" description:"Suricata Smb EventType"`
	FlowID       *int        `json:"flow_id,omitempty" description:"Suricata Smb FlowID"`
	PcapCnt      *int        `json:"pcap_cnt,omitempty" description:"Suricata Smb PcapCnt"`
	PcapFilename *string     `json:"pcap_filename,omitempty" description:"Suricata Smb PcapFilename"`
	Proto        *string     `json:"proto" validate:"required" description:"Suricata Smb Proto"`
	Smb          *SmbDetails `json:"smb" validate:"required,dive" description:"Suricata Smb Smb"`
	SrcIP        *string     `json:"src_ip" validate:"required" description:"Suricata Smb SrcIP"`
	SrcPort      *int        `json:"src_port,omitempty" description:"Suricata Smb SrcPort"`
	Timestamp    *string     `json:"timestamp" validate:"required" description:"Suricata Smb Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type SmbDetails struct {
	Access         *string             `json:"access,omitempty" description:"Suricata SmbDetails Access"`
	Accessed       *int                `json:"accessed,omitempty" description:"Suricata SmbDetails Accessed"`
	Changed        *int                `json:"changed,omitempty" description:"Suricata SmbDetails Changed"`
	ClientDialects []string            `json:"client_dialects,omitempty" description:"Suricata SmbDetails ClientDialects"`
	ClientGUID     *string             `json:"client_guid,omitempty" description:"Suricata SmbDetails ClientGUID"`
	Command        *string             `json:"command,omitempty" description:"Suricata SmbDetails Command"`
	Created        *int                `json:"created,omitempty" description:"Suricata SmbDetails Created"`
	Dcerpc         *SmbDetailsDcerpc   `json:"dcerpc,omitempty" validate:"omitempty,dive" description:"Suricata SmbDetails Dcerpc"`
	Dialect        *string             `json:"dialect,omitempty" description:"Suricata SmbDetails Dialect"`
	Directory      *string             `json:"directory,omitempty" description:"Suricata SmbDetails Directory"`
	Disposition    *string             `json:"disposition,omitempty" description:"Suricata SmbDetails Disposition"`
	Filename       *string             `json:"filename,omitempty" description:"Suricata SmbDetails Filename"`
	Fuid           *string             `json:"fuid,omitempty" description:"Suricata SmbDetails Fuid"`
	Function       *string             `json:"function,omitempty" description:"Suricata SmbDetails Function"`
	ID             *int                `json:"id,omitempty" description:"Suricata SmbDetails ID"`
	Kerberos       *SmbDetailsKerberos `json:"kerberos,omitempty" validate:"omitempty,dive" description:"Suricata SmbDetails Kerberos"`
	Modified       *int                `json:"modified,omitempty" description:"Suricata SmbDetails Modified"`
	NamedPipe      *string             `json:"named_pipe,omitempty" description:"Suricata SmbDetails NamedPipe"`
	Ntlmssp        *SmbDetailsNtlmssp  `json:"ntlmssp,omitempty" validate:"omitempty,dive" description:"Suricata SmbDetails Ntlmssp"`
	Rename         *SmbDetailsRename   `json:"rename,omitempty" validate:"omitempty,dive" description:"Suricata SmbDetails Rename"`
	Request        *SmbDetailsRequest  `json:"request,omitempty" validate:"omitempty,dive" description:"Suricata SmbDetails Request"`
	Response       *SmbDetailsResponse `json:"response,omitempty" validate:"omitempty,dive" description:"Suricata SmbDetails Response"`
	ServerGUID     *string             `json:"server_guid,omitempty" description:"Suricata SmbDetails ServerGUID"`
	Service        *SmbDetailsService  `json:"service,omitempty" validate:"omitempty,dive" description:"Suricata SmbDetails Service"`
	SessionID      *int                `json:"session_id,omitempty" description:"Suricata SmbDetails SessionID"`
	SetInfo        *SmbDetailsSetInfo  `json:"set_info,omitempty" validate:"omitempty,dive" description:"Suricata SmbDetails SetInfo"`
	Share          *string             `json:"share,omitempty" description:"Suricata SmbDetails Share"`
	ShareType      *string             `json:"share_type,omitempty" description:"Suricata SmbDetails ShareType"`
	Size           *int                `json:"size,omitempty" description:"Suricata SmbDetails Size"`
	Status         *string             `json:"status,omitempty" description:"Suricata SmbDetails Status"`
	StatusCode     *string             `json:"status_code,omitempty" description:"Suricata SmbDetails StatusCode"`
	TreeID         *int                `json:"tree_id,omitempty" description:"Suricata SmbDetails TreeID"`
}

//nolint:lll
type SmbDetailsNtlmssp struct {
	Domain *string `json:"domain,omitempty" description:"Suricata SmbDetailsNtlmssp Domain"`
	Host   *string `json:"host,omitempty" description:"Suricata SmbDetailsNtlmssp Host"`
	User   *string `json:"user,omitempty" description:"Suricata SmbDetailsNtlmssp User"`
}

//nolint:lll
type SmbDetailsDcerpc struct {
	CallID     *int                 `json:"call_id,omitempty" description:"Suricata SmbDetailsDcerpc CallID"`
	Interfaces *jsoniter.RawMessage `json:"interfaces,omitempty" description:"Suricata SmbDetailsDcerpc Interfaces"`
	Opnum      *int                 `json:"opnum,omitempty" description:"Suricata SmbDetailsDcerpc Opnum"`
	Req        *jsoniter.RawMessage `json:"req,omitempty" description:"Suricata SmbDetailsDcerpc Req"`
	Request    *string              `json:"request,omitempty" description:"Suricata SmbDetailsDcerpc Request"`
	Res        *jsoniter.RawMessage `json:"res,omitempty" description:"Suricata SmbDetailsDcerpc Res"`
	Response   *string              `json:"response,omitempty" description:"Suricata SmbDetailsDcerpc Response"`
}

//nolint:lll
type SmbDetailsRequest struct {
	NativeLm *string `json:"native_lm,omitempty" description:"Suricata SmbDetailsRequest NativeLm"`
	NativeOs *string `json:"native_os,omitempty" description:"Suricata SmbDetailsRequest NativeOs"`
}

//nolint:lll
type SmbDetailsResponse struct {
	NativeLm *string `json:"native_lm,omitempty" description:"Suricata SmbDetailsResponse NativeLm"`
	NativeOs *string `json:"native_os,omitempty" description:"Suricata SmbDetailsResponse NativeOs"`
}

//nolint:lll
type SmbDetailsService struct {
	Request  *string `json:"request,omitempty" description:"Suricata SmbDetailsService Request"`
	Response *string `json:"response,omitempty" description:"Suricata SmbDetailsService Response"`
}

//nolint:lll
type SmbDetailsKerberos struct {
	Realm  *string  `json:"realm,omitempty" description:"Suricata SmbDetailsKerberos Realm"`
	Snames []string `json:"snames,omitempty" description:"Suricata SmbDetailsKerberos Snames"`
}

//nolint:lll
type SmbDetailsSetInfo struct {
	Class     *string `json:"class,omitempty" description:"Suricata SmbDetailsSetInfo Class"`
	InfoLevel *string `json:"info_level,omitempty" description:"Suricata SmbDetailsSetInfo InfoLevel"`
}

//nolint:lll
type SmbDetailsRename struct {
	From *string `json:"from,omitempty" description:"Suricata SmbDetailsRename From"`
	To   *string `json:"to,omitempty" description:"Suricata SmbDetailsRename To"`
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
