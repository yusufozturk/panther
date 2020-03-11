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

var Dnp3Desc = `Suricata parser for the Dnp3 event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Dnp3 struct {
	CommunityID  *string      `json:"community_id" validate:"required"`
	DestIP       *string      `json:"dest_ip" validate:"required"`
	DestPort     *int         `json:"dest_port" validate:"required"`
	Dnp3         *Dnp3Details `json:"dnp3" validate:"required,dive"`
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

type Dnp3Details struct {
	Application *Dnp3DetailsApplication `json:"application" validate:"required,dive"`
	Control     *Dnp3DetailsControl     `json:"control" validate:"required,dive"`
	Dst         *int                    `json:"dst" validate:"required"`
	Iin         *Dnp3DetailsIin         `json:"iin,omitempty" validate:"omitempty,dive"`
	Src         *int                    `json:"src" validate:"required"`
	Type        *string                 `json:"type" validate:"required"`
}

type Dnp3DetailsControl struct {
	Dir          *bool `json:"dir" validate:"required"`
	Fcb          *bool `json:"fcb" validate:"required"`
	Fcv          *bool `json:"fcv" validate:"required"`
	FunctionCode *int  `json:"function_code" validate:"required"`
	Pri          *bool `json:"pri" validate:"required"`
}

type Dnp3DetailsApplication struct {
	Complete     *bool                           `json:"complete" validate:"required"`
	Control      *Dnp3DetailsApplicationControl  `json:"control" validate:"required,dive"`
	FunctionCode *int                            `json:"function_code" validate:"required"`
	Objects      []Dnp3DetailsApplicationObjects `json:"objects" validate:"required,dive"`
}

type Dnp3DetailsApplicationControl struct {
	Con      *bool `json:"con" validate:"required"`
	Fin      *bool `json:"fin" validate:"required"`
	Fir      *bool `json:"fir" validate:"required"`
	Sequence *int  `json:"sequence" validate:"required"`
	Uns      *bool `json:"uns" validate:"required"`
}

type Dnp3DetailsApplicationObjects struct {
	Count      *int                                  `json:"count" validate:"required"`
	Group      *int                                  `json:"group" validate:"required"`
	Points     []Dnp3DetailsApplicationObjectsPoints `json:"points,omitempty" validate:"omitempty,dive"`
	PrefixCode *int                                  `json:"prefix_code" validate:"required"`
	Qualifier  *int                                  `json:"qualifier" validate:"required"`
	RangeCode  *int                                  `json:"range_code" validate:"required"`
	Start      *int                                  `json:"start" validate:"required"`
	Stop       *int                                  `json:"stop" validate:"required"`
	Variation  *int                                  `json:"variation" validate:"required"`
}

type Dnp3DetailsApplicationObjectsPoints struct {
	AuthenticationKey  *int    `json:"authentication_key,omitempty"`
	BlockNumber        *int    `json:"block_number,omitempty"`
	ChallengeDataLen   *int    `json:"challenge_data_len,omitempty"`
	ChatterFilter      *int    `json:"chatter_filter,omitempty"`
	CommLost           *int    `json:"comm_lost,omitempty"`
	Count              *int    `json:"count,omitempty"`
	Cr                 *int    `json:"cr,omitempty"`
	Created            *int    `json:"created,omitempty"`
	DataMacValue       *string `json:"data->mac_value,omitempty"`
	DataWrappedKeyData *string `json:"data->wrapped_key_data,omitempty"`
	DelayMs            *int    `json:"delay_ms,omitempty"`
	FileData           *string `json:"file_data,omitempty"`
	FileHandle         *int    `json:"file_handle,omitempty"`
	FileSize           *int    `json:"file_size,omitempty"`
	Filename           *string `json:"filename,omitempty"`
	FilenameOffset     *int    `json:"filename_offset,omitempty"`
	FilenameSize       *int    `json:"filename_size,omitempty"`
	Index              *int    `json:"index" validate:"required"`
	KeyStatus          *int    `json:"key_status,omitempty"`
	KeyWrapAlg         *int    `json:"key_wrap_alg,omitempty"`
	Ksq                *int    `json:"ksq,omitempty"`
	LocalForced        *int    `json:"local_forced,omitempty"`
	Mal                *int    `json:"mal,omitempty"`
	MaximumBlockSize   *int    `json:"maximum_block_size,omitempty"`
	Offtime            *int    `json:"offtime,omitempty"`
	Online             *int    `json:"online,omitempty"`
	Ontime             *int    `json:"ontime,omitempty"`
	OpType             *int    `json:"op_type,omitempty"`
	OperationalMode    *int    `json:"operational_mode,omitempty"`
	OptionalText       *string `json:"optional_text,omitempty"`
	OverRange          *int    `json:"over_range,omitempty"`
	Permissions        *int    `json:"permissions,omitempty"`
	Prefix             *int    `json:"prefix" validate:"required"`
	Qu                 *int    `json:"qu,omitempty"`
	ReferenceErr       *int    `json:"reference_err,omitempty"`
	RemoteForced       *int    `json:"remote_forced,omitempty"`
	RequestID          *int    `json:"request_id,omitempty"`
	Reserved           *int    `json:"reserved,omitempty"`
	Reserved0          *int    `json:"reserved0,omitempty"`
	Reserved1          *int    `json:"reserved1,omitempty"`
	Restart            *int    `json:"restart,omitempty"`
	Size               *int    `json:"size,omitempty"`
	State              *int    `json:"state,omitempty"`
	StatusCode         *int    `json:"status_code,omitempty"`
	Tcc                *int    `json:"tcc,omitempty"`
	Timestamp          *int    `json:"timestamp,omitempty"`
	UserNumber         *int    `json:"user_number,omitempty"`
	Usr                *int    `json:"usr,omitempty"`
	Value              *int    `json:"value,omitempty"`
}

type Dnp3DetailsIin struct {
	Indicators []string `json:"indicators" validate:"required"`
}

// Dnp3Parser parses Suricata Dnp3 alerts in the JSON format
type Dnp3Parser struct{}

func (p *Dnp3Parser) New() parsers.LogParser {
	return &Dnp3Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *Dnp3Parser) Parse(log string) []interface{} {
	event := &Dnp3{}

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
func (p *Dnp3Parser) LogType() string {
	return "Suricata.Dnp3"
}

func (event *Dnp3) updatePantherFields(p *Dnp3Parser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
