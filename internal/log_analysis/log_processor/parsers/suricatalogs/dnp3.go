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

//nolint:lll
type Dnp3 struct {
	CommunityID  *string      `json:"community_id,omitempty" description:"Suricata Dnp3 CommunityID"`
	DestIP       *string      `json:"dest_ip" validate:"required" description:"Suricata Dnp3 DestIP"`
	DestPort     *int         `json:"dest_port,omitempty" description:"Suricata Dnp3 DestPort"`
	Dnp3         *Dnp3Details `json:"dnp3" validate:"required,dive" description:"Suricata Dnp3 Dnp3"`
	EventType    *string      `json:"event_type" validate:"required,eq=dnp3" description:"Suricata Dnp3 EventType"`
	FlowID       *int         `json:"flow_id,omitempty" description:"Suricata Dnp3 FlowID"`
	PcapCnt      *int         `json:"pcap_cnt,omitempty" description:"Suricata Dnp3 PcapCnt"`
	PcapFilename *string      `json:"pcap_filename,omitempty" description:"Suricata Dnp3 PcapFilename"`
	Proto        *string      `json:"proto" validate:"required" description:"Suricata Dnp3 Proto"`
	SrcIP        *string      `json:"src_ip" validate:"required" description:"Suricata Dnp3 SrcIP"`
	SrcPort      *int         `json:"src_port,omitempty" description:"Suricata Dnp3 SrcPort"`
	Timestamp    *string      `json:"timestamp" validate:"required" description:"Suricata Dnp3 Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type Dnp3Details struct {
	Application *Dnp3DetailsApplication `json:"application,omitempty" validate:"omitempty,dive" description:"Suricata Dnp3Details Application"`
	Control     *Dnp3DetailsControl     `json:"control,omitempty" validate:"omitempty,dive" description:"Suricata Dnp3Details Control"`
	Dst         *int                    `json:"dst,omitempty" description:"Suricata Dnp3Details Dst"`
	Iin         *Dnp3DetailsIin         `json:"iin,omitempty" validate:"omitempty,dive" description:"Suricata Dnp3Details Iin"`
	Src         *int                    `json:"src,omitempty" description:"Suricata Dnp3Details Src"`
	Type        *string                 `json:"type,omitempty" description:"Suricata Dnp3Details Type"`
}

//nolint:lll
type Dnp3DetailsControl struct {
	Dir          *bool `json:"dir,omitempty" description:"Suricata Dnp3DetailsControl Dir"`
	Fcb          *bool `json:"fcb,omitempty" description:"Suricata Dnp3DetailsControl Fcb"`
	Fcv          *bool `json:"fcv,omitempty" description:"Suricata Dnp3DetailsControl Fcv"`
	FunctionCode *int  `json:"function_code,omitempty" description:"Suricata Dnp3DetailsControl FunctionCode"`
	Pri          *bool `json:"pri,omitempty" description:"Suricata Dnp3DetailsControl Pri"`
}

//nolint:lll
type Dnp3DetailsApplication struct {
	Complete     *bool                `json:"complete,omitempty" description:"Suricata Dnp3DetailsApplication Complete"`
	Control      *jsoniter.RawMessage `json:"control,omitempty" description:"Suricata Dnp3DetailsApplication Control"`
	FunctionCode *int                 `json:"function_code,omitempty" description:"Suricata Dnp3DetailsApplication FunctionCode"`
	Objects      *jsoniter.RawMessage `json:"objects,omitempty" description:"Suricata Dnp3DetailsApplication Objects"`
}

//nolint:lll
type Dnp3DetailsIin struct {
	Indicators []string `json:"indicators,omitempty" description:"Suricata Dnp3DetailsIin Indicators"`
}

// Dnp3Parser parses Suricata Dnp3 alerts in the JSON format
type Dnp3Parser struct{}

func (p *Dnp3Parser) New() parsers.LogParser {
	return &Dnp3Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *Dnp3Parser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *Dnp3Parser) LogType() string {
	return "Suricata.Dnp3"
}

func (event *Dnp3) updatePantherFields(p *Dnp3Parser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
