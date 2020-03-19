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

var Ikev2Desc = `Suricata parser for the Ikev2 event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

//nolint:lll
type Ikev2 struct {
	CommunityID  *string       `json:"community_id,omitempty" description:"Suricata Ikev2 CommunityID"`
	DestIP       *string       `json:"dest_ip" validate:"required" description:"Suricata Ikev2 DestIP"`
	DestPort     *int          `json:"dest_port,omitempty" description:"Suricata Ikev2 DestPort"`
	EventType    *string       `json:"event_type" validate:"required" description:"Suricata Ikev2 EventType"`
	FlowID       *int          `json:"flow_id,omitempty" description:"Suricata Ikev2 FlowID"`
	Ikev2        *Ikev2Details `json:"ikev2" validate:"required,dive" description:"Suricata Ikev2 Ikev2"`
	PcapCnt      *int          `json:"pcap_cnt,omitempty" description:"Suricata Ikev2 PcapCnt"`
	PcapFilename *string       `json:"pcap_filename,omitempty" description:"Suricata Ikev2 PcapFilename"`
	Proto        *string       `json:"proto" validate:"required" description:"Suricata Ikev2 Proto"`
	SrcIP        *string       `json:"src_ip" validate:"required" description:"Suricata Ikev2 SrcIP"`
	SrcPort      *int          `json:"src_port,omitempty" description:"Suricata Ikev2 SrcPort"`
	Timestamp    *string       `json:"timestamp" validate:"required" description:"Suricata Ikev2 Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type Ikev2Details struct {
	AlgAuth      *string  `json:"alg_auth,omitempty" description:"Suricata Ikev2Details AlgAuth"`
	AlgDh        *string  `json:"alg_dh,omitempty" description:"Suricata Ikev2Details AlgDh"`
	AlgEnc       *string  `json:"alg_enc,omitempty" description:"Suricata Ikev2Details AlgEnc"`
	AlgEsn       *string  `json:"alg_esn,omitempty" description:"Suricata Ikev2Details AlgEsn"`
	AlgPrf       *string  `json:"alg_prf,omitempty" description:"Suricata Ikev2Details AlgPrf"`
	Errors       *int     `json:"errors,omitempty" description:"Suricata Ikev2Details Errors"`
	ExchangeType *int     `json:"exchange_type,omitempty" description:"Suricata Ikev2Details ExchangeType"`
	InitSpi      *string  `json:"init_spi,omitempty" description:"Suricata Ikev2Details InitSpi"`
	MessageID    *int     `json:"message_id,omitempty" description:"Suricata Ikev2Details MessageID"`
	Notify       []string `json:"notify,omitempty" description:"Suricata Ikev2Details Notify"`
	Payload      []string `json:"payload,omitempty" description:"Suricata Ikev2Details Payload"`
	RespSpi      *string  `json:"resp_spi,omitempty" description:"Suricata Ikev2Details RespSpi"`
	Role         *string  `json:"role,omitempty" description:"Suricata Ikev2Details Role"`
	VersionMajor *int     `json:"version_major,omitempty" description:"Suricata Ikev2Details VersionMajor"`
	VersionMinor *int     `json:"version_minor,omitempty" description:"Suricata Ikev2Details VersionMinor"`
}

// Ikev2Parser parses Suricata Ikev2 alerts in the JSON format
type Ikev2Parser struct{}

func (p *Ikev2Parser) New() parsers.LogParser {
	return &Ikev2Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *Ikev2Parser) Parse(log string) []*parsers.PantherLog {
	event := &Ikev2{}

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
func (p *Ikev2Parser) LogType() string {
	return "Suricata.Ikev2"
}

func (event *Ikev2) updatePantherFields(p *Ikev2Parser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
