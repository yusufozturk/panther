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

type Ikev2 struct {
	CommunityID  *string       `json:"community_id" validate:"required"`
	DestIP       *string       `json:"dest_ip" validate:"required"`
	DestPort     *int          `json:"dest_port" validate:"required"`
	EventType    *string       `json:"event_type" validate:"required"`
	FlowID       *int          `json:"flow_id" validate:"required"`
	Ikev2        *Ikev2Details `json:"ikev2" validate:"required,dive"`
	PcapCnt      *int          `json:"pcap_cnt" validate:"required"`
	PcapFilename *string       `json:"pcap_filename" validate:"required"`
	Proto        *string       `json:"proto" validate:"required"`
	SrcIP        *string       `json:"src_ip" validate:"required"`
	SrcPort      *int          `json:"src_port" validate:"required"`
	Timestamp    *string       `json:"timestamp" validate:"required"`

	parsers.PantherLog
}

type Ikev2Details struct {
	AlgAuth      *string  `json:"alg_auth,omitempty"`
	AlgDh        *string  `json:"alg_dh,omitempty"`
	AlgEnc       *string  `json:"alg_enc,omitempty"`
	AlgEsn       *string  `json:"alg_esn,omitempty"`
	AlgPrf       *string  `json:"alg_prf,omitempty"`
	Errors       *int     `json:"errors" validate:"required"`
	ExchangeType *int     `json:"exchange_type" validate:"required"`
	InitSpi      *string  `json:"init_spi" validate:"required"`
	MessageID    *int     `json:"message_id" validate:"required"`
	Notify       []string `json:"notify" validate:"required"`
	Payload      []string `json:"payload" validate:"required"`
	RespSpi      *string  `json:"resp_spi" validate:"required"`
	Role         *string  `json:"role" validate:"required"`
	VersionMajor *int     `json:"version_major" validate:"required"`
	VersionMinor *int     `json:"version_minor" validate:"required"`
}

// Ikev2Parser parses Suricata Ikev2 alerts in the JSON format
type Ikev2Parser struct{}

func (p *Ikev2Parser) New() parsers.LogParser {
	return &Ikev2Parser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *Ikev2Parser) Parse(log string) []interface{} {
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

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *Ikev2Parser) LogType() string {
	return "Suricata.Ikev2"
}

func (event *Ikev2) updatePantherFields(p *Ikev2Parser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
