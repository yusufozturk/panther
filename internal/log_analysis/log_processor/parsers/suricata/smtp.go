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

var SMTPDesc = `Suricata parser for the SMTP event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type SMTP struct {
	CommunityID  *string       `json:"community_id" validate:"required"`
	DestIP       *string       `json:"dest_ip" validate:"required"`
	DestPort     *int          `json:"dest_port" validate:"required"`
	Email        *SMTPEmail    `json:"email" validate:"required,dive"`
	EventType    *string       `json:"event_type" validate:"required"`
	FlowID       *int          `json:"flow_id" validate:"required"`
	Metadata     *SMTPMetadata `json:"metadata" validate:"required,dive"`
	PcapCnt      *int          `json:"pcap_cnt" validate:"required"`
	PcapFilename *string       `json:"pcap_filename" validate:"required"`
	Proto        *string       `json:"proto" validate:"required"`
	SMTP         *SMTPDetails  `json:"smtp" validate:"required,dive"`
	SrcIP        *string       `json:"src_ip" validate:"required"`
	SrcPort      *int          `json:"src_port" validate:"required"`
	Timestamp    *string       `json:"timestamp" validate:"required"`
	TxID         *int          `json:"tx_id" validate:"required"`

	parsers.PantherLog
}

type SMTPMetadata struct {
	Flowints *SMTPMetadataFlowints `json:"flowints" validate:"required,dive"`
}

type SMTPMetadataFlowints struct {
	ApplayerAnomalyCount *int `json:"applayer.anomaly.count" validate:"required"`
}

type SMTPDetails struct {
	Helo     *string  `json:"helo" validate:"required"`
	MailFrom *string  `json:"mail_from" validate:"required"`
	RcptTo   []string `json:"rcpt_to" validate:"required"`
}

type SMTPEmail struct {
	Attachment []string `json:"attachment,omitempty"`
	BodyMd5    *string  `json:"body_md5" validate:"required"`
	Cc         []string `json:"cc,omitempty"`
	From       *string  `json:"from" validate:"required"`
	Status     *string  `json:"status" validate:"required"`
	SubjectMd5 *string  `json:"subject_md5" validate:"required"`
	To         []string `json:"to" validate:"required"`
}

// SMTPParser parses Suricata SMTP alerts in the JSON format
type SMTPParser struct{}

func (p *SMTPParser) New() parsers.LogParser {
	return &SMTPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *SMTPParser) Parse(log string) []interface{} {
	event := &SMTP{}

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
func (p *SMTPParser) LogType() string {
	return "Suricata.SMTP"
}

func (event *SMTP) updatePantherFields(p *SMTPParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
