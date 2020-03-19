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

//nolint:lll
type SMTP struct {
	CommunityID  *string       `json:"community_id,omitempty" description:"Suricata SMTP CommunityID"`
	DestIP       *string       `json:"dest_ip" validate:"required" description:"Suricata SMTP DestIP"`
	DestPort     *int          `json:"dest_port,omitempty" description:"Suricata SMTP DestPort"`
	Email        *SMTPEmail    `json:"email,omitempty" validate:"omitempty,dive" description:"Suricata SMTP Email"`
	EventType    *string       `json:"event_type" validate:"required,eq=smtp" description:"Suricata SMTP EventType"`
	FlowID       *int          `json:"flow_id,omitempty" description:"Suricata SMTP FlowID"`
	Metadata     *SMTPMetadata `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata SMTP Metadata"`
	PcapCnt      *int          `json:"pcap_cnt,omitempty" description:"Suricata SMTP PcapCnt"`
	PcapFilename *string       `json:"pcap_filename,omitempty" description:"Suricata SMTP PcapFilename"`
	Proto        *string       `json:"proto" validate:"required" description:"Suricata SMTP Proto"`
	SMTP         *SMTPDetails  `json:"smtp" validate:"required,dive" description:"Suricata SMTP SMTP"`
	SrcIP        *string       `json:"src_ip" validate:"required" description:"Suricata SMTP SrcIP"`
	SrcPort      *int          `json:"src_port,omitempty" description:"Suricata SMTP SrcPort"`
	Timestamp    *string       `json:"timestamp" validate:"required" description:"Suricata SMTP Timestamp"`
	TxID         *int          `json:"tx_id,omitempty" description:"Suricata SMTP TxID"`

	parsers.PantherLog
}

//nolint:lll
type SMTPMetadata struct {
	Flowints *SMTPMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata SMTPMetadata Flowints"`
}

//nolint:lll
type SMTPMetadataFlowints struct {
	ApplayerAnomalyCount *int `json:"applayer.anomaly.count,omitempty" description:"Suricata SMTPMetadataFlowints ApplayerAnomalyCount"`
}

//nolint:lll
type SMTPDetails struct {
	Helo     *string  `json:"helo,omitempty" description:"Suricata SMTPDetails Helo"`
	MailFrom *string  `json:"mail_from,omitempty" description:"Suricata SMTPDetails MailFrom"`
	RcptTo   []string `json:"rcpt_to,omitempty" description:"Suricata SMTPDetails RcptTo"`
}

//nolint:lll
type SMTPEmail struct {
	Attachment []string `json:"attachment,omitempty" description:"Suricata SMTPEmail Attachment"`
	BodyMd5    *string  `json:"body_md5,omitempty" description:"Suricata SMTPEmail BodyMd5"`
	Cc         []string `json:"cc,omitempty" description:"Suricata SMTPEmail Cc"`
	From       *string  `json:"from,omitempty" description:"Suricata SMTPEmail From"`
	Status     *string  `json:"status,omitempty" description:"Suricata SMTPEmail Status"`
	SubjectMd5 *string  `json:"subject_md5,omitempty" description:"Suricata SMTPEmail SubjectMd5"`
	To         []string `json:"to,omitempty" description:"Suricata SMTPEmail To"`
}

// SMTPParser parses Suricata SMTP alerts in the JSON format
type SMTPParser struct{}

func (p *SMTPParser) New() parsers.LogParser {
	return &SMTPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *SMTPParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *SMTPParser) LogType() string {
	return "Suricata.SMTP"
}

func (event *SMTP) updatePantherFields(p *SMTPParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
