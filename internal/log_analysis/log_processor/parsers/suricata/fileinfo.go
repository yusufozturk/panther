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

var FileinfoDesc = `Suricata parser for the Fileinfo event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type Fileinfo struct {
	AppProto     *string          `json:"app_proto" validate:"required"`
	DestIP       *string          `json:"dest_ip" validate:"required"`
	DestPort     *int             `json:"dest_port" validate:"required"`
	Email        *FileinfoEmail   `json:"email,omitempty" validate:"omitempty,dive"`
	EventType    *string          `json:"event_type" validate:"required"`
	Fileinfo     *FileinfoDetails `json:"fileinfo" validate:"required,dive"`
	FlowID       *int             `json:"flow_id" validate:"required"`
	HTTP         *FileinfoHTTP    `json:"http,omitempty" validate:"omitempty,dive"`
	PcapCnt      *int             `json:"pcap_cnt,omitempty"`
	PcapFilename *string          `json:"pcap_filename" validate:"required"`
	Proto        *string          `json:"proto" validate:"required"`
	SMTP         *FileinfoSMTP    `json:"smtp,omitempty" validate:"omitempty,dive"`
	Smb          *FileinfoSmb     `json:"smb,omitempty" validate:"omitempty,dive"`
	SrcIP        *string          `json:"src_ip" validate:"required"`
	SrcPort      *int             `json:"src_port" validate:"required"`
	Timestamp    *string          `json:"timestamp" validate:"required"`

	parsers.PantherLog
}

type FileinfoHTTP struct {
	ContentRange    *FileinfoHTTPContentRange `json:"content_range,omitempty" validate:"omitempty,dive"`
	HTTPContentType *string                   `json:"http_content_type,omitempty"`
	HTTPMethod      *string                   `json:"http_method,omitempty"`
	HTTPPort        *int                      `json:"http_port,omitempty"`
	HTTPRefer       *string                   `json:"http_refer,omitempty"`
	HTTPUserAgent   *string                   `json:"http_user_agent,omitempty"`
	Hostname        *string                   `json:"hostname,omitempty"`
	Length          *int                      `json:"length" validate:"required"`
	Protocol        *string                   `json:"protocol,omitempty"`
	Redirect        *string                   `json:"redirect,omitempty"`
	Status          *int                      `json:"status,omitempty"`
	URL             *string                   `json:"url" validate:"required"`
}

type FileinfoHTTPContentRange struct {
	End   *int    `json:"end,omitempty"`
	Raw   *string `json:"raw" validate:"required"`
	Size  *int    `json:"size,omitempty"`
	Start *int    `json:"start,omitempty"`
}

type FileinfoDetails struct {
	End      *int    `json:"end,omitempty"`
	FileID   *int    `json:"file_id" validate:"required"`
	Filename *string `json:"filename" validate:"required"`
	Gaps     *bool   `json:"gaps" validate:"required"`
	Magic    *string `json:"magic,omitempty"`
	Md5      *string `json:"md5,omitempty"`
	Sha1     *string `json:"sha1,omitempty"`
	Sha256   *string `json:"sha256" validate:"required"`
	Sid      []int   `json:"sid" validate:"required"`
	Size     *int    `json:"size" validate:"required"`
	Start    *int    `json:"start,omitempty"`
	State    *string `json:"state" validate:"required"`
	Stored   *bool   `json:"stored" validate:"required"`
	TxID     *int    `json:"tx_id" validate:"required"`
}

type FileinfoSmb struct {
	Command    *string `json:"command" validate:"required"`
	Dialect    *string `json:"dialect" validate:"required"`
	Filename   *string `json:"filename" validate:"required"`
	Fuid       *string `json:"fuid" validate:"required"`
	ID         *int    `json:"id" validate:"required"`
	SessionID  *int    `json:"session_id" validate:"required"`
	Share      *string `json:"share" validate:"required"`
	Status     *string `json:"status,omitempty"`
	StatusCode *string `json:"status_code,omitempty"`
	TreeID     *int    `json:"tree_id" validate:"required"`
}

type FileinfoSMTP struct {
	Helo     *string  `json:"helo" validate:"required"`
	MailFrom *string  `json:"mail_from" validate:"required"`
	RcptTo   []string `json:"rcpt_to" validate:"required"`
}

type FileinfoEmail struct {
	Attachment []string `json:"attachment,omitempty"`
	From       *string  `json:"from" validate:"required"`
	Status     *string  `json:"status" validate:"required"`
	To         []string `json:"to" validate:"required"`
}

// FileinfoParser parses Suricata Fileinfo alerts in the JSON format
type FileinfoParser struct{}

func (p *FileinfoParser) New() parsers.LogParser {
	return &FileinfoParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *FileinfoParser) Parse(log string) []interface{} {
	event := &Fileinfo{}

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
func (p *FileinfoParser) LogType() string {
	return "Suricata.Fileinfo"
}

func (event *Fileinfo) updatePantherFields(p *FileinfoParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
