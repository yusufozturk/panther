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

//nolint:lll
type Fileinfo struct {
	AppProto     *string          `json:"app_proto,omitempty" description:"Suricata Fileinfo AppProto"`
	DestIP       *string          `json:"dest_ip" validate:"required" description:"Suricata Fileinfo DestIP"`
	DestPort     *int             `json:"dest_port,omitempty" description:"Suricata Fileinfo DestPort"`
	Email        *FileinfoEmail   `json:"email,omitempty" validate:"omitempty,dive" description:"Suricata Fileinfo Email"`
	EventType    *string          `json:"event_type" validate:"required" description:"Suricata Fileinfo EventType"`
	Fileinfo     *FileinfoDetails `json:"fileinfo" validate:"required,dive" description:"Suricata Fileinfo Fileinfo"`
	FlowID       *int             `json:"flow_id,omitempty" description:"Suricata Fileinfo FlowID"`
	HTTP         *FileinfoHTTP    `json:"http,omitempty" validate:"omitempty,dive" description:"Suricata Fileinfo HTTP"`
	PcapCnt      *int             `json:"pcap_cnt,omitempty" description:"Suricata Fileinfo PcapCnt"`
	PcapFilename *string          `json:"pcap_filename,omitempty" description:"Suricata Fileinfo PcapFilename"`
	Proto        *string          `json:"proto" validate:"required" description:"Suricata Fileinfo Proto"`
	SMTP         *FileinfoSMTP    `json:"smtp,omitempty" validate:"omitempty,dive" description:"Suricata Fileinfo SMTP"`
	Smb          *FileinfoSmb     `json:"smb,omitempty" validate:"omitempty,dive" description:"Suricata Fileinfo Smb"`
	SrcIP        *string          `json:"src_ip" validate:"required" description:"Suricata Fileinfo SrcIP"`
	SrcPort      *int             `json:"src_port,omitempty" description:"Suricata Fileinfo SrcPort"`
	Timestamp    *string          `json:"timestamp" validate:"required" description:"Suricata Fileinfo Timestamp"`

	parsers.PantherLog
}

//nolint:lll
type FileinfoHTTP struct {
	ContentRange    *FileinfoHTTPContentRange `json:"content_range,omitempty" validate:"omitempty,dive" description:"Suricata FileinfoHTTP ContentRange"`
	HTTPContentType *string                   `json:"http_content_type,omitempty" description:"Suricata FileinfoHTTP HTTPContentType"`
	HTTPMethod      *string                   `json:"http_method,omitempty" description:"Suricata FileinfoHTTP HTTPMethod"`
	HTTPPort        *int                      `json:"http_port,omitempty" description:"Suricata FileinfoHTTP HTTPPort"`
	HTTPRefer       *string                   `json:"http_refer,omitempty" description:"Suricata FileinfoHTTP HTTPRefer"`
	HTTPUserAgent   *string                   `json:"http_user_agent,omitempty" description:"Suricata FileinfoHTTP HTTPUserAgent"`
	Hostname        *string                   `json:"hostname,omitempty" description:"Suricata FileinfoHTTP Hostname"`
	Length          *int                      `json:"length,omitempty" description:"Suricata FileinfoHTTP Length"`
	Protocol        *string                   `json:"protocol,omitempty" description:"Suricata FileinfoHTTP Protocol"`
	Redirect        *string                   `json:"redirect,omitempty" description:"Suricata FileinfoHTTP Redirect"`
	Status          *int                      `json:"status,omitempty" description:"Suricata FileinfoHTTP Status"`
	URL             *string                   `json:"url,omitempty" description:"Suricata FileinfoHTTP URL"`
}

//nolint:lll
type FileinfoHTTPContentRange struct {
	End   *int    `json:"end,omitempty" description:"Suricata FileinfoHTTPContentRange End"`
	Raw   *string `json:"raw,omitempty" description:"Suricata FileinfoHTTPContentRange Raw"`
	Size  *int    `json:"size,omitempty" description:"Suricata FileinfoHTTPContentRange Size"`
	Start *int    `json:"start,omitempty" description:"Suricata FileinfoHTTPContentRange Start"`
}

//nolint:lll
type FileinfoDetails struct {
	End      *int    `json:"end,omitempty" description:"Suricata FileinfoDetails End"`
	FileID   *int    `json:"file_id,omitempty" description:"Suricata FileinfoDetails FileID"`
	Filename *string `json:"filename,omitempty" description:"Suricata FileinfoDetails Filename"`
	Gaps     *bool   `json:"gaps,omitempty" description:"Suricata FileinfoDetails Gaps"`
	Magic    *string `json:"magic,omitempty" description:"Suricata FileinfoDetails Magic"`
	Md5      *string `json:"md5,omitempty" description:"Suricata FileinfoDetails Md5"`
	Sha1     *string `json:"sha1,omitempty" description:"Suricata FileinfoDetails Sha1"`
	Sha256   *string `json:"sha256,omitempty" description:"Suricata FileinfoDetails Sha256"`
	Sid      []int   `json:"sid,omitempty" description:"Suricata FileinfoDetails Sid"`
	Size     *int    `json:"size,omitempty" description:"Suricata FileinfoDetails Size"`
	Start    *int    `json:"start,omitempty" description:"Suricata FileinfoDetails Start"`
	State    *string `json:"state,omitempty" description:"Suricata FileinfoDetails State"`
	Stored   *bool   `json:"stored,omitempty" description:"Suricata FileinfoDetails Stored"`
	TxID     *int    `json:"tx_id,omitempty" description:"Suricata FileinfoDetails TxID"`
}

//nolint:lll
type FileinfoSmb struct {
	Command    *string `json:"command,omitempty" description:"Suricata FileinfoSmb Command"`
	Dialect    *string `json:"dialect,omitempty" description:"Suricata FileinfoSmb Dialect"`
	Filename   *string `json:"filename,omitempty" description:"Suricata FileinfoSmb Filename"`
	Fuid       *string `json:"fuid,omitempty" description:"Suricata FileinfoSmb Fuid"`
	ID         *int    `json:"id,omitempty" description:"Suricata FileinfoSmb ID"`
	SessionID  *int    `json:"session_id,omitempty" description:"Suricata FileinfoSmb SessionID"`
	Share      *string `json:"share,omitempty" description:"Suricata FileinfoSmb Share"`
	Status     *string `json:"status,omitempty" description:"Suricata FileinfoSmb Status"`
	StatusCode *string `json:"status_code,omitempty" description:"Suricata FileinfoSmb StatusCode"`
	TreeID     *int    `json:"tree_id,omitempty" description:"Suricata FileinfoSmb TreeID"`
}

//nolint:lll
type FileinfoSMTP struct {
	Helo     *string  `json:"helo,omitempty" description:"Suricata FileinfoSMTP Helo"`
	MailFrom *string  `json:"mail_from,omitempty" description:"Suricata FileinfoSMTP MailFrom"`
	RcptTo   []string `json:"rcpt_to,omitempty" description:"Suricata FileinfoSMTP RcptTo"`
}

//nolint:lll
type FileinfoEmail struct {
	Attachment []string `json:"attachment,omitempty" description:"Suricata FileinfoEmail Attachment"`
	From       *string  `json:"from,omitempty" description:"Suricata FileinfoEmail From"`
	Status     *string  `json:"status,omitempty" description:"Suricata FileinfoEmail Status"`
	To         []string `json:"to,omitempty" description:"Suricata FileinfoEmail To"`
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
