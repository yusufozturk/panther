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

var HTTPDesc = `Suricata parser for the HTTP event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type HTTP struct {
	CommunityID  *string       `json:"community_id" validate:"required"`
	DestIP       *string       `json:"dest_ip" validate:"required"`
	DestPort     *int          `json:"dest_port" validate:"required"`
	EventType    *string       `json:"event_type" validate:"required"`
	FlowID       *int          `json:"flow_id" validate:"required"`
	HTTP         *HTTPDetails  `json:"http" validate:"required,dive"`
	Metadata     *HTTPMetadata `json:"metadata,omitempty" validate:"omitempty,dive"`
	PcapCnt      *int          `json:"pcap_cnt,omitempty"`
	PcapFilename *string       `json:"pcap_filename" validate:"required"`
	Proto        *string       `json:"proto" validate:"required"`
	SrcIP        *string       `json:"src_ip" validate:"required"`
	SrcPort      *int          `json:"src_port" validate:"required"`
	Timestamp    *string       `json:"timestamp" validate:"required"`
	TxID         *int          `json:"tx_id" validate:"required"`

	parsers.PantherLog
}

type HTTPDetails struct {
	ContentRange    *HTTPDetailsContentRange     `json:"content_range,omitempty" validate:"omitempty,dive"`
	HTTPContentType *string                      `json:"http_content_type,omitempty"`
	HTTPMethod      *string                      `json:"http_method,omitempty"`
	HTTPPort        *int                         `json:"http_port,omitempty"`
	HTTPRefer       *string                      `json:"http_refer,omitempty"`
	HTTPUserAgent   *string                      `json:"http_user_agent,omitempty"`
	Hostname        *string                      `json:"hostname,omitempty"`
	Length          *int                         `json:"length" validate:"required"`
	Protocol        *string                      `json:"protocol,omitempty"`
	Redirect        *string                      `json:"redirect,omitempty"`
	RequestHeaders  []HTTPDetailsRequestHeaders  `json:"request_headers" validate:"required,dive"`
	ResponseHeaders []HTTPDetailsResponseHeaders `json:"response_headers" validate:"required,dive"`
	Status          *int                         `json:"status,omitempty"`
	URL             *string                      `json:"url,omitempty"`
}

type HTTPDetailsRequestHeaders struct {
	Name  *string `json:"name" validate:"required"`
	Value *string `json:"value" validate:"required"`
}

type HTTPDetailsResponseHeaders struct {
	Name  *string `json:"name" validate:"required"`
	Value *string `json:"value" validate:"required"`
}

type HTTPDetailsContentRange struct {
	End   *int    `json:"end,omitempty"`
	Raw   *string `json:"raw" validate:"required"`
	Size  *int    `json:"size,omitempty"`
	Start *int    `json:"start,omitempty"`
}

type HTTPMetadata struct {
	Flowbits []string              `json:"flowbits,omitempty"`
	Flowints *HTTPMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive"`
}

type HTTPMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty"`
}

// HTTPParser parses Suricata HTTP alerts in the JSON format
type HTTPParser struct{}

func (p *HTTPParser) New() parsers.LogParser {
	return &HTTPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *HTTPParser) Parse(log string) []interface{} {
	event := &HTTP{}

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
func (p *HTTPParser) LogType() string {
	return "Suricata.HTTP"
}

func (event *HTTP) updatePantherFields(p *HTTPParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
