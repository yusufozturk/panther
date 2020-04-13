package suricatalogs

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
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

//nolint:lll
type HTTP struct {
	CommunityID  *string       `json:"community_id,omitempty" description:"Suricata HTTP CommunityID"`
	DestIP       *string       `json:"dest_ip" validate:"required" description:"Suricata HTTP DestIP"`
	DestPort     *int          `json:"dest_port,omitempty" description:"Suricata HTTP DestPort"`
	EventType    *string       `json:"event_type" validate:"required,eq=http" description:"Suricata HTTP EventType"`
	FlowID       *int          `json:"flow_id,omitempty" description:"Suricata HTTP FlowID"`
	HTTP         *HTTPDetails  `json:"http" validate:"required,dive" description:"Suricata HTTP HTTP"`
	Metadata     *HTTPMetadata `json:"metadata,omitempty" validate:"omitempty,dive" description:"Suricata HTTP Metadata"`
	PcapCnt      *int          `json:"pcap_cnt,omitempty" description:"Suricata HTTP PcapCnt"`
	PcapFilename *string       `json:"pcap_filename,omitempty" description:"Suricata HTTP PcapFilename"`
	Proto        *string       `json:"proto" validate:"required" description:"Suricata HTTP Proto"`
	SrcIP        *string       `json:"src_ip" validate:"required" description:"Suricata HTTP SrcIP"`
	SrcPort      *int          `json:"src_port,omitempty" description:"Suricata HTTP SrcPort"`
	Timestamp    *string       `json:"timestamp" validate:"required" description:"Suricata HTTP Timestamp"`
	TxID         *int          `json:"tx_id,omitempty" description:"Suricata HTTP TxID"`

	parsers.PantherLog
}

//nolint:lll
type HTTPDetails struct {
	ContentRange    *HTTPDetailsContentRange     `json:"content_range,omitempty" validate:"omitempty,dive" description:"Suricata HTTPDetails ContentRange"`
	HTTPContentType *string                      `json:"http_content_type,omitempty" description:"Suricata HTTPDetails HTTPContentType"`
	HTTPMethod      *string                      `json:"http_method,omitempty" description:"Suricata HTTPDetails HTTPMethod"`
	HTTPPort        *int                         `json:"http_port,omitempty" description:"Suricata HTTPDetails HTTPPort"`
	HTTPRefer       *string                      `json:"http_refer,omitempty" description:"Suricata HTTPDetails HTTPRefer"`
	HTTPUserAgent   *string                      `json:"http_user_agent,omitempty" description:"Suricata HTTPDetails HTTPUserAgent"`
	Hostname        *string                      `json:"hostname,omitempty" description:"Suricata HTTPDetails Hostname"`
	Length          *int                         `json:"length,omitempty" description:"Suricata HTTPDetails Length"`
	Protocol        *string                      `json:"protocol,omitempty" description:"Suricata HTTPDetails Protocol"`
	Redirect        *string                      `json:"redirect,omitempty" description:"Suricata HTTPDetails Redirect"`
	RequestHeaders  []HTTPDetailsRequestHeaders  `json:"request_headers,omitempty" validate:"omitempty,dive" description:"Suricata HTTPDetails RequestHeaders"`
	ResponseHeaders []HTTPDetailsResponseHeaders `json:"response_headers,omitempty" validate:"omitempty,dive" description:"Suricata HTTPDetails ResponseHeaders"`
	Status          *int                         `json:"status,omitempty" description:"Suricata HTTPDetails Status"`
	URL             *string                      `json:"url,omitempty" description:"Suricata HTTPDetails URL"`
}

//nolint:lll
type HTTPDetailsRequestHeaders struct {
	Name  *string `json:"name,omitempty" description:"Suricata HTTPDetailsRequestHeaders Name"`
	Value *string `json:"value,omitempty" description:"Suricata HTTPDetailsRequestHeaders Value"`
}

//nolint:lll
type HTTPDetailsResponseHeaders struct {
	Name  *string `json:"name,omitempty" description:"Suricata HTTPDetailsResponseHeaders Name"`
	Value *string `json:"value,omitempty" description:"Suricata HTTPDetailsResponseHeaders Value"`
}

//nolint:lll
type HTTPDetailsContentRange struct {
	End   *int    `json:"end,omitempty" description:"Suricata HTTPDetailsContentRange End"`
	Raw   *string `json:"raw,omitempty" description:"Suricata HTTPDetailsContentRange Raw"`
	Size  *int    `json:"size,omitempty" description:"Suricata HTTPDetailsContentRange Size"`
	Start *int    `json:"start,omitempty" description:"Suricata HTTPDetailsContentRange Start"`
}

//nolint:lll
type HTTPMetadata struct {
	Flowbits []string              `json:"flowbits,omitempty" description:"Suricata HTTPMetadata Flowbits"`
	Flowints *HTTPMetadataFlowints `json:"flowints,omitempty" validate:"omitempty,dive" description:"Suricata HTTPMetadata Flowints"`
}

//nolint:lll
type HTTPMetadataFlowints struct {
	ApplayerAnomalyCount   *int `json:"applayer.anomaly.count,omitempty" description:"Suricata HTTPMetadataFlowints ApplayerAnomalyCount"`
	HTTPAnomalyCount       *int `json:"http.anomaly.count,omitempty" description:"Suricata HTTPMetadataFlowints HTTPAnomalyCount"`
	TCPRetransmissionCount *int `json:"tcp.retransmission.count,omitempty" description:"Suricata HTTPMetadataFlowints TCPRetransmissionCount"`
}

// HTTPParser parses Suricata HTTP alerts in the JSON format
type HTTPParser struct{}

func (p *HTTPParser) New() parsers.LogParser {
	return &HTTPParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *HTTPParser) Parse(log string) []*parsers.PantherLog {
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

	return event.Logs()
}

// LogType returns the log type supported by this parser
func (p *HTTPParser) LogType() string {
	return "Suricata.HTTP"
}

func (event *HTTP) updatePantherFields(p *HTTPParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime, event)
	event.AppendAnyIPAddressPtr(event.SrcIP)
	event.AppendAnyIPAddressPtr(event.DestIP)
}
