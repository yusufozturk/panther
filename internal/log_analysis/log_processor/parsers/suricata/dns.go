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

var DNSDesc = `Suricata parser for the DNS event type in the EVE JSON output.
Reference: https://suricata.readthedocs.io/en/suricata-5.0.2/output/eve/eve-json-output.html`

type DNS struct {
	CommunityID  *string     `json:"community_id" validate:"required"`
	DNS          *DNSDetails `json:"dns" validate:"required,dive"`
	DestIP       *string     `json:"dest_ip" validate:"required"`
	DestPort     *int        `json:"dest_port" validate:"required"`
	EventType    *string     `json:"event_type" validate:"required"`
	FlowID       *int        `json:"flow_id" validate:"required"`
	PcapCnt      *int        `json:"pcap_cnt,omitempty"`
	PcapFilename *string     `json:"pcap_filename" validate:"required"`
	Proto        *string     `json:"proto" validate:"required"`
	SrcIP        *string     `json:"src_ip" validate:"required"`
	SrcPort      *int        `json:"src_port" validate:"required"`
	Timestamp    *string     `json:"timestamp" validate:"required"`
	Vlan         []int       `json:"vlan,omitempty"`

	parsers.PantherLog
}

type DNSDetails struct {
	Aa          *bool                   `json:"aa,omitempty"`
	Answers     []DNSDetailsAnswers     `json:"answers,omitempty" validate:"omitempty,dive"`
	Authorities []DNSDetailsAuthorities `json:"authorities,omitempty" validate:"omitempty,dive"`
	Flags       *string                 `json:"flags,omitempty"`
	Grouped     *DNSDetailsGrouped      `json:"grouped,omitempty" validate:"omitempty,dive"`
	ID          *int                    `json:"id" validate:"required"`
	Qr          *bool                   `json:"qr,omitempty"`
	Ra          *bool                   `json:"ra,omitempty"`
	Rcode       *string                 `json:"rcode,omitempty"`
	Rd          *bool                   `json:"rd,omitempty"`
	Rrname      *string                 `json:"rrname" validate:"required"`
	Rrtype      *string                 `json:"rrtype" validate:"required"`
	TxID        *int                    `json:"tx_id,omitempty"`
	Type        *string                 `json:"type" validate:"required"`
	Version     *int                    `json:"version,omitempty"`
}

type DNSDetailsAnswers struct {
	Rdata  *string `json:"rdata,omitempty"`
	Rrname *string `json:"rrname" validate:"required"`
	Rrtype *string `json:"rrtype" validate:"required"`
	TTL    *int    `json:"ttl" validate:"required"`
}

type DNSDetailsGrouped struct {
	A     []string `json:"A,omitempty"`
	Aaaa  []string `json:"AAAA,omitempty"`
	Cname []string `json:"CNAME,omitempty"`
	Mx    []string `json:"MX,omitempty"`
	Ptr   []string `json:"PTR,omitempty"`
	Txt   []string `json:"TXT,omitempty"`
}

type DNSDetailsAuthorities struct {
	Rrname *string `json:"rrname" validate:"required"`
	Rrtype *string `json:"rrtype" validate:"required"`
	TTL    *int    `json:"ttl" validate:"required"`
}

// DNSParser parses Suricata DNS alerts in the JSON format
type DNSParser struct{}

func (p *DNSParser) New() parsers.LogParser {
	return &DNSParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *DNSParser) Parse(log string) []interface{} {
	event := &DNS{}

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
func (p *DNSParser) LogType() string {
	return "Suricata.DNS"
}

func (event *DNS) updatePantherFields(p *DNSParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
