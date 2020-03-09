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

var AlertDesc = `Suricata parser for the Alert event in EVE JSON output.`

{"timestamp":"2016-11-26T14:52:59.669097+0000","flow_id":1844600973768105,"pcap_cnt":3,"event_type":"alert","src_ip":"10.0.2.15","src_port":27942,"dest_ip":"10.0.2.15","dest_port":27942,"proto":"017","community_id":"1:NALMnASfrmROPp+ghhgVXLG+cpM=","alert":{"action":"allowed","gid":1,"signature_id":2200075,"rev":2,"signature":"SURICATA UDPv4 invalid checksum","category":"Generic Protocol Command Decode","severity":3},"app_proto":"failed","flow":{"pkts_toserver":1,"pkts_toclient":0,"bytes_toserver":47,"bytes_toclient":0,"start":"2016-11-26T14:52:59.669097+0000"},"payload":"VEVTVAA=","payload_printable":"TEST.","stream":0,"packet":"AAAAAAAAAAAAAAAACABFAAAhvzpAAEARY3QKAAIPCgACD20mbSYADRg8VEVTVAA=","packet_info":{"linktype":1},"pcap_filename":"\/pcaps\/sip-rtp-g711.pcap"}
{"timestamp":"2013-03-07T21:42:07.009775+0000","flow_id":619927151985632,"pcap_cnt":9,"event_type":"alert","src_ip":"192.150.187.43","src_port":80,"dest_ip":"141.142.228.5","dest_port":59856,"proto":"006","community_id":"1:+49TarwoW9lFS8886GydFbUG720=","alert":{"action":"allowed","gid":1,"signature_id":101,"rev":0,"signature":"FOO HTTP","category":"","severity":3},"http":{"hostname":"bro.org","url":"HTTP\/1.1","http_method":"GET","length":0},"app_proto":"http","flow":{"pkts_toserver":3,"pkts_toclient":6,"bytes_toserver":346,"bytes_toclient":5411,"start":"2013-03-07T21:42:06.869344+0000"},"payload":"IHRocmVhZCBsaWJyYXJ5IHdoZW4gbmVjZXNzYXJ5IChlLmcuCiAgICBQRl9SSU5HJ3MgbGlicGNhcCkgKEpvbiBTaXdlaykKCiAgKiBJbnN0YWxsIGJpbmFyaWVzIHdpdGggYW4gUlBBVEggKEpvbiBTaXdlaykKCiAgKiBXb3JrYXJvdW5kIGZvciBGcmVlQlNEIENNYWtlIHBvcnQgbWlzc2luZyBkZWJ1ZyBmbGFncyAoSm9uIFNpd2VrKQoKICAqIFJld3JpdGUgb2YgdGhlIHVwZGF0ZS1jaGFuZ2VzIHNjcmlwdC4gKFJvYmluIFNvbW1lcikKCjAuMS0xIHwgMjAxMS0wNi0xNCAyMToxMjo0MSAtMDcwMAoKICAqIEFkZCBhIHNjcmlwdCBmb3IgZ2VuZXJhdGluZyBNb3ppbGxhJ3MgQ0EgbGlzdCBmb3IgdGhlIFNTTCBhbmFseXplci4KICAgIChTZXRoIEhhbGwpCgowLjEgfCAyMDExLTA0LTAxIDE2OjI4OjIyIC0wNzAwCgogICogQ29udmVydGluZyBidWlsZCBwcm9jZXNzIHRvIENNYWtlLiAoSm9uIFNpd2VrKQoKICAqIFJlbW92aW5nIGNmL2hmL2NhLSogZnJvbSBkaXN0cmlidXRpb24uIFRoZSBSRUFETUUgaGFzIGEgbm90ZSB3aGVyZQogICAgdG8gZmluZCB0aGVtIG5vdy4gKFJvYmluIFNvbW1lcikKCiAgKiBHZW5lcmFsIGNsZWFudXAuIChSb2JpbiBTb21tZXIpCgogICogSW5pdGlhbCBpbXBvcnQgb2YgYnJvL2F1eCBmcm9tIFNWTiByNzA4OC4gKEpvbiBTaXdlaykK","payload_printable":" thread library when necessary (e.g.\n    PF_RING's libpcap) (Jon Siwek)\n\n  * Install binaries with an RPATH (Jon Siwek)\n\n  * Workaround for FreeBSD CMake port missing debug flags (Jon Siwek)\n\n  * Rewrite of the update-changes script. (Robin Sommer)\n\n0.1-1 | 2011-06-14 21:12:41 -0700\n\n  * Add a script for generating Mozilla's CA list for the SSL analyzer.\n    (Seth Hall)\n\n0.1 | 2011-04-01 16:28:22 -0700\n\n  * Converting build process to CMake. (Jon Siwek)\n\n  * Removing cf\/hf\/ca-* from distribution. The README has a note where\n    to find them now. (Robin Sommer)\n\n  * General cleanup. (Robin Sommer)\n\n  * Initial import of bro\/aux from SVN r7088. (Jon Siwek)\n","stream":0,"packet":"yLzIltKgABDbiNLvCABFAALLjKRAAC8GzzLAlrsrjY7kBQBQ6dClr983\/iEyw4AYAHqlKAAAAQEICi+JQp8WSt1mIHRocmVhZCBsaWJyYXJ5IHdoZW4gbmVjZXNzYXJ5IChlLmcuCiAgICBQRl9SSU5HJ3MgbGlicGNhcCkgKEpvbiBTaXdlaykKCiAgKiBJbnN0YWxsIGJpbmFyaWVzIHdpdGggYW4gUlBBVEggKEpvbiBTaXdlaykKCiAgKiBXb3JrYXJvdW5kIGZvciBGcmVlQlNEIENNYWtlIHBvcnQgbWlzc2luZyBkZWJ1ZyBmbGFncyAoSm9uIFNpd2VrKQoKICAqIFJld3JpdGUgb2YgdGhlIHVwZGF0ZS1jaGFuZ2VzIHNjcmlwdC4gKFJvYmluIFNvbW1lcikKCjAuMS0xIHwgMjAxMS0wNi0xNCAyMToxMjo0MSAtMDcwMAoKICAqIEFkZCBhIHNjcmlwdCBmb3IgZ2VuZXJhdGluZyBNb3ppbGxhJ3MgQ0EgbGlzdCBmb3IgdGhlIFNTTCBhbmFseXplci4KICAgIChTZXRoIEhhbGwpCgowLjEgfCAyMDExLTA0LTAxIDE2OjI4OjIyIC0wNzAwCgogICogQ29udmVydGluZyBidWlsZCBwcm9jZXNzIHRvIENNYWtlLiAoSm9uIFNpd2VrKQoKICAqIFJlbW92aW5nIGNmL2hmL2NhLSogZnJvbSBkaXN0cmlidXRpb24uIFRoZSBSRUFETUUgaGFzIGEgbm90ZSB3aGVyZQogICAgdG8gZmluZCB0aGVtIG5vdy4gKFJvYmluIFNvbW1lcikKCiAgKiBHZW5lcmFsIGNsZWFudXAuIChSb2JpbiBTb21tZXIpCgogICogSW5pdGlhbCBpbXBvcnQgb2YgYnJvL2F1eCBmcm9tIFNWTiByNzA4OC4gKEpvbiBTaXdlaykK","packet_info":{"linktype":1},"pcap_filename":"\/pcaps\/no-uri.pcap"}
{"timestamp":"2014-05-20T00:53:33.668004+0000","flow_id":1938390271209551,"pcap_cnt":37,"event_type":"alert","src_ip":"118.189.96.132","src_port":55483,"dest_ip":"118.189.96.132","dest_port":502,"proto":"006","metadata":{"flowints":{"applayer.anomaly.count":1}},"community_id":"1:Cy0CEi2sORlkOHxwWifTYWCjBkg=","alert":{"action":"allowed","gid":1,"signature_id":2260002,"rev":1,"signature":"SURICATA Applayer Detect protocol only one direction","category":"Generic Protocol Command Decode","severity":3},"app_proto":"modbus","app_proto_tc":"failed","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":284,"bytes_toclient":216,"start":"2014-05-20T00:53:33.667727+0000"},"payload":"","payload_printable":"","stream":0,"packet":"AAAAAAAAAAAAAAAACABFAAA07zxAAEAGnQR2vWCEdr1ghNi7Afa9vjlvbs58L4AQAVb+KAAAAQEICgFW1lsBVtZb","packet_info":{"linktype":1},"pcap_filename":"\/pcaps\/modbusSmall.pcap"}
{"timestamp":"2014-05-20T00:53:57.108698+0000","flow_id":1001889833785988,"pcap_cnt":102,"event_type":"alert","src_ip":"118.189.96.132","src_port":53,"dest_ip":"118.189.96.132","dest_port":56426,"proto":"017","community_id":"1:tGrjcWyaaeBeTrnonYdHgIU\/YWU=","alert":{"action":"allowed","gid":1,"signature_id":2200075,"rev":2,"signature":"SURICATA UDPv4 invalid checksum","category":"Generic Protocol Command Decode","severity":3},"app_proto":"dns","flow":{"pkts_toserver":1,"pkts_toclient":1,"bytes_toserver":75,"bytes_toclient":270,"start":"2014-05-20T00:53:57.105092+0000"},"payload":"mBCBgAABAAMABAAEBG1haWwGZ29vZ2xlA2NvbQAAAQABwAwABQABAAU4rgAPCmdvb2dsZW1haWwBbMARwC0AAQABAAAAIwAESn3vNsAtAAEAAQAAACMABEp97zXAEQACAAEAAUQhAAYDbnMzwBHAEQACAAEAAUQhAAYDbnMywBHAEQACAAEAAUQhAAYDbnM0wBHAEQACAAEAAUQhAAYDbnMxwBHAjAABAAEAAVWKAATY7yYKwGgAAQABAAFVigAE2O8kCsB6AAEAAQABVYoABNjvIgrAngABAAEAAVWKAATY7yAK","payload_printable":".............mail.google.com.............8...\ngooglemail.l...-.......#..J}.6.-.......#..J}.5........D!...ns3..........D!...ns2..........D!...ns4..........D!...ns1..........U.....&\n.h......U.....$\n.z......U.....\"\n........U..... \n","stream":0,"packet":"AAAAAAAAAAAAAAAACABFAAEAeuFAAEAREIl2vWCEdr1ghAA13GoA7P7\/mBCBgAABAAMABAAEBG1haWwGZ29vZ2xlA2NvbQAAAQABwAwABQABAAU4rgAPCmdvb2dsZW1haWwBbMARwC0AAQABAAAAIwAESn3vNsAtAAEAAQAAACMABEp97zXAEQACAAEAAUQhAAYDbnMzwBHAEQACAAEAAUQhAAYDbnMywBHAEQACAAEAAUQhAAYDbnM0wBHAEQACAAEAAUQhAAYDbnMxwBHAjAABAAEAAVWKAATY7yYKwGgAAQABAAFVigAE2O8kCsB6AAEAAQABVYoABNjvIgrAngABAAEAAVWKAATY7yAK","packet_info":{"linktype":1},"pcap_filename":"\/pcaps\/modbusSmall.pcap"}


{
    "timestamp": "2014-05-20T00:53:57.108698+0000",
    "flow_id": 1001889833785988,
    "pcap_cnt": 102,
    "event_type": "alert",
    "src_ip": "118.189.96.132",
    "src_port": 53,
    "dest_ip": "118.189.96.132",
    "dest_port": 56426,
    "proto": "017",
    "community_id": "1:tGrjcWyaaeBeTrnonYdHgIU\/YWU=",
    "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 2200075,
        "rev": 2,
        "signature": "SURICATA UDPv4 invalid checksum",
        "category": "Generic Protocol Command Decode",
        "severity": 3
    },
    "app_proto": "dns",
    "flow": {
        "pkts_toserver": 1,
        "pkts_toclient": 1,
        "bytes_toserver": 75,
        "bytes_toclient": 270,
        "start": "2014-05-20T00:53:57.105092+0000"
    },
    "payload": "mBCBgAABAAMABAAEBG1haWwGZ29vZ2xlA2NvbQAAAQABwAwABQABAAU4rgAPCmdvb2dsZW1haWwBbMARwC0AAQABAAAAIwAESn3vNsAtAAEAAQAAACMABEp97zXAEQACAAEAAUQhAAYDbnMzwBHAEQACAAEAAUQhAAYDbnMywBHAEQACAAEAAUQhAAYDbnM0wBHAEQACAAEAAUQhAAYDbnMxwBHAjAABAAEAAVWKAATY7yYKwGgAAQABAAFVigAE2O8kCsB6AAEAAQABVYoABNjvIgrAngABAAEAAVWKAATY7yAK",
    "payload_printable": ".............mail.google.com.............8...\ngooglemail.l...-.......#..J}.6.-.......#..J}.5........D!...ns3..........D!...ns2..........D!...ns4..........D!...ns1..........U.....&\n.h......U.....$\n.z......U.....\"\n........U..... \n",
    "stream": 0,
    "packet": "AAAAAAAAAAAAAAAACABFAAEAeuFAAEAREIl2vWCEdr1ghAA13GoA7P7\/mBCBgAABAAMABAAEBG1haWwGZ29vZ2xlA2NvbQAAAQABwAwABQABAAU4rgAPCmdvb2dsZW1haWwBbMARwC0AAQABAAAAIwAESn3vNsAtAAEAAQAAACMABEp97zXAEQACAAEAAUQhAAYDbnMzwBHAEQACAAEAAUQhAAYDbnMywBHAEQACAAEAAUQhAAYDbnM0wBHAEQACAAEAAUQhAAYDbnMxwBHAjAABAAEAAVWKAATY7yYKwGgAAQABAAFVigAE2O8kCsB6AAEAAQABVYoABNjvIgrAngABAAEAAVWKAATY7yAK",
    "packet_info": {
        "linktype": 1
    },
    "pcap_filename": "\/pcaps\/modbusSmall.pcap"
}


type Alert struct {
	Action      *string  `json:"action" validate:"required"`
	Category    *string  `json:"category" validate:"required"`
	Gid         *int     `json:"gid" validate:"required"`
	Metadata    Metadata `json:"metadata,omitempty" validate:"dive"`
	Rev         *int     `json:"rev" validate:"required"`
	Severity    *int     `json:"severity" validate:"required"`
	Signature   *string  `json:"signature" validate:"required"`
	SignatureID *int     `json:"signature_id" validate:"required"`
}

type Metadata struct {
	AffectedProduct   []string `json:"affected_product,omitempty"`
	AttackTarget      []string `json:"attack_target,omitempty"`
	CreatedAt         []string `json:"created_at" validate:"required"`
	Deployment        []string `json:"deployment,omitempty"`
	FormerCategory    []string `json:"former_category,omitempty"`
	MalwareFamily     []string `json:"malware_family,omitempty"`
	PerformanceImpact []string `json:"performance_impact,omitempty"`
	SignatureSeverity []string `json:"signature_severity,omitempty"`
	Tag               []string `json:"tag,omitempty"`
	UpdatedAt         []string `json:"updated_at" validate:"required"`
}

type Flow struct {
	Age           *int64  `json:"age,omitempty"`
	Alerted       *bool   `json:"alerted,omitempty"`
	BytesToclient *int64   `json:"bytes_toclient" validate:"required"`
	BytesToserver *int64   `json:"bytes_toserver" validate:"required"`
	Emergency     *bool   `json:"emergency,omitempty"`
	End           *string `json:"end,omitempty"`
	PktsToclient  *int64   `json:"pkts_toclient" validate:"required"`
	PktsToserver  *int64   `json:"pkts_toserver" validate:"required"`
	Reason        *string `json:"reason,omitempty"`
	Start         *string  `json:"start" validate:"required"`
	State         *string `json:"state,omitempty"`
}



// AlertParser parses Suricata Alert alerts in the JSON format
type AlertParser struct{}

func (p *AlertParser) New() parsers.LogParser {
	return &AlertParser{}
}

// Parse returns the parsed events or nil if parsing failed
func (p *AlertParser) Parse(log string) []interface{} {
	event := &Alert{}

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
func (p *AlertParser) LogType() string {
	return "Suricata.Alert"
}

func (event *Alert) updatePantherFields(p *AlertParser) {
	eventTime, _ := timestamp.Parse(time.RFC3339Nano, *event.Timestamp)
	event.SetCoreFields(p.LogType(), &eventTime)
	event.AppendAnyIPAddressPtrs(event.SrcIP, event.DestIP)
}
