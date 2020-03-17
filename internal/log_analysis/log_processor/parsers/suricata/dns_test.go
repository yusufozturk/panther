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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

func TestDNS(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	//nolint:lll
	logs := `{"timestamp": "2019-01-02T06:42:52.653129", "flow_id": 43586032, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 44850, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "answer", "id": 23270}}
{"timestamp": "2019-01-02T06:42:52.654396", "flow_id": 43586368, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 46110, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "answer", "id": 15025, "rrname": "mirrors.digitalocean.com", "rrtype": "A", "ttl": 111, "rdata": "192.241.164.26"}}
{"timestamp": "2019-01-02T06:42:52.654396", "flow_id": 43586368, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 46110, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "answer", "id": 43649, "rrname": "mirrors.digitalocean.com", "rrtype": "AAAA", "ttl": 83, "rdata": "2a03:b0c0:0000:0001:0000:0000:0000:0004"}}
{"timestamp": "2019-01-02T06:42:52.654396", "flow_id": 43586368, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 46110, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "answer", "id": 43649, "rrname": "mirrors.digitalocean.com", "rrtype": "AAAA", "ttl": 83, "rdata": "2a03:b0c0:0001:0001:0000:0000:0000:0004"}}
{"timestamp": "2019-01-02T06:42:52.654396", "flow_id": 43586368, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 46110, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "answer", "id": 43649, "rrname": "mirrors.digitalocean.com", "rrtype": "AAAA", "ttl": 83, "rdata": "2604:a880:0001:0001:0000:0000:0000:0004"}}
{"timestamp": "2019-01-02T06:42:52.654396", "flow_id": 43586368, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 46110, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "answer", "id": 15025, "rrname": "mirrors.digitalocean.com", "rrtype": "A", "ttl": 111, "rdata": "5.101.111.50"}}
{"timestamp": "2019-01-02T06:42:52.654396", "flow_id": 43586368, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 46110, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "answer", "id": 15025, "rrname": "mirrors.digitalocean.com", "rrtype": "A", "ttl": 111, "rdata": "103.253.144.50"}}
{"timestamp": "2019-01-02T06:42:52.654396", "flow_id": 43586368, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 46110, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "answer", "id": 43649, "rrname": "mirrors.digitalocean.com", "rrtype": "AAAA", "ttl": 83, "rdata": "2604:a880:0000:0001:0000:0000:0000:0004"}}
{"timestamp": "2019-01-02T06:42:52.654396", "flow_id": 43586368, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 46110, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "query", "id": 15025, "rrname": "mirrors.digitalocean.com", "rrtype": "A", "tx_id": 0}}
{"timestamp": "2019-01-02T06:42:52.654396", "flow_id": 43586368, "in_iface": "eth0", "event_type": "dns", "src_ip": "138.68.3.71", "src_port": 46110, "dest_ip": "67.207.67.2", "dest_port": 53, "proto": "UDP", "dns": {"type": "query", "id": 43649, "rrname": "mirrors.digitalocean.com", "rrtype": "AAAA", "tx_id": 1}}
`

	parser := &DNSParser{}
	lines := strings.FieldsFunc(logs, func(r rune) bool { return r == '\n' })
	for _, line := range lines {
		events := parser.Parse(line)
		require.Equal(t, 1, len(events))
	}
}

func TestDNSType(t *testing.T) {
	parser := &DNSParser{}
	require.Equal(t, "Suricata.DNS", parser.LogType())
}
