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

func TestHTTP(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	//nolint:lll
	logs := `{"timestamp": "2019-01-02T06:44:53.005858", "flow_id": 43586704, "event_type": "http", "src_ip": "138.68.3.71", "src_port": 41694, "dest_ip": "198.199.99.226", "dest_port": 80, "proto": "TCP", "http": {"hostname": "mirrors.digitalocean.com", "url": "/ubuntu/pool/main/t/tzdata/tzdata_2018i-0ubuntu0.16.04_all.deb", "http_user_agent": "Debian APT-HTTP/1.3 (1.2.29)", "http_content_type": "application/octet-stream", "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": 1197, "tx_id": 0}}
`

	parser := &HTTPParser{}
	lines := strings.FieldsFunc(logs, func(r rune) bool { return r == '\n' })
	for _, line := range lines {
		events := parser.Parse(line)
		require.Equal(t, 1, len(events))
	}
}

func TestHTTPType(t *testing.T) {
	parser := &HTTPParser{}
	require.Equal(t, "Suricata.HTTP", parser.LogType())
}
