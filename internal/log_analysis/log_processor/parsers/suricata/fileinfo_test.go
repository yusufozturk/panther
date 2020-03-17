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

func TestFileinfo(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	//nolint:lll
	logs := `{"timestamp": "2019-01-02T06:42:52.664089", "flow_id": 43586704, "in_iface": "eth0", "event_type": "fileinfo", "src_ip": "198.199.99.226", "src_port": 80, "dest_ip": "138.68.3.71", "dest_port": 41694, "proto": "TCP", "http": {"url": "/ubuntu/pool/main/t/tzdata/tzdata_2018i-0ubuntu0.16.04_all.deb", "hostname": "mirrors.digitalocean.com", "http_user_agent": "Debian APT-HTTP/1.3 (1.2.29)"}, "fileinfo": {"filename": "/ubuntu/pool/main/t/tzdata/tzdata_2018i-0ubuntu0.16.04_all.deb", "state": "TRUNCATED", "stored": false, "size": 1197, "tx_id": 0}}
`

	parser := &FileinfoParser{}
	lines := strings.FieldsFunc(logs, func(r rune) bool { return r == '\n' })
	for _, line := range lines {
		events := parser.Parse(line)
		require.Equal(t, 1, len(events))
	}
}

func TestFileinfoType(t *testing.T) {
	parser := &FileinfoParser{}
	require.Equal(t, "Suricata.Fileinfo", parser.LogType())
}
