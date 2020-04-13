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
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

//nolint:lll
func TestIkev2(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2015-08-10T13:15:41.689103+0000", "flow_id": 1979072141687872, "pcap_cnt": 2, "event_type": "ikev2", "src_ip": "192.168.12.2", "src_port": 500, "dest_ip": "192.168.12.1", "dest_port": 500, "proto": "017", "community_id": "1:hNRHE/97j/DjLoaW67ZqPtdXa2Q=", "ikev2": {"version_major": 2, "version_minor": 0, "exchange_type": 34, "message_id": 0, "init_spi": "864330ac30e6564d", "resp_spi": "8329cc09a2c7d7e0", "role": "responder", "alg_enc": "ENCR_AES_CBC", "alg_auth": "AUTH_HMAC_SHA1_96", "alg_prf": "PRF_HMAC_SHA1", "alg_dh": "1024-bit MODP Group", "alg_esn": "NoESN", "errors": 0, "payload": ["SecurityAssociation", "KeyExchange", "Nonce", "VendorID", "VendorID", "VendorID", "Notify", "Notify", "VendorID", "NoNextPayload"], "notify": ["NAT_DETECTION_SOURCE_IP", "NAT_DETECTION_DESTINATION_IP"]}, "pcap_filename": "/pcaps/wireshark-capture-ipsec-ikev2.pcap"}`,
		`{"timestamp": "2015-08-10T13:15:41.687168+0000", "flow_id": 1979072141687872, "pcap_cnt": 1, "event_type": "ikev2", "src_ip": "192.168.12.1", "src_port": 500, "dest_ip": "192.168.12.2", "dest_port": 500, "proto": "017", "community_id": "1:hNRHE/97j/DjLoaW67ZqPtdXa2Q=", "ikev2": {"version_major": 2, "version_minor": 0, "exchange_type": 34, "message_id": 0, "init_spi": "864330ac30e6564d", "resp_spi": "0000000000000000", "role": "initiator", "errors": 0, "payload": ["SecurityAssociation", "KeyExchange", "Nonce", "VendorID", "VendorID", "VendorID", "Notify", "Notify", "VendorID", "NoNextPayload"], "notify": ["NAT_DETECTION_SOURCE_IP", "NAT_DETECTION_DESTINATION_IP"]}, "pcap_filename": "/pcaps/wireshark-capture-ipsec-ikev2.pcap"}`,
	}

	parser := &Ikev2Parser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestIkev2Type(t *testing.T) {
	parser := &Ikev2Parser{}
	require.Equal(t, "Suricata.Ikev2", parser.LogType())
}
