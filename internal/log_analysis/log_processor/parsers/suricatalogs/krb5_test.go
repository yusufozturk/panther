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
func TestKrb5(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2016-08-16T22:05:15.023938+0000", "flow_id": 1976683772688143, "pcap_cnt": 341, "event_type": "krb5", "src_ip": "192.168.1.46", "src_port": 49163, "dest_ip": "192.168.1.195", "dest_port": 88, "proto": "006", "community_id": "1:7qqzStB4B915cu3xJprlm397rUw=", "krb5": {"msg_type": "KRB_TGS_REP", "cname": "CHIP-DOUGLAS-PC$", "realm": "PICKLESWORTH.LOCAL", "sname": "ldap/win-cnneq7ocuqs.picklesworth.local", "encryption": "aes256-cts-hmac-sha1-96", "weak_encryption": false}, "pcap_filename": "/pcaps/aug_16_par4.pcap"}`,
		`{"timestamp": "2017-03-01T00:42:57.918656+0000", "flow_id": 782354483315124, "pcap_cnt": 5124, "event_type": "krb5", "src_ip": "192.168.1.46", "src_port": 49516, "dest_ip": "192.168.1.195", "dest_port": 88, "proto": "006", "community_id": "1:6BI+PKLSdYaPUF2Qt7ihdYgLPf4=", "krb5": {"msg_type": "KRB_TGS_REP", "cname": "choppydog", "realm": "PICKLESWORTH.LOCAL", "sname": "LDAP/SnickleFritz.picklesworth.local/picklesworth.local", "encryption": "aes256-cts-hmac-sha1-96", "weak_encryption": false}, "pcap_filename": "/pcaps/winreg_query_rdp_netshare_madness.pcap"}`,
		`{"timestamp": "2017-04-17T18:26:12.118186+0000", "flow_id": 659584717212215, "pcap_cnt": 36, "event_type": "krb5", "src_ip": "192.168.1.46", "src_port": 49243, "dest_ip": "192.168.1.195", "dest_port": 88, "proto": "006", "community_id": "1:6CVTUtjdbYaK3OF9V45vNt1sIBY=", "krb5": {"msg_type": "KRB_TGS_REP", "cname": "Administrator", "realm": "PICKLESWORTH.LOCAL", "sname": "RPCSS/SNICKLEFRITZ.picklesworth.local", "encryption": "aes256-cts-hmac-sha1-96", "weak_encryption": false}, "pcap_filename": "/pcaps/ipconf1.pcap"}`,
		`{"timestamp": "2017-02-20T03:42:58.554375+0000", "flow_id": 69075518769191, "pcap_cnt": 841, "event_type": "krb5", "src_ip": "192.168.1.46", "src_port": 49165, "dest_ip": "192.168.1.195", "dest_port": 88, "proto": "006", "community_id": "1:ZcOn0A8Tsa855bu7axOy6PImJds=", "krb5": {"msg_type": "KRB_TGS_REP", "cname": "CHIP_DOUGLAS-PC$", "realm": "PICKLESWORTH.LOCAL", "sname": "LDAP/SnickleFritz.picklesworth.local/picklesworth.local", "encryption": "aes256-cts-hmac-sha1-96", "weak_encryption": false}, "pcap_filename": "/pcaps/rig_dreambot_variant.pcap"}`,
		`{"timestamp": "2016-08-16T22:47:01.405982+0000", "flow_id": 1342489066023399, "pcap_cnt": 7448, "event_type": "krb5", "src_ip": "192.168.1.195", "src_port": 88, "dest_ip": "192.168.1.46", "dest_port": 49179, "proto": "006", "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:IJXQ/eya2G3+KoANAChsCZt9VNg=", "krb5": {"msg_type": "KRB_ERROR", "failed_request": "KRB_TGS_REQ", "error_code": "KDC_ERR_BADOPTION", "cname": "<empty>", "realm": "<empty>", "sname": "chip-douglas-pc$@PICKLESWORTH.LOCAL", "encryption": "<none>", "weak_encryption": false}, "pcap_filename": "/pcaps/aug_16_par4.pcap"}`,
		`{"timestamp": "2017-02-21T23:11:43.885486+0000", "flow_id": 259793062166522, "pcap_cnt": 126, "event_type": "krb5", "src_ip": "192.168.1.46", "src_port": 49225, "dest_ip": "192.168.1.195", "dest_port": 88, "proto": "006", "community_id": "1:XV+h24kQs8VQTNFuxQ+lB1+2Ho4=", "krb5": {"msg_type": "KRB_TGS_REP", "cname": "Administrator", "realm": "PICKLESWORTH.LOCAL", "sname": "RestrictedKrbHost/SnickleFritz", "encryption": "aes256-cts-hmac-sha1-96", "weak_encryption": false}, "pcap_filename": "/pcaps/wmi_commands_calc.pcap"}`,
		`{"timestamp": "2017-02-22T00:01:37.871946+0000", "flow_id": 2095153043032915, "pcap_cnt": 28, "event_type": "krb5", "src_ip": "192.168.1.195", "src_port": 88, "dest_ip": "192.168.1.46", "dest_port": 49336, "proto": "006", "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:R9miHSw1L57oIe2eEahA6UoIvx4=", "krb5": {"msg_type": "KRB_ERROR", "failed_request": "KRB_AS_REQ", "error_code": "KDC_ERR_PREAUTH_REQUIRED", "cname": "<empty>", "realm": "<empty>", "sname": "krbtgt/picklesworth", "encryption": "<none>", "weak_encryption": false}, "pcap_filename": "/pcaps/wmi_to_vss.pcap"}`,
		`{"timestamp": "2017-07-25T21:01:15.475259+0000", "flow_id": 1973845394930912, "pcap_cnt": 399, "event_type": "krb5", "src_ip": "192.168.1.195", "src_port": 88, "dest_ip": "192.168.1.46", "dest_port": 49247, "proto": "006", "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:oNkSrT1U9PU9F2D93OxVfajTlrY=", "krb5": {"msg_type": "KRB_ERROR", "failed_request": "KRB_AS_REQ", "error_code": "KDC_ERR_PREAUTH_REQUIRED", "cname": "<empty>", "realm": "<empty>", "sname": "krbtgt/Picklesworth", "encryption": "<none>", "weak_encryption": false}, "pcap_filename": "/pcaps/schtasks.pcap"}`,
		`{"timestamp": "2016-08-15T21:51:46.508681+0000", "flow_id": 1079485159096279, "pcap_cnt": 11336, "event_type": "krb5", "src_ip": "192.168.1.46", "src_port": 54444, "dest_ip": "192.168.1.195", "dest_port": 88, "proto": "006", "community_id": "1:t1cCPlqslJqbIYWcYV5+o2vbLmY=", "krb5": {"msg_type": "KRB_TGS_REP", "cname": "CHIP-DOUGLAS-PC$", "realm": "PICKLESWORTH.LOCAL", "sname": "chip-douglas-pc$@PICKLESWORTH.LOCAL", "encryption": "aes256-cts-hmac-sha1-96", "weak_encryption": false}, "pcap_filename": "/pcaps/jon_3.pcap"}`,
		`{"timestamp": "2017-04-25T19:59:40.471923+0000", "flow_id": 1577462746853526, "pcap_cnt": 320, "event_type": "krb5", "src_ip": "192.168.1.195", "src_port": 88, "dest_ip": "192.168.1.46", "dest_port": 49166, "proto": "006", "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:+f/rL8S47b5dB/kbK71QKmLj9as=", "krb5": {"msg_type": "KRB_ERROR", "failed_request": "KRB_AS_REQ", "error_code": "KDC_ERR_PREAUTH_REQUIRED", "cname": "<empty>", "realm": "<empty>", "sname": "krbtgt/PICKLESWORTH.LOCAL", "encryption": "<none>", "weak_encryption": false}, "pcap_filename": "/pcaps/wmi_exec_2.pcap"}`,
	}

	parser := &Krb5Parser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestKrb5Type(t *testing.T) {
	parser := &Krb5Parser{}
	require.Equal(t, "Suricata.Krb5", parser.LogType())
}
