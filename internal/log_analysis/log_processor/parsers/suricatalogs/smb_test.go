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
func TestSmb(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2017-03-28T17:22:49.246410+0000", "flow_id": 992711290160032, "pcap_cnt": 1818, "event_type": "smb", "src_ip": "192.168.1.195", "src_port": 49538, "dest_ip": "192.168.1.46", "dest_port": 445, "proto": "006", "smb": {"id": 1135, "dialect": "2.10", "command": "SMB2_COMMAND_CLOSE", "status": "STATUS_SUCCESS", "status_code": "0x0", "session_id": 4398046511121, "tree_id": 5}, "pcap_filename": "/pcaps/more_netshare.pcap"}`,
		`{"timestamp": "2017-09-09T20:32:31.737656+0000", "flow_id": 2100388521519284, "pcap_cnt": 210, "event_type": "smb", "src_ip": "192.168.1.161", "src_port": 40334, "dest_ip": "192.168.1.195", "dest_port": 445, "proto": "006", "smb": {"id": 34, "dialect": "2.10", "command": "SMB2_COMMAND_CREATE", "status": "STATUS_SUCCESS", "status_code": "0x0", "session_id": 4398247837805, "tree_id": 13, "filename": "Temp\\__output", "disposition": "FILE_OPEN", "access": "normal", "created": 1504989110, "accessed": 1504989145, "modified": 1504989145, "changed": 1504989145, "size": 798, "fuid": "00000099-0010-0000-0011-0000ffffffff"}, "pcap_filename": "/pcaps/secretsdump_vssadmin.pcap"}`,
		`{"timestamp": "2017-03-28T17:22:49.444460+0000", "flow_id": 992711290160032, "pcap_cnt": 3610, "event_type": "smb", "src_ip": "192.168.1.195", "src_port": 49538, "dest_ip": "192.168.1.46", "dest_port": 445, "proto": "006", "smb": {"id": 2321, "dialect": "2.10", "command": "SMB2_COMMAND_CREATE", "status": "STATUS_SUCCESS", "status_code": "0x0", "session_id": 4398046511121, "tree_id": 5, "filename": "choppydog\\AppData\\Local\\Microsoft\\Internet Explorer\\Recovery", "disposition": "FILE_OPEN", "access": "normal", "created": 1478118874, "accessed": 1478118997, "modified": 1478118997, "changed": 1478118997, "size": 0, "fuid": "00000091-0050-0000-0085-0000ffffffff"}, "pcap_filename": "/pcaps/more_netshare.pcap"}`,
		`{"timestamp": "2017-05-09T20:02:17.874763+0000", "flow_id": 714592905416916, "pcap_cnt": 801, "event_type": "smb", "src_ip": "192.168.1.46", "src_port": 49190, "dest_ip": "192.168.1.195", "dest_port": 445, "proto": "006", "smb": {"id": 3, "dialect": "2.10", "command": "SMB2_COMMAND_SESSION_SETUP", "status": "STATUS_SUCCESS", "status_code": "0x0", "session_id": 4398046511129, "tree_id": 0, "kerberos": {"realm": "PICKLESWORTH.LOCAL", "snames": ["cifs", "SnickleFritz.picklesworth.local"]}}, "pcap_filename": "/pcaps/chip_host_signin.pcap"}`,
		`{"timestamp": "2017-04-25T20:21:00.384916+0000", "flow_id": 5294346048441, "pcap_cnt": 224, "event_type": "smb", "src_ip": "192.168.1.161", "src_port": 60244, "dest_ip": "192.168.1.195", "dest_port": 445, "proto": "006", "smb": {"id": 61, "dialect": "2.10", "command": "SMB2_COMMAND_TREE_CONNECT", "status": "STATUS_SUCCESS", "status_code": "0x0", "session_id": 4398046511189, "tree_id": 53, "share": "\\\\192.168.1.195\\ADMIN$", "share_type": "FILE"}, "pcap_filename": "/pcaps/wmi_exec1.pcap"}`,
		`{"timestamp": "2017-03-28T17:22:49.201648+0000", "flow_id": 992711290160032, "pcap_cnt": 1342, "event_type": "smb", "src_ip": "192.168.1.195", "src_port": 49538, "dest_ip": "192.168.1.46", "dest_port": 445, "proto": "006", "smb": {"id": 819, "dialect": "2.10", "command": "SMB2_COMMAND_CLOSE", "status": "STATUS_SUCCESS", "status_code": "0x0", "session_id": 4398046511121, "tree_id": 5}, "pcap_filename": "/pcaps/more_netshare.pcap"}`,
		`{"timestamp": "2017-05-01T20:48:08.671889+0000", "flow_id": 864390603777586, "pcap_cnt": 496, "event_type": "smb", "src_ip": "192.168.1.161", "src_port": 54998, "dest_ip": "192.168.1.195", "dest_port": 445, "proto": "006", "smb": {"id": 106, "dialect": "NT LM 0.12", "command": "SMB1_COMMAND_WRITE_ANDX", "status": "STATUS_SUCCESS", "status_code": "0x0", "session_id": 2048, "tree_id": 2048, "dcerpc": {"request": "REQUEST", "response": "RESPONSE", "opnum": 12, "req": {"frag_cnt": 1, "stub_data_size": 420}, "res": {"frag_cnt": 1, "stub_data_size": 28}, "call_id": 30}}, "pcap_filename": "/pcaps/smbexec.pcap"}`,
		`{"timestamp": "2017-03-28T17:22:49.083153+0000", "flow_id": 992711290160032, "pcap_cnt": 350, "event_type": "smb", "src_ip": "192.168.1.195", "src_port": 49538, "dest_ip": "192.168.1.46", "dest_port": 445, "proto": "006", "smb": {"id": 164, "dialect": "2.10", "command": "SMB2_COMMAND_CREATE", "status": "STATUS_SUCCESS", "status_code": "0x0", "session_id": 4398046511121, "tree_id": 5, "filename": "choppydog\\AppData\\Local\\Apps\\2.0\\HAD5QNX8.RHV\\7MZRWHPN.5LY\\clic...exe_baa8013a79450f71_0001.0003_none_855491df37a516c6", "disposition": "FILE_OPEN", "access": "normal", "created": 1490116228, "accessed": 1490116228, "modified": 1490116228, "changed": 1490116228, "size": 0, "fuid": "000000a9-0000-0000-0089-0000ffffffff"}, "pcap_filename": "/pcaps/more_netshare.pcap"}`,
		`{"timestamp": "2017-08-27T21:44:38.210454+0000", "flow_id": 517398558077594, "pcap_cnt": 9115, "event_type": "smb", "src_ip": "192.168.1.195", "src_port": 50300, "dest_ip": "192.168.1.46", "dest_port": 445, "proto": "006", "smb": {"id": 5963, "dialect": "2.10", "command": "SMB2_COMMAND_FIND", "status": "STATUS_NO_MORE_FILES", "status_code": "0x80000006", "session_id": 4398046511137, "tree_id": 1}, "pcap_filename": "/pcaps/xcopy_choppy_to_pick.pcap"}`,
		`{"timestamp": "2017-08-27T21:44:37.741783+0000", "flow_id": 517398558077594, "pcap_cnt": 4471, "event_type": "smb", "src_ip": "192.168.1.195", "src_port": 50300, "dest_ip": "192.168.1.46", "dest_port": 445, "proto": "006", "smb": {"id": 2936, "dialect": "2.10", "command": "SMB2_COMMAND_CLOSE", "status": "STATUS_SUCCESS", "status_code": "0x0", "session_id": 4398046511137, "tree_id": 1}, "pcap_filename": "/pcaps/xcopy_choppy_to_pick.pcap"}`,
	}

	parser := &SmbParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestSmbType(t *testing.T) {
	parser := &SmbParser{}
	require.Equal(t, "Suricata.Smb", parser.LogType())
}
