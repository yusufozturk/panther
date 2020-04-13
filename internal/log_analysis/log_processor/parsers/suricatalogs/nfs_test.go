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
func TestNfs(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "1999-12-03T07:48:58.570000+0000", "flow_id": 1152116218034704, "pcap_cnt": 36, "event_type": "nfs", "src_ip": "139.25.22.102", "src_port": 2049, "dest_ip": "139.25.22.2", "dest_port": 1023, "proto": "017", "community_id": "1:rZbRQnUEiYTnE+Ne8hdtynlE5Z0=", "rpc": {"xid": 1578961825, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "werrmsche", "uid": 0, "gid": 0}}, "nfs": {"version": 2, "procedure": "ACCESS", "filename": "", "id": 14, "file_tx": false, "type": "response", "status": "ERR_NOENT"}, "pcap_filename": "/pcaps/nfsv2.pcap"}`,
		`{"timestamp": "2017-12-29T17:22:11.691876+0000", "flow_id": 1974228857618887, "pcap_cnt": 96, "event_type": "nfs", "src_ip": "10.111.131.18", "src_port": 720, "dest_ip": "10.111.131.132", "dest_port": 2049, "proto": "006", "community_id": "1:9oe5rmzlMseecMtxxJxspJXxB20=", "rpc": {"xid": 404785116, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "pddevbal802", "uid": 12, "gid": 889192448}}, "nfs": {"version": 3, "procedure": "RMDIR", "filename": "bro-nfs", "hhash": "56d448b4", "id": 35, "file_tx": false, "type": "response", "status": "OK"}, "pcap_filename": "/pcaps/mount_base.pcap"}`,
		`{"timestamp": "1999-12-03T07:48:58.580000+0000", "flow_id": 1152116218034704, "pcap_cnt": 44, "event_type": "nfs", "src_ip": "139.25.22.102", "src_port": 2049, "dest_ip": "139.25.22.2", "dest_port": 1023, "proto": "017", "community_id": "1:rZbRQnUEiYTnE+Ne8hdtynlE5Z0=", "rpc": {"xid": 1578961829, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "werrmsche", "uid": 0, "gid": 0}}, "nfs": {"version": 2, "procedure": "ACCESS", "filename": "", "id": 18, "file_tx": false, "type": "response", "status": "ERR_NOENT"}, "pcap_filename": "/pcaps/nfsv2.pcap"}`,
		`{"timestamp": "1999-12-03T07:48:58.560000+0000", "flow_id": 1152116218034704, "pcap_cnt": 32, "event_type": "nfs", "src_ip": "139.25.22.102", "src_port": 2049, "dest_ip": "139.25.22.2", "dest_port": 1023, "proto": "017", "community_id": "1:rZbRQnUEiYTnE+Ne8hdtynlE5Z0=", "rpc": {"xid": 1578961823, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "werrmsche", "uid": 0, "gid": 0}}, "nfs": {"version": 2, "procedure": "ACCESS", "filename": "", "id": 12, "file_tx": false, "type": "response", "status": "ERR_NOENT"}, "pcap_filename": "/pcaps/nfsv2.pcap"}`,
		`{"timestamp": "1999-12-03T07:48:58.530000+0000", "flow_id": 1152116218034704, "pcap_cnt": 14, "event_type": "nfs", "src_ip": "139.25.22.102", "src_port": 2049, "dest_ip": "139.25.22.2", "dest_port": 1023, "proto": "017", "community_id": "1:rZbRQnUEiYTnE+Ne8hdtynlE5Z0=", "rpc": {"xid": 1578961814, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "werrmsche", "uid": 0, "gid": 0}}, "nfs": {"version": 2, "procedure": "ACCESS", "filename": "", "id": 3, "file_tx": false, "type": "response", "status": "ERR_NOENT"}, "pcap_filename": "/pcaps/nfsv2.pcap"}`,
		`{"timestamp": "2017-12-29T17:22:11.651806+0000", "flow_id": 1974228857618887, "pcap_cnt": 88, "event_type": "nfs", "src_ip": "10.111.131.18", "src_port": 720, "dest_ip": "10.111.131.132", "dest_port": 2049, "proto": "006", "community_id": "1:9oe5rmzlMseecMtxxJxspJXxB20=", "rpc": {"xid": 371230684, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "pddevbal802", "uid": 12, "gid": 889192448}}, "nfs": {"version": 3, "procedure": "ACCESS", "filename": "testfile-link", "hhash": "5fbcc878", "id": 33, "file_tx": false, "type": "response", "status": "OK"}, "pcap_filename": "/pcaps/mount_base.pcap"}`,
		`{"timestamp": "2017-12-29T17:22:11.643131+0000", "flow_id": 1974228857618887, "pcap_cnt": 66, "event_type": "nfs", "src_ip": "10.111.131.18", "src_port": 720, "dest_ip": "10.111.131.132", "dest_port": 2049, "proto": "006", "community_id": "1:9oe5rmzlMseecMtxxJxspJXxB20=", "rpc": {"xid": 186681308, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "pddevbal802", "uid": 12, "gid": 889192448}}, "nfs": {"version": 3, "procedure": "READLINK", "filename": "", "id": 22, "file_tx": false, "type": "response", "status": "OK"}, "pcap_filename": "/pcaps/mount_base.pcap"}`,
		`{"timestamp": "1999-12-03T07:49:57.570000+0000", "flow_id": 1210278668999296, "pcap_cnt": 70, "event_type": "nfs", "src_ip": "139.25.22.102", "src_port": 2049, "dest_ip": "139.25.22.2", "dest_port": 1022, "proto": "017", "community_id": "1:sZT6xytzkYcJCYXRnXvKqdFSAW4=", "rpc": {"xid": 1578961913, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "werrmsche", "uid": 0, "gid": 0}}, "nfs": {"version": 3, "procedure": "MKDIR", "filename": "d", "hhash": "38a4e9f6", "id": 30, "file_tx": false, "type": "response", "status": "OK"}, "pcap_filename": "/pcaps/nfsv3.pcap"}`,
		`{"timestamp": "1999-12-03T07:48:58.540000+0000", "flow_id": 1152116218034704, "pcap_cnt": 18, "event_type": "nfs", "src_ip": "139.25.22.102", "src_port": 2049, "dest_ip": "139.25.22.2", "dest_port": 1023, "proto": "017", "community_id": "1:rZbRQnUEiYTnE+Ne8hdtynlE5Z0=", "rpc": {"xid": 1578961816, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "werrmsche", "uid": 0, "gid": 0}}, "nfs": {"version": 2, "procedure": "MKDIR", "filename": "", "id": 5, "file_tx": false, "type": "response", "status": "OK"}, "pcap_filename": "/pcaps/nfsv2.pcap"}`,
		`{"timestamp": "1999-12-03T07:48:58.490000+0000", "flow_id": 1152116218034704, "pcap_cnt": 12, "event_type": "nfs", "src_ip": "139.25.22.102", "src_port": 2049, "dest_ip": "139.25.22.2", "dest_port": 1023, "proto": "017", "community_id": "1:rZbRQnUEiYTnE+Ne8hdtynlE5Z0=", "rpc": {"xid": 1578961813, "status": "ACCEPTED", "auth_type": "UNIX", "creds": {"machine_name": "werrmsche", "uid": 0, "gid": 0}}, "nfs": {"version": 2, "procedure": "READDIRPLUS", "filename": "", "id": 2, "file_tx": false, "type": "response", "status": "OK"}, "pcap_filename": "/pcaps/nfsv2.pcap"}`,
	}

	parser := &NfsParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestNfsType(t *testing.T) {
	parser := &NfsParser{}
	require.Equal(t, "Suricata.Nfs", parser.LogType())
}
