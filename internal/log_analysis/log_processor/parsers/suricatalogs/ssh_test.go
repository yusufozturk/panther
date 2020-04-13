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
func TestSSH(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2015-10-22T08:42:39.713239+0000", "flow_id": 474386142286007, "pcap_cnt": 815531, "event_type": "ssh", "src_ip": "192.168.2.199", "src_port": 32888, "dest_ip": "192.168.88.60", "dest_port": 22, "proto": "006", "community_id": "1:c9jAl5ZaMeBzC6QUo2v3Bj1/mM0=", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "moxa_1.0"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-21T10:44:22.417407+0000", "flow_id": 1910046664381883, "event_type": "ssh", "src_ip": "192.168.2.64", "src_port": 52596, "dest_ip": "192.168.88.61", "dest_port": 22, "proto": "006", "community_id": "1:SrXlg2+Bhog+x7Glx+zIRzk4lFE=", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "moxa_1.0"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-22T11:38:15.996199+0000", "flow_id": 682782940970753, "pcap_cnt": 1955025, "event_type": "ssh", "src_ip": "192.168.2.53", "src_port": 35137, "dest_ip": "192.168.88.61", "dest_port": 22, "proto": "006", "community_id": "1:fG7qXhIJAmDMB4+reqeBc/EAcfk=", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "moxa_1.0"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T12:49:49.732874+0000", "flow_id": 2046426748920167, "pcap_cnt": 2195120, "event_type": "ssh", "src_ip": "192.168.2.53", "src_port": 54390, "dest_ip": "192.168.88.115", "dest_port": 22, "proto": "006", "community_id": "1:dJ456d0DbSEXqnGhTLvXotYvn+c=", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_4.0"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T12:40:18.967905+0000", "flow_id": 751343747904519, "pcap_cnt": 2136885, "event_type": "ssh", "src_ip": "192.168.2.53", "src_port": 54177, "dest_ip": "192.168.88.115", "dest_port": 22, "proto": "006", "community_id": "1:rP3dZqjERB0BG1TymAg+NOM3Dxw=", "ssh": {"client": {"proto_version": "1.5", "software_version": "NmapNSE_1.0"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_4.0"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T07:35:40.642663+0000", "flow_id": 650243314875828, "pcap_cnt": 326889, "event_type": "ssh", "src_ip": "192.168.2.137", "src_port": 41775, "dest_ip": "192.168.88.60", "dest_port": 22, "proto": "006", "community_id": "1:0a3qoIiTVNhGNtRlGMQJukU7Q1A=", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "moxa_1.0"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T11:38:45.618441+0000", "flow_id": 79872613599473, "pcap_cnt": 1962430, "event_type": "ssh", "src_ip": "192.168.2.53", "src_port": 46410, "dest_ip": "192.168.88.95", "dest_port": 22, "proto": "006", "community_id": "1:fkWjfdtmIbn6dj39kGRSLpPyH44=", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "Mocana SSH "}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-03-30T14:45:20.303691+0000", "flow_id": 440819899201146, "pcap_cnt": 204, "event_type": "ssh", "src_ip": "192.168.56.1", "src_port": 55475, "dest_ip": "192.168.56.103", "dest_port": 22, "proto": "006", "community_id": "1:K0Zgy1NXTNl2KkxdkLkhQUbr7QY=", "ssh": {"client": {"proto_version": "2.0", "software_version": "OpenSSH_6.2"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_6.7p1 Debian-3"}}, "pcap_filename": "/pcaps/sshguess.pcap"}`,
		`{"timestamp": "2015-10-22T07:35:17.978557+0000", "flow_id": 1251706238527028, "pcap_cnt": 324480, "event_type": "ssh", "src_ip": "192.168.2.137", "src_port": 53868, "dest_ip": "192.168.88.115", "dest_port": 22, "proto": "006", "community_id": "1:Rwvq+qGhphtiKadq7WE8DrP3HZc=", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "OpenSSH_4.0"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T11:38:15.196018+0000", "flow_id": 625586861431557, "pcap_cnt": 1954599, "event_type": "ssh", "src_ip": "192.168.2.53", "src_port": 35098, "dest_ip": "192.168.88.61", "dest_port": 22, "proto": "006", "community_id": "1:+KgWN9Mcf8ziWFy6L9vbQZa6OkQ=", "ssh": {"client": {"proto_version": "2.0", "software_version": "Nmap-SSH2-Hostkey"}, "server": {"proto_version": "2.0", "software_version": "moxa_1.0"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
	}

	parser := &SSHParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestSSHType(t *testing.T) {
	parser := &SSHParser{}
	require.Equal(t, "Suricata.SSH", parser.LogType())
}
