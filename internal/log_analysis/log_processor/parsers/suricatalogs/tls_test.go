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
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

//nolint:lll
func TestTLS(t *testing.T) {
	zap.ReplaceGlobals(zaptest.NewLogger(t))

	logs := []string{
		`{"timestamp": "2017-02-20T03:46:35.822861+0000", "flow_id": 1963639294378664, "pcap_cnt": 8672, "event_type": "tls", "src_ip": "192.168.1.46", "src_port": 49411, "dest_ip": "216.58.217.65", "dest_port": 443, "proto": "006", "community_id": "1:AHz9+kD8UIQt8WCig8PDfs9iTPc=", "tls": {"subject": "C=US, ST=California, L=Mountain View, O=Google Inc, CN=tpc.googlesyndication.com", "issuerdn": "C=US, O=Google Inc, CN=Google Internet Authority G2", "serial": "7C:A0:B0:E6:92:73:25:F7", "fingerprint": "0a:d5:92:f1:b9:16:30:f4:13:c9:ee:e7:3e:d3:bf:98:ca:74:ab:e0", "sni": "tpc.googlesyndication.com", "version": "TLSv1", "notbefore": "2017-02-01T13:47:26", "notafter": "2017-04-26T13:21:00", "ja3": {"hash": "2201d8e006f8f005a6b415f61e677532", "string": "769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,65281-0-5-10-11,23-24,0"}, "ja3s": {"hash": "184d532a16876b78846ae6a03f654890", "string": "769,49171,65281-11"}}, "pcap_filename": "/pcaps/rig_dreambot_variant.pcap"}`,
		`{"timestamp": "2015-10-22T08:01:19.412493+0000", "flow_id": 471667256011071, "event_type": "tls", "src_ip": "192.168.2.166", "src_port": 1701, "dest_ip": "192.168.88.115", "dest_port": 80, "proto": "006", "metadata": {"flowints": {"applayer.anomaly.count": 1}}, "community_id": "1:a7jb/UcWr5uIqCjFzogYaPlN+UI=", "tls": {"version": "SSLv2", "ja3": {"hash": "d0efa5850df2a794759c6e9478335477", "string": "771,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-59-49200-49196-49192-49188-49172-49162-163-159-107-106-56-136-135-49177-167-109-137-49202-49198-49194-49190-49167-49157-157-61-132-49199-49195-49191-49187-49171-49161-162-158-103-64-50-154-153-69-68-49176-166-108-155-70-49201-49197-49193-49189-49166-49156-156-60-150-65-7-49169-49159-49174-49164-49154-49170-49160-19-49175-49165-49155-18-17-255,11-10-35-13-15-21,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2"}, "ja3s": {}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T08:57:20.985775+0000", "flow_id": 1446530512618694, "event_type": "tls", "src_ip": "192.168.2.199", "src_port": 44241, "dest_ip": "192.168.88.51", "dest_port": 443, "proto": "006", "community_id": "1:QMQyEqG2nfm6is0FWG8bvK5jscc=", "tls": {"version": "UNDETERMINED", "ja3": {"hash": "f9f7dafdbb2f53769ded4abaca13caec", "string": "771,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-59-49200-49196-49192-49188-49172-49162-163-159-107-106-56-136-135-49177-167-109-137-49202-49198-49194-49190-49167-49157-157-61-132-49199-49195-49191-49187-49171-49161-162-158-103-64-50-154-153-69-68-49176-166-108-155-70-49201-49197-49193-49189-49166-49156-156-60-150-65-49169-49159-49174-49164-49154-49170-49160-19-49175-49165-49155-18-17-255,11-10-35-13-15-21,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2"}, "ja3s": {}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2017-02-13T22:16:11.922267+0000", "flow_id": 297538962585927, "pcap_cnt": 1995, "event_type": "tls", "src_ip": "192.168.1.46", "src_port": 49578, "dest_ip": "216.58.217.162", "dest_port": 443, "proto": "006", "community_id": "1:4KajY07fp752XcV1LF/XVSlhR2Q=", "tls": {"subject": "C=US, ST=California, L=Mountain View, O=Google Inc, CN=www.googleadservices.com", "issuerdn": "C=US, O=Google Inc, CN=Google Internet Authority G2", "serial": "04:16:85:05:68:A1:51:AC", "fingerprint": "d8:89:b3:a4:c2:ac:81:cc:4e:d0:af:85:cf:8b:35:a3:0e:24:bc:8a", "sni": "www.googleadservices.com", "version": "TLSv1", "notbefore": "2017-01-25T10:41:05", "notafter": "2017-04-19T10:09:00", "ja3": {"hash": "2201d8e006f8f005a6b415f61e677532", "string": "769,47-53-5-10-49171-49172-49161-49162-50-56-19-4,65281-0-5-10-11,23-24,0"}, "ja3s": {"hash": "8ca430f840a9e4501ec08479c0bc714c", "string": "769,49171,65281-0-11"}}, "pcap_filename": "/pcaps/capture-Mon-02-13-17-17-15-34_Empire.pcap"}`,
		`{"timestamp": "2015-10-22T11:19:00.698615+0000", "flow_id": 1741754296718096, "pcap_cnt": 1812722, "event_type": "tls", "src_ip": "192.168.2.22", "src_port": 33284, "dest_ip": "192.168.88.75", "dest_port": 443, "proto": "006", "community_id": "1:RSsIIek9JqB5H0HRjjuZb+VP2cU=", "tls": {"session_resumed": true, "version": "TLSv1", "ja3": {"hash": "07e4f12082fc28a84c5412bedc0aa0e2", "string": "771,49195-49199-49162-49161-49171-49172-51-57-47-53-10,65281-10-11-35-13172-16-5-13,23-24-25,0"}, "ja3s": {"hash": "18e962e106761869a61045bed0e81c2c", "string": "769,47,"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-21T12:01:19.231075+0000", "flow_id": 1990678662818850, "pcap_cnt": 738397, "event_type": "tls", "src_ip": "192.168.2.113", "src_port": 3316, "dest_ip": "192.168.88.115", "dest_port": 443, "proto": "006", "community_id": "1:r6EeYkHeF0gexmuhOImqGIL1H9Y=", "tls": {"subject": "C=US, ST=Minnesota, O=Digi International, CN=Digi CM", "issuerdn": "C=US, ST=Minnesota, L=Minneapois, O=Digi International, CN=Digi International", "serial": "04", "fingerprint": "db:1a:a3:65:35:ac:b2:b5:b0:61:30:83:a8:c3:a0:da:57:08:62:44", "version": "TLSv1", "notbefore": "2004-03-22T04:04:12", "notafter": "2014-03-21T04:04:12", "ja3": {}, "ja3s": {"hash": "9aeeb84942a46257594025306635f0ff", "string": "769,5,"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
		`{"timestamp": "2015-10-22T12:47:50.074263+0000", "flow_id": 1037229685654402, "pcap_cnt": 2188351, "event_type": "tls", "src_ip": "192.168.2.53", "src_port": 38364, "dest_ip": "192.168.88.75", "dest_port": 443, "proto": "006", "community_id": "1:hQtC0rzorEfHpRo1VlmzEHQ3u8M=", "tls": {"session_resumed": true, "version": "TLSv1", "ja3": {"hash": "703eb8ca6b6319bc627d4694394f375c", "string": "769,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-49172-49162-49186-49185-56-136-135-49177-49184-137-49167-49157-132-49170-49160-49180-49179-19-49175-49178-49165-49155-49171-49161-49183-49182-50-154-153-69-68-49176-49181-155-70-49166-49156-150-65-49169-49159-49174-49164-49154-18-17-255,11-10-35-15,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2"}, "ja3s": {"hash": "ab1e32eeaf70ee94c0af00f08d126891", "string": "769,53,"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T08:40:11.529916+0000", "flow_id": 9533232226516, "pcap_cnt": 787575, "event_type": "tls", "src_ip": "192.168.2.199", "src_port": 59700, "dest_ip": "192.168.88.75", "dest_port": 443, "proto": "006", "community_id": "1:Fd9+CsuZly9+36suLbjIkmQp3Vc=", "tls": {"session_resumed": true, "version": "TLSv1", "ja3": {"hash": "75cf58e015270e5cbb444641a8cee23a", "string": "769,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-49172-49162-56-136-135-49177-137-49167-49157-132-49171-49161-50-154-153-69-68-49176-155-70-49166-49156-150-65-49169-49159-49174-49164-49154-49170-49160-19-49175-49165-49155-18-17-255,11-10-35-15-21,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2"}, "ja3s": {"hash": "ab1e32eeaf70ee94c0af00f08d126891", "string": "769,53,"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-22T07:19:40.308480+0000", "flow_id": 683941565321653, "pcap_cnt": 277323, "event_type": "tls", "src_ip": "192.168.2.137", "src_port": 59595, "dest_ip": "192.168.88.75", "dest_port": 443, "proto": "006", "community_id": "1:LL7mj5JOPw9eNI3lhyATePbeXFA=", "tls": {"session_resumed": true, "version": "TLSv1", "ja3": {"hash": "5310f0ed1061dd952936a4a4f747c1e9", "string": "769,5-4-2-8-20-3-1-21-6-22-23-51-57-25-58-26-24-53-9-10-27-47-52-49168-49158-49173-49163-49153-49172-49162-56-136-135-49177-137-49167-49157-132-49170-49160-19-49175-49165-49155-49171-49161-50-154-153-69-68-49176-155-70-49166-49156-150-65-49169-49159-49174-49164-49154-18-17-255,11-10-35-15,14-13-25-11-12-24-9-10-22-23-8-6-7-20-21-4-5-18-19-1-2-3-15-16-17,0-1-2"}, "ja3s": {"hash": "ab1e32eeaf70ee94c0af00f08d126891", "string": "769,53,"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`,
		`{"timestamp": "2015-10-21T10:11:29.985299+0000", "flow_id": 1810800705651822, "pcap_cnt": 488950, "event_type": "tls", "src_ip": "192.168.2.64", "src_port": 52205, "dest_ip": "192.168.88.61", "dest_port": 443, "proto": "006", "community_id": "1:+lH4wgQgnz0scLAdtgZJspzg5nk=", "tls": {"subject": "CN=192.168.88.61/O=Moxa Networking Co., Ltd./OU=IEI/C=TW/unknown=Taiwan/L=Taipei", "issuerdn": "C=TW, ST=Taiwan, L=Taipei, O=Moxa Networking Co., Ltd., OU=Moxa Networking, CN=Moxa Networking Co., Ltd./emailAddress=support@moxanet.com", "serial": "00:83:30:1C:10:21:DE:05:D1", "fingerprint": "68:ae:f5:27:45:83:d2:14:45:d6:c8:0a:2a:e7:14:38:75:59:8c:d1", "version": "TLSv1", "notbefore": "2002-11-13T00:00:00", "notafter": "2032-11-12T00:00:00", "ja3": {}, "ja3s": {"hash": "9aeeb84942a46257594025306635f0ff", "string": "769,5,"}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151021.pcap"}`,
	}

	parser := &TLSParser{}
	for _, log := range logs {
		events := parser.Parse(log)
		require.Equal(t, 1, len(events))
	}
}

func TestTLSType(t *testing.T) {
	parser := &TLSParser{}
	require.Equal(t, "Suricata.TLS", parser.LogType())
}
