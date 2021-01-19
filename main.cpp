#include <bits/stdc++.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>

using namespace std;

typedef pair<uint32_t, uint16_t> tcp_key;

struct A {
	int send, recv;
	int sB, rB;
};

bool operator<(const ether_addr &a, const ether_addr &b) {
	bool f = false;
	for (int i = 0; i < ETH_ALEN; i++)
		if (a.ether_addr_octet[i] != b.ether_addr_octet[i]) {
			f = a.ether_addr_octet[i] < b.ether_addr_octet[i];
			break;
		}
	return f;
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		cout << "syntax: report_ip_stat <pcap path>\n";
		cout << "sample: report_ip_stat ./test.pcap\n";
		return 0;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	FILE *f = fopen(argv[1], "r");
	if (f == nullptr) {
		cout << "File doesn't exist.\n";
		return 0;
	}

	pcap_t *handle = pcap_fopen_offline(f, errbuf);
	if (handle == nullptr) {
		cerr << "pcap_fopen_offline(" << argv[1] << ") return nullptr - " << errbuf << "\n";
		return 0;
	}

	unordered_map<uint32_t, A> mp; //ip
	map<ether_addr, A> mac_mp; //mac address

	auto update = [](auto &endpoint, const auto &key, bool isRecv, int byteLen) {
		A &val = endpoint[key];
		if (isRecv) {
			++val.recv;
			val.rB += byteLen;
		} else {
			++val.send;
			val.sB += byteLen;
		}
	};

	map<tcp_key, map<tcp_key, pair<int, int>>> conv_tcp; //tcp conversation
	map<ether_addr, map<ether_addr, pair<int, int>>> conv_ether; //ethernet conversation

	auto flow_update = [](auto &conversation, const auto &src, const auto &dst, int byteLen) {
		++conversation[src][dst].first;
		conversation[src][dst].second += byteLen;
	};

	while (1) {
		pcap_pkthdr *header;
		const u_char *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1) {
			cerr << "pcap_next_ex return -1(" << pcap_geterr(handle) << ")\n";
			break;
		}
		if (res == -2) break;

		auto *eth = (ether_header *) packet;

		ether_addr dst_eth{}, src_eth{};
		memcpy(dst_eth.ether_addr_octet, eth->ether_dhost, sizeof(eth->ether_dhost));
		memcpy(src_eth.ether_addr_octet, eth->ether_shost, sizeof(eth->ether_shost));

		//cout << ether_ntoa(&src_eth) << " " << ether_ntoa(&dst_eth) << "\n";

		update(mac_mp, src_eth, false, header->caplen); //send ethernet packet
		update(mac_mp, dst_eth, true, header->caplen); //recv ethernet packet

		flow_update(conv_ether, src_eth, dst_eth, header->caplen);

		ip *_ip = (ip *) (packet + 14);
		if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
			auto src_ip = _ip->ip_src.s_addr, dst_ip = _ip->ip_dst.s_addr;
			update(mp, src_ip, true, header->caplen); //recv ip packet
			update(mp, dst_ip, false, header->caplen); //send ip packet

			if (_ip->ip_p == IPPROTO_TCP) {
				auto *tcp = (tcphdr *) (packet + 14 + _ip->ip_hl * 4);
				auto src_port = tcp->th_sport, dst_port = tcp->th_dport;

				flow_update(conv_tcp, tcp_key(src_ip, src_port), tcp_key(dst_ip, dst_port), header->caplen);
			}
		}
	}

	for (const auto &[ip, info] : mp)
		cout << inet_ntoa({ip}) << " (total " << info.rB + info.sB << " bytes)\n received " << info.recv
		     << " ip packets ("
		     << info.rB << " bytes)\n "
		     << "sent " << info.send << " ip packets (" << info.sB << " bytes)\n\n";

	for (const auto &[mac, info] : mac_mp)
		cout << ether_ntoa(&mac) << " (total " << info.rB + info.sB << " bytes)\n received " << info.recv
		     << " ethernet packets ("
		     << info.rB << " bytes)\n "
		     << "sent " << info.send << " ethernet packets (" << info.sB << " bytes)\n\n";
	{
		map<tcp_key, map<tcp_key, bool>> vis;
		cout << "=== DUMP TCP Conversations ===\n";
		cout << "A -> B     Send(Count/Len) / Recv(Count/Len)\n";
		for (const auto &[a, b] : conv_tcp)
			for (const auto &[c, d] : b) {
				if (vis[a][c]) continue;
				vis[c][a] = true;
				auto rev = conv_tcp[c][a];
				cout << inet_ntoa({a.first}) << ":" << ntohs(a.second) << " -> " << inet_ntoa({c.first}) << ":"
				     << ntohs(c.second)
				     << "    >    " << d.first << " packets " << d.second << " bytes / " << rev.first << " packets "
				     << rev.second << " bytes\n";
			}
	}

	{
		map<ether_addr, map<ether_addr, bool>> vis;
		cout << "\n=== DUMP Ethernet Conversations ===\n";
		cout << "A -> B     Send(Count/Len) / Recv(Count/Len)\n";
		for (const auto &[a, b] : conv_ether)
			for (const auto &[c, d] : b) {
				if (vis[a][c]) continue;
				vis[c][a] = true;
				auto rev = conv_ether[c][a];
				cout << ether_ntoa(&a) << " -> " << ether_ntoa(&c) << "    >    " << d.first << " packets " << d.second
				     << " bytes / " << rev.first << " packets " << rev.second << " bytes\n";
			}
	}

	pcap_close(handle);
}
