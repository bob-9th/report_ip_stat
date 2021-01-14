#include <bits/stdc++.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/ethernet.h>

using namespace std;

struct A {
	int send, recv;
	int sB, rB;

	bool operator<(const A &b) const {
		if (send != b.send) return send < b.send;
		if (recv != b.recv) return recv < b.recv;
		if (sB != b.sB) return sB < b.sB;
		if (rB != b.rB) return rB < b.rB;
		return 0;
	}
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

bool operator==(const ether_addr &a, const ether_addr &b) {
	bool f = true;
	for (int i = 0; i < ETH_ALEN; i++)
		if (a.ether_addr_octet[i] != b.ether_addr_octet[i]) {
			f = false;
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
		return -0;
	}

	unordered_map<uint32_t, A> mp; //ip
	set<pair<ether_addr, A>> mac_mp; //mac address

	auto update = [](auto &mac_mp, const ether_addr &mac, bool isRecv, int byteLen) {
		auto it = mac_mp.lower_bound(make_pair(mac, A{}));
		A val = {};
		if (it != mac_mp.end() && it->first == mac) val = it->second, mac_mp.erase(it);
		if (isRecv) {
			++val.recv;
			val.rB += byteLen;
		} else {
			++val.send;
			val.sB += byteLen;
		}
		mac_mp.insert(make_pair(mac, val));
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

		ether_addr tmp{};
		memcpy(tmp.ether_addr_octet, eth->ether_dhost, sizeof(eth->ether_dhost));
		update(mac_mp, tmp, true, header->caplen);
		memcpy(tmp.ether_addr_octet, eth->ether_shost, sizeof(eth->ether_shost));
		update(mac_mp, tmp, false, header->caplen);

		ip *_ip = (ip *) (packet + 14);
		if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
			auto &dst = mp[_ip->ip_dst.s_addr];
			++dst.recv;
			dst.rB += header->caplen;

			auto &src = mp[_ip->ip_src.s_addr];
			++src.send;
			src.sB += header->caplen;
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


	pcap_close(handle);
}
