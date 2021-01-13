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
};

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

	unordered_map<string, A> mp; //ip
	unordered_map<string, A> mac_mp; //mac address

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
		string src_mac = string(ether_ntoa((ether_addr *) eth->ether_shost)),
				dst_mac = string(ether_ntoa((ether_addr *) eth->ether_dhost));

		auto &mac_dst = mac_mp[dst_mac];
		++mac_dst.recv;
		mac_dst.rB += header->caplen;

		auto &mac_src = mac_mp[src_mac];
		++mac_src.send;
		mac_src.sB += header->caplen;

		ip *_ip = (ip *) (packet + 14);
		if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
			string src_ip = string(inet_ntoa(_ip->ip_src));
			string dst_ip = string(inet_ntoa(_ip->ip_dst));

			auto &dst = mp[dst_ip];
			++dst.recv;
			dst.rB += header->caplen;

			auto &src = mp[src_ip];
			++src.send;
			src.sB += header->caplen;
		}
	}

	for (const auto &[ip, info] : mp)
		cout << ip << " (total " << info.rB + info.sB << " bytes)\n received " << info.recv << " ip packets ("
		     << info.rB << " bytes)\n "
		     << "sent " << info.send << " ip packets (" << info.sB << " bytes)\n\n";

	for (const auto &[mac, info] : mac_mp)
		cout << mac << " (total " << info.rB + info.sB << " bytes)\n received " << info.recv << " mac packets ("
		     << info.rB << " bytes)\n "
		     << "sent " << info.send << " mac packets (" << info.sB << " bytes)\n\n";


	pcap_close(handle);
}
