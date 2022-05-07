#ifndef _pcap_example_Ethernet_h_
#define _pcap_example_Ethernet_h_
#include "pcap_const.h"

constexpr int eth_addr_len = 6;
constexpr int eth_header_len = 14;

struct EthHeader{
	unsigned char source_mac[eth_addr_len];
	unsigned char dest_mac[eth_addr_len];
	unsigned short ethernet_packet_type;
	
	Upp::String ToString() const{
		Upp::String str;
		str << "Layer 2 Ethernet: [Source: " << Upp::Format("%02x", source_mac[eth_addr_len - 1]);
		for(int e = eth_addr_len - 2; e >= 0; e--)
			str << Upp::Format(":%02x", source_mac[e]);
		str << "\tDestination: " << Upp::Format("%02x", dest_mac[eth_addr_len - 1]);
		for(int e = eth_addr_len - 2; e >= 0; e--)
			str << Upp::Format(":%02x", dest_mac[e]);
		str << "\tType: " << ethernet_packet_type << "]";
		return str;
	}
};

EthHeader decode_ethernet(const unsigned char* header_start){
	EthHeader eth;
	memcpy(&eth, header_start, sizeof(EthHeader));
	eth.ethernet_packet_type = ntohs(eth.ethernet_packet_type);
	LOG(eth);
	return eth;
}

#endif
