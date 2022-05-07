#ifndef _pcap_example_Ip_h_
#define _pcap_example_Ip_h_
#include "pcap_const.h"

Upp::String ip_to_string(const unsigned int ip){
	Upp::String str;
	str << Upp::Format("%02d",(int)(ip >> 24 & 0xFF) ) << "." << Upp::Format("%02d",(int)(ip >> 16 & 0xFF))
	<< "." << Upp::Format("%02d",(int)(ip  >> 8 & 0xFF)) << "." << Upp::Format("%02d",(int)ip & 0xFF);
	return str;
}

struct IpHeader{
	unsigned char ihl_version;
	unsigned char tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned short frag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check;
	unsigned int src_addr;
	unsigned int dest_addr;
	
	Upp::String ToString() const{
		Upp::String str;
		str << "Layer 3 IP: [Source IP: " << ip_to_string(src_addr);
		str << "\tDestination IP: " << ip_to_string(dest_addr)  << "\n";
		str << "\t\tType: " << (int)protocol << "\tID: " << id << "\tLength: " << tot_len << "]";
		return str;
	}
};

IpHeader decode_ip(const unsigned char* header_start){
	IpHeader ip;
	memcpy(&ip, header_start, sizeof(IpHeader));
	ip.tot_len = ntohs(ip.tot_len);
	ip.id = ntohs(ip.id);
	ip.frag_off = ntohs(ip.frag_off);
	ip.check = ntohs(ip.check);
	ip.src_addr = ntohl(ip.src_addr);
	ip.dest_addr = ntohl(ip.dest_addr);
	LOG(ip);
	return ip;
}

#endif
