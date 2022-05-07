#ifndef _pcap_example_Tcp_h_
#define _pcap_example_Tcp_h_
#include "pcap_const.h"

enum TCP_FLAG : unsigned char{
	FIN = 0x1,
	SYN = 0x2,
	RST = 0x4,
	PUSH = 0x8,
	ACK = 0x10,
	URG = 0x20
};

struct TcpHeader{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int sequence_number;
	unsigned int acknowledgment_number;
	unsigned char reserved:4;
	unsigned char data_offset:4;
	TCP_FLAG flags;
	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
	
	Upp::String ToString() const{
		Upp::String str;
		str << "Layer 4 TCP: [Source port: " << src_port << "\tDestination port: " << dst_port << "\n";
		str << "\t\tSeq #: " << sequence_number << "\tAck #: " << acknowledgment_number << "\n";
		str << "\t\tHeader size: " << 4 * data_offset << "\tFlags: ";
		if(flags & TCP_FLAG::FIN)
			str << "FIN,";
		if(flags & TCP_FLAG::SYN)
			str << "SYN,";
		if(flags & TCP_FLAG::RST)
			str << "RST,";
		if(flags & TCP_FLAG::PUSH)
			str << "PUSH,";
		if(flags & TCP_FLAG::ACK)
			str << "ACK,";
		if(flags & TCP_FLAG::URG)
			str << "URG";
		str << "]";
		return str;
	}
};

TcpHeader decode_tcp(const unsigned char* header_start){
	TcpHeader tcp;
	memcpy(&tcp, header_start, sizeof(TcpHeader));
	tcp.src_port = ntohs(tcp.src_port);
	tcp.dst_port = ntohs(tcp.dst_port);
	tcp.sequence_number = ntohl(tcp.sequence_number);
	tcp.acknowledgment_number = ntohl(tcp.acknowledgment_number);
	tcp.window = ntohs(tcp.window);
	tcp.checksum = ntohs(tcp.checksum);
	tcp.urgent_pointer = ntohs(tcp.urgent_pointer);
	
	LOG(tcp);
	return tcp;
}

#endif
