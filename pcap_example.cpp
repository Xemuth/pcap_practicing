#include <Core/Core.h>
#include <pcap/pcap.h>
#include "pcap_const.h"
#include "Ethernet.h"
#include "Ip.h"
#include "Tcp.h"

using namespace Upp;

static char errbuff[PCAP_ERRBUF_SIZE + 1];

void manage_error(bool test, const Upp::String& str){
	if(test){LOG(str); Exit(1);}
}

void pcap_fatal(const char* failed_in, const char* errbuf){
	printf("Fatal error in %s: %s\n", failed_in, errbuf);
	Exit(1);
}

void pcap_handler_callback(u_char *args, const struct pcap_pkthdr *h, const u_char *bytes){
	decode_ethernet(bytes);
	decode_ip(bytes + sizeof(EthHeader));
	decode_tcp(bytes + sizeof(EthHeader) + sizeof(IpHeader));
	int remaining_size = (sizeof(EthHeader) + sizeof(IpHeader) + sizeof(TcpHeader) - h->len);
	LOG(Upp::Format("%d bytes of data:\n", remaining_size));
	dump_buffer(bytes + sizeof(EthHeader) + sizeof(IpHeader) + sizeof(TcpHeader), remaining_size, 16);
}

CONSOLE_APP_MAIN
{
	StdLogSetup(LOG_COUT | LOG_FILE);
	
	int flag_device = PCAP_IF_WIRELESS;
	pcap_t* handle;
	pcap_findalldevs_janitor itf;
	
	pcap_if_t* device = find_device(itf, flag_device);
	manage_error(!device, Format("No device found for flags %s", flag_to_str(flag_device)));
	
	handle = pcap_open_live(device->name, 4096, 1, 0, errbuff);
	manage_error(!handle, Format("pcap_open_live failled may you cant use %s with your privilege level", device->name));
	
	pcap_loop(handle, 10, pcap_handler_callback, nullptr);
	pcap_close(handle);
}
