#ifndef _pcap_example_pcap_const_h_
#define _pcap_example_pcap_const_h_
#include <Core/Core.h>

Upp::String flag_to_str(int flags_to_str);
pcap_if_t* find_device(int flags);
void dump_buffer(const char* buffer, int size, int row_dump_size = 32);
Upp::String buffer_to_string(const unsigned char* buffer, int size);

class pcap_findalldevs_janitor{
	public:
		pcap_findalldevs_janitor() : itf(nullptr){
			int result = pcap_findalldevs(&itf, errbuff);
			if(!itf or result == -1){
				itf = nullptr;
				LOG("No device found, may you should try with sudo privilede");
				Upp::Exit(1);
			}
		}
		
		operator pcap_if_t*(){
			return itf;
		}
		
		~pcap_findalldevs_janitor(){
			if(itf)
				pcap_freealldevs(itf);
		}
		
	private:
		pcap_if_t* itf;
		char errbuff[PCAP_ERRBUF_SIZE + 1];
};


const int pcap_flags[] = {PCAP_IF_LOOPBACK,
						  PCAP_IF_UP,
						  PCAP_IF_RUNNING,
						  PCAP_IF_WIRELESS,
						  PCAP_IF_CONNECTION_STATUS,
						  PCAP_IF_CONNECTION_STATUS_UNKNOWN,
						  PCAP_IF_CONNECTION_STATUS_DISCONNECTED,
						  PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE};

constexpr const int pcap_flags_size = (sizeof(pcap_flags) / sizeof(pcap_flags[0]));

const char* pcap_flags_str[] = {"PCAP_IF_LOOPBACK",
							    "PCAP_IF_UP",
							    "PCAP_IF_RUNNING",
							    "PCAP_IF_WIRELESS",
							    "PCAP_IF_CONNECTION_STATUS",
							    "PCAP_IF_CONNECTION_STATUS_UNKNOWN",
							    "PCAP_IF_CONNECTION_STATUS_DISCONNECTED",
							    "PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE"};


pcap_if_t* find_device(pcap_if_t* itf, int flags){
	pcap_if_t* buffer = itf;
	int e = 0;
	while(buffer){
		LOG(Upp::Format("Device no %d : %s-%s", e + 1, buffer->name, ((buffer->description) ? buffer->description : "No description available")));
		LOG(Upp::Format("\tflags: %s", flag_to_str(buffer->flags)));
		if(buffer->flags & flags)
			return buffer;
		buffer = buffer->next;
		e++;
	}
	return nullptr;
}

Upp::String flag_to_str(int flags_to_str){
	Upp::String flags;
	for(int q = 0; q < pcap_flags_size; q++){
		if(flags_to_str & pcap_flags[q]){
			const char* ptr =  pcap_flags_str[q];
			flags << (flags.GetCount()?", ": "") << ptr;
		}
	}
	return flags;
}

void dump_buffer(const unsigned char* buffer, int size, int row_dump_size){
	static const char* hexa = "0123456789ABCDEF";
	ASSERT_(row_dump_size <= 32, "Invalide size for dump");
	char buffer_row[132];
	buffer_row[ row_dump_size * 3] = '|';
	buffer_row[ row_dump_size * 3 + 1] = ' ';
	int loop_count = (size / row_dump_size) + (((size % row_dump_size) > 0)? 1 : 0);
	const unsigned char* position = buffer;
	for(int i = 0; i < loop_count; i++){
		for(int e = 0; e < row_dump_size; e++){
			int pos_letter = 3 * row_dump_size + 3 + e + 1;
			int pos_hexa = e * 3;
			buffer_row[pos_hexa] = hexa[position[0] & 0xF0 >> 4];
			buffer_row[pos_hexa + 1] = hexa[position[0] & 0x0F];
			buffer_row[pos_hexa + 2] = ' ';
			if( position[0] >= 32 and position[0] < 127){
				buffer_row[pos_letter] = position[0];
			}else{
				buffer_row[pos_letter] = '.';
			}
			position++;
		}
		LOG(buffer_row);
	}
}

Upp::String buffer_to_string(const unsigned char* buffer, int size){
	static const char* hexa = "0123456789ABCDEF";
	Upp::String str;
	for(int i = 0; i < size; i++){
		str << hexa[buffer[i] & 0xF0 >> 4] << hexa[buffer[i] & 0x0F] << (i < size ? " ": "");
	}
	return str;
}


#endif
