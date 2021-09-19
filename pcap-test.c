#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "my_lib.h"

#define ADD16(a, b) (a << 8) + b
#define ADD32(a, b, c, d) (a << 24) + (b << 16) + (c << 8) + d


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

Header header;


bool parse_param(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void parse_packet(const u_char* packet) {
	parse_ethernet(packet);
	parse_ip(&packet[14]);
	parse_tcp(&packet[14 + header.ipv4.hl * 4]);
	// 출력
	// ip의 protocol에서 tcp이면 출력
	// TCP는 0x6
	if(header.ipv4.p != 0x6) {
		printf("this is not tcp\n");
		return;
	}
	printf("ehternet src mac     ");
	for(int i = 0; i < 6; i++) {
		printf("%X", header.ethernet.shost[i]);
		if(i!=5)printf(":");
	}
	printf("\nehternet src mac     ");
	for(int i = 0; i < 6; i++) {
		printf("%X", header.ethernet.dhost[i]);
		if(i!=5)printf(":");
	}

	printf("\nip header src ip     ");
	for(int i = 0; i < 4; i++) {
		printf("%d", header.ipv4.src.ip[i]);
		if(i!=3) printf(".");
	}

	printf("\nip header dst ip     ");
	for(int i = 0; i < 4; i++) {
		printf("%d", header.ipv4.dst.ip[i]);
		if(i!=3) printf(".");
	}

	printf("\ntcp header src port  ");
	printf("%d", header.tcp.sport);
	printf("\ntcp header dst port  ");
	printf("%d", header.tcp.dport);

	// 길이 체크
	int payload_len = header.ipv4.len - (header.ipv4.hl + header.tcp.off) * 4;
	if(payload_len > 0) {
		printf("\npayload              ");
		for(int i = 0; i < 8; i++) {
			printf("%X", packet[i + 14 + (header.ipv4.hl + header.tcp.off) * 4]);
		}
	}
}

void parse_ethernet(const u_char* packet) {
	for(int i = 0; i < 6; i++) {
		header.ethernet.dhost[i] = packet[i];
		header.ethernet.shost[i] = packet[i + 6];
	}
	header.ethernet.type = ADD16(packet[12], packet[13]);
}

void parse_ip(const u_char* packet) {
	header.ipv4.v = packet[0] >> 4;
	header.ipv4.hl = packet[0] &0xf;
	header.ipv4.tos = packet[1];
	header.ipv4.len = ADD16(packet[2], packet[3]);
	header.ipv4.id = ADD16(packet[4], packet[5]);
	header.ipv4.off = ADD16(packet[6], packet[7]);
	header.ipv4.ttl = packet[8];
	header.ipv4.p = packet[9];
	header.ipv4.sum = ADD16(packet[10], packet[11]);
	for(int i = 0; i < 4; i++) {
		header.ipv4.src.ip[i] = packet[12+i];
		header.ipv4.dst.ip[i] = packet[16+i];
	}
}

void parse_tcp(const u_char* packet) {
	header.tcp.sport = ADD16(packet[0], packet[1]);
	header.tcp.dport = ADD16(packet[2], packet[3]);
	header.tcp.seq = ADD32(packet[4], packet[5], packet[6], packet[7]);
	header.tcp.ack = ADD32(packet[8], packet[9], packet[10], packet[11]);
	header.tcp.off = packet[12] >> 4;
	header.tcp.x2 = packet[12] & 0xf;
	header.tcp.flags = packet[13];
	header.tcp.win = ADD16(packet[14], packet[15]);
	header.tcp.sum = ADD16(packet[16], packet[17]);
	header.tcp.urp = ADD16(packet[18], packet[19]);
}

int main(int argc, char* argv[]) {
	if (!parse_param(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* pkheader;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &pkheader, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("\n%u bytes captured\n", pkheader->caplen);
		parse_packet(packet);
		printf("\n");

		


	}

	pcap_close(pcap);
}


