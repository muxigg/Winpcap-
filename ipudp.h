#ifndef __IPUDP__
#define __IPUDP__
#include<pcap.h>


typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_address;

// IPv4 �ײ� 
typedef struct ip_header
{
	u_char  ver_ihl;        // �汾 (4 bits) + �ײ����� (4 bits)
	u_char  tos;            // ��������(Type of service)
	u_short tlen;           // �ܳ�(Total length)
	u_short identification; // ��ʶ(Identification)
	u_short flags_fo;       // ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	u_char  ttl;            // ���ʱ��(Time to live)
	u_char  proto;          // Э��(Protocol)
	u_short crc;            // �ײ�У���(Header checksum)
	ip_address  saddr;      // Դ��ַ(Source address)
	ip_address  daddr;      // Ŀ�ĵ�ַ(Destination address)
	u_int   op_pad;         // ѡ�������(Option + Padding)
} ip_header;

#endif // !__ipudp__

