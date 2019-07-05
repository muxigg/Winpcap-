//ʱ�䣺2019.7.4
//���ߣ�PancrasLiu
//��������������WinPcapץ��
#include<iostream>
#include<pcap.h>
#include"ipudp.h"
using namespace std;

#define PACA_ERRBUF_SIZE 256
#define IPTOSBUFFERS    12

char* iptos(u_long in);
void Outputaddr(pcap_addr_t* dev_addr);
void Find_mydevices(pcap_if_t* (&allDevs), pcap_if_t* (&dev), char* errbuf, int i);
void Catch_netmessg(pcap_if_t* allDevs, pcap_if_t* dev, char* errbuf);
int Devnum(pcap_if_t* allDevs, pcap_if_t* (&dev), int k);

int main()
{
	//�����ʼ��������Ұָ��
	pcap_if_t* allDevs = nullptr;   //���������豸��Ϣ
	pcap_if_t* dev = nullptr;    //�����豸��Ϣ
	char errbuf[PACA_ERRBUF_SIZE];   //���������Ϣ
	int i = 1;  //�豸��
	int k;
	Find_mydevices(allDevs, dev, errbuf, i);
	cout << "ѡ��һ���豸��ץ��(1-5):";
	cin >> k;
	//�ҵ��豸
	system("cls");
	Devnum(allDevs, dev, k);
	Catch_netmessg(allDevs, dev, errbuf);
	return 0;
}

//���������͵�IP��ַת�����ַ������͵� 
char* iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;
	p = (u_char*)& in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

//��������豸�ĵ�ַ��Ϣ
void Outputaddr(pcap_addr_t* dev_addr)
{
	if (dev_addr->addr)
		cout << "IPv4��ַ��" << iptos(((sockaddr_in*)dev_addr->addr)->sin_addr.s_addr) << endl;
	if (dev_addr->netmask)
		cout << "�������룺" << iptos(((sockaddr_in*)dev_addr->netmask)->sin_addr.s_addr) << endl;
	if (dev_addr->broadaddr)
		cout << "�㲥��ַ��" << iptos(((sockaddr_in*)dev_addr->broadaddr)->sin_addr.s_addr) << endl;
	if (dev_addr->dstaddr)
		cout << "Ŀ�ĵ�ַ��" << iptos(((sockaddr_in*)dev_addr->dstaddr)->sin_addr.s_addr) << endl;
}

//��ñ�����������ӿ���Ϣ
void Find_mydevices(pcap_if_t* (&allDevs), pcap_if_t* (&dev), char* errbuf, int i)
{
	pcap_addr_t* dev_addr = nullptr;    //���������豸��ַ��Ϣ��ָ��
	if (pcap_findalldevs_ex(const_cast <char*>(PCAP_SRC_IF_STRING), NULL, &allDevs, errbuf) == -1)
		cout << "��ȡ�豸����ӿ���Ϣʧ�ܣ�";
	else
		for (dev = allDevs, i = 1; dev != nullptr; dev = dev->next, ++i)
		{
			cout << i << "-------" << endl;
			cout << "�豸���ƣ�" << dev->name << endl;
			cout << "�豸������Ϣ��" << dev->description << endl;
			//cout << "�豸���ص�ַ��" << dev->addresses << endl;
			dev_addr = dev->addresses;
			Outputaddr(dev_addr);   //���������Ϣ
			cout << endl;
		}
}

//ץ������
void Catch_netmessg(pcap_if_t* allDevs, pcap_if_t* dev, char* errbuf)
{
	pcap_t* handler;   //���ڱ���pcap_open()�ķ���ֵ
	pcap_pkthdr* pkt_header;   //����ץ���İ�������
	const u_char* pkt_data;   //���������ݰ���Ϣ
	int rec; //����pcap_next_ex()�ķ���ֵ
	ip_header* ih;   //ipͷ����Ϣ
	handler = pcap_open(dev->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 3000, nullptr, errbuf);
	if (handler == nullptr)
	{
		cout << "ץ��ʧ�ܣ�" << endl;
		pcap_freealldevs(allDevs);
	}
	else
	{
		while ((rec = pcap_next_ex(handler, &pkt_header, &pkt_data)) >= 0)
		{
			if (rec == 0)
			{
				cout << "��ʱ����������Ч�ԣ�" << endl;
				continue;
			}
			else
			{
				cout << "���ݰ�������(��λms)��" << pkt_header->ts.tv_usec << endl;
				cout << "���ݰ����ȣ�" << pkt_header->len << endl;
				ih = (ip_header*)(pkt_data + 14);  //���ip���ݰ���λ��  14=Ŀ��mac��ַ+Դmac��ַ+��һ��Э������
				cout << "Դ��ַ��" << (int)ih->saddr.byte1 << '.' << (int)ih->saddr.byte2 << '.' << (int)ih->saddr.byte3 << '.' << (int)ih->saddr.byte4 << endl;
				cout << "Ŀ�ĵ�ַ��" << (int)ih->daddr.byte1 << '.' << (int)ih->daddr.byte2 << '.' << (int)ih->daddr.byte3 << '.' << (int)ih->daddr.byte4 << endl;
				cout << "---------------------------------------------" << endl;
			}
		}
	}
}

//�ҵ���Ӧ�����豸
int Devnum(pcap_if_t* allDevs, pcap_if_t* (&dev), int k)
{
	int j;
	for (dev = allDevs, j = 1; j <= 5; dev = dev->next, ++j)
	{
		if (k == j)
			break;
	}
	if (j > 5)
	{
		cout << "�������";
		pcap_freealldevs(allDevs);
		return 0;
	}
}
