//时间：2019.7.4
//作者：PancrasLiu
//功能描述：利用WinPcap抓包
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
	//必须初始化，否则野指针
	pcap_if_t* allDevs = nullptr;   //保存所有设备信息
	pcap_if_t* dev = nullptr;    //单个设备信息
	char errbuf[PACA_ERRBUF_SIZE];   //保存出错信息
	int i = 1;  //设备号
	int k;
	Find_mydevices(allDevs, dev, errbuf, i);
	cout << "选择一个设备来抓包(1-5):";
	cin >> k;
	//找到设备
	system("cls");
	Devnum(allDevs, dev, k);
	Catch_netmessg(allDevs, dev, errbuf);
	return 0;
}

//将数字类型的IP地址转换成字符串类型的 
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

//输出网卡设备的地址信息
void Outputaddr(pcap_addr_t* dev_addr)
{
	if (dev_addr->addr)
		cout << "IPv4地址：" << iptos(((sockaddr_in*)dev_addr->addr)->sin_addr.s_addr) << endl;
	if (dev_addr->netmask)
		cout << "子网掩码：" << iptos(((sockaddr_in*)dev_addr->netmask)->sin_addr.s_addr) << endl;
	if (dev_addr->broadaddr)
		cout << "广播地址：" << iptos(((sockaddr_in*)dev_addr->broadaddr)->sin_addr.s_addr) << endl;
	if (dev_addr->dstaddr)
		cout << "目的地址：" << iptos(((sockaddr_in*)dev_addr->dstaddr)->sin_addr.s_addr) << endl;
}

//获得本地所有网络接口信息
void Find_mydevices(pcap_if_t* (&allDevs), pcap_if_t* (&dev), char* errbuf, int i)
{
	pcap_addr_t* dev_addr = nullptr;    //保存网卡设备地址信息的指针
	if (pcap_findalldevs_ex(const_cast <char*>(PCAP_SRC_IF_STRING), NULL, &allDevs, errbuf) == -1)
		cout << "获取设备网络接口信息失败！";
	else
		for (dev = allDevs, i = 1; dev != nullptr; dev = dev->next, ++i)
		{
			cout << i << "-------" << endl;
			cout << "设备名称：" << dev->name << endl;
			cout << "设备描述信息：" << dev->description << endl;
			//cout << "设备环回地址：" << dev->addresses << endl;
			dev_addr = dev->addresses;
			Outputaddr(dev_addr);   //输出其他信息
			cout << endl;
		}
}

//抓包函数
void Catch_netmessg(pcap_if_t* allDevs, pcap_if_t* dev, char* errbuf)
{
	pcap_t* handler;   //用于保存pcap_open()的返回值
	pcap_pkthdr* pkt_header;   //保存抓到的包的描述
	const u_char* pkt_data;   //完整的数据包信息
	int rec; //保存pcap_next_ex()的返回值
	ip_header* ih;   //ip头部信息
	handler = pcap_open(dev->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 3000, nullptr, errbuf);
	if (handler == nullptr)
	{
		cout << "抓包失败！" << endl;
		pcap_freealldevs(allDevs);
	}
	else
	{
		while ((rec = pcap_next_ex(handler, &pkt_header, &pkt_data)) >= 0)
		{
			if (rec == 0)
			{
				cout << "超时，包不具有效性！" << endl;
				continue;
			}
			else
			{
				cout << "数据包的描述(单位ms)：" << pkt_header->ts.tv_usec << endl;
				cout << "数据包长度：" << pkt_header->len << endl;
				ih = (ip_header*)(pkt_data + 14);  //获得ip数据包的位置  14=目的mac地址+源mac地址+上一层协议类型
				cout << "源地址：" << (int)ih->saddr.byte1 << '.' << (int)ih->saddr.byte2 << '.' << (int)ih->saddr.byte3 << '.' << (int)ih->saddr.byte4 << endl;
				cout << "目的地址：" << (int)ih->daddr.byte1 << '.' << (int)ih->daddr.byte2 << '.' << (int)ih->daddr.byte3 << '.' << (int)ih->daddr.byte4 << endl;
				cout << "---------------------------------------------" << endl;
			}
		}
	}
}

//找到对应网卡设备
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
		cout << "输入错误！";
		pcap_freealldevs(allDevs);
		return 0;
	}
}
