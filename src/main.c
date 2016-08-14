/* File: main.c
 * ------------
 * 校园网802.1X客户端命令行
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <pcap.h>

#include <time.h>

#include <net/if.h>
#include <linux/if_ether.h>

#include <sys/types.h>
#include <sys/select.h>  
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <linux/if_packet.h>
	struct sockaddr_ll auth_8021x_addr;
	struct sockaddr_ll sa_ll_recv;
/* File: auth.c
 * ------------
 * 注：核心函数为Authentication()，由该函数执行801.1X认证
 */

#include "tracelog.h"
#include "info.h"

#define SERVER_PORT  0xf000 // 服务器端口
#define LOGOFF  0 // 下线标志位
#define YOUNG_CLIENT  1 // 翼起来客户端标志位
#define DRCOM_CLIENT  2 // Drcom客户端标志位


/* 静态变量*/
static uint8_t Packet[1024]={0};
static int success_8021x=0;
static uint8_t EthHeader[14] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8e};
static size_t packetlen = 0;
static int clientHandler = 0;
static int auth_8021x_sock = 0;
static int auth_udp_sock = 0;
/* 静态变量*/

typedef enum {REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_Code;
typedef enum {IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILABLE=20, ALLOCATED=7} EAP_Type;
typedef uint8_t EAP_ID;

// 子函数声明
void auth_8021x_Handler(uint8_t recv_data[]);
size_t appendSuccessPkt(uint8_t header[]);
size_t appendRequestIdentity(const uint8_t request[]);
size_t appendRequestMD5(const uint8_t request[]);
void appendLogoffPkt();

int checkWanStatus(int sock)
{
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));  
	unsigned char devicename[16] = {0};
	GetDeviceName(devicename);
	strcpy(ifr.ifr_name,devicename);

	int	err = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if( err < 0)
	{
		LogWrite(ERROR,"%s","ioctl get if_flag error.");
		perror("ioctl get if_flag error");
		return 0;
	}
	if(ifr.ifr_ifru.ifru_flags & IFF_RUNNING )
	{
		LogWrite(INF,"%s","WAN had linked up.");
	}
	else
	{
		LogWrite(ERROR,"%s","WAN had linked down. Please do check it.");
		perror("WAN had linked down. Please do check it.");
		return 0;
	}

	//获取接口索引
	if( ioctl(sock,SIOCGIFINDEX,&ifr) < 0)
	{
		LogWrite(ERROR,"%s","Get WAN index error.");
		perror("Get WAN index error.");	
		return 0;
	}
	auth_8021x_addr.sll_ifindex = ifr.ifr_ifindex;
	auth_8021x_addr.sll_family = PF_PACKET;
	auth_8021x_addr.sll_protocol  = htons(ETH_P_ALL);
	auth_8021x_addr.sll_pkttype = PACKET_HOST | PACKET_BROADCAST  | PACKET_MULTICAST | PACKET_OTHERHOST | PACKET_OUTGOING;
	return 1;
}

int auth_UDP_Sender(struct sockaddr_in serv_addr, unsigned char *send_data, int send_data_len)
{
	int ret = 0;
	ret = sendto(auth_udp_sock, send_data, send_data_len, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (ret != send_data_len) 
	{ 
		//ret不等于send_data长度报错
		LogWrite(ERROR,"%s","auth_UDP_Sender error.");
		perror("auth_UDP_Sender error");
		return 0;
	}
	return 1;
}

int auth_UDP_Receiver(char *recv_data, int recv_len)
{
	if(recv(auth_udp_sock, recv_data, ETH_FRAME_LEN, 0) < 0)
	{ 
		//小于0代表没收到
		return 0;
	}
	return 1;
}

int auth_8021x_Sender()
{
	if (sendto(auth_8021x_sock, Packet, packetlen, 0, (struct sockaddr *)&auth_8021x_addr,  sizeof(auth_8021x_addr)) < 0) 
	{ 
		//ret不等于send_data长度报错
		LogWrite(ERROR,"%s","auth_8021x_Sender failed.");
		perror("auth_8021x_Sender failed.");
		return 0;
	}
	return 1;
}

int auth_8021x_Receiver(char *recv_data)
{
	if(recvfrom(auth_8021x_sock, recv_data, ETH_FRAME_LEN, 0,NULL,NULL) < 0)
	{ 
		//ret小于0代表没收到
		return 0;
	}
	return 1;
}

size_t udp_LOGIN_Setter(uint8_t *send_data,uint8_t *recv_data)
{
	uint8_t buf[] = 
	{0x07,0x00,0x10,0x00,0x02,0x00
	,0x00,0x00,0x33,0x33,0x44,0x56,0x66,0x77,0x66,0x77,0xa8,0xac,0x00,0x00,0x4f,0xe4
	,0x16,0xc1,0x00,0x00,0x00,0x00,0xdc,0x02,0x00,0x00};
	int data_len = sizeof(buf);
	memcpy(send_data,buf,data_len);
	return data_len;
}

size_t udp_ALIVE_Setter(uint8_t *send_data,uint8_t *recv_data)
{
	uint8_t buf[] = 
	{0x07,0x01,0x10,0x00,0x06,0x00
	,0x2c,0x40,0x29,0xe6,0x0d,0x01,0xd3,0x42,0x0d,0xe1,0xa8,0xac,0x00,0x00,0x4f,0xe4
	,0x16,0xc1,0x00,0x00,0x00,0x00,0xdc,0x02,0x00,0x00,0x0c,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x39,0x08,0x00,0x00,0x3b,0x3b,0xb7,0x31,0x00,0x00
	,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
	int data_len = sizeof(buf);
	memcpy(send_data,buf,data_len);
	return data_len;
}

size_t udp_INFO_Setter(uint8_t *send_data,uint8_t *recv_data)
{
	uint8_t buf[] = 
	{0x07,0x01,0x30,0x00,0x04,0x0c
	,0x20,0x00,0x6e,0x2d,0x45,0x84,0x00,0x00,0x00,0x00,0x44,0x39,0xd8,0xed,0xac,0x31
	,0x4b,0x07,0x64,0x98,0xf4,0x48,0xd0,0x0f,0x04,0xd2,0xb0,0x82,0x00,0x60,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	int data_len = sizeof(buf);
	memcpy(send_data,buf,data_len);
	return data_len;
}

size_t udp_MISC_2800_02_Setter(uint8_t *send_data,uint8_t *recv_data)
{
	uint8_t buf[] = 
	{0x07,0x01,0x28,0x00,0x0b,0x02
	,0xdc,0x02,0x03,0x27,0x00,0x00,0x00,0x00,0x00,0x00,0xd7,0xe5,0x0d,0x01,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00};
	int data_len = sizeof(buf);
	memcpy(send_data,buf,data_len);
	return data_len;
}

size_t udp_MISC_2800_04_Setter(uint8_t *send_data,uint8_t *recv_data)
{
	uint8_t buf[] = 
	{0x07,0x02,0x28,0x00,0x0b,0x04
	,0xdc,0x02,0x06,0x27,0x00,0x00,0x00,0x00,0x00,0x00,0xd8,0xe5,0x0d,0x01,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00};
	int data_len = sizeof(buf);
	memcpy(send_data,buf,data_len);
	return data_len;
}

size_t appendSuccessPkt(uint8_t header[])
{
	uint8_t buf[] = 
	{0x08,0x9e,0x01,0x28,0xc9,0x55,0x58,0x66,0xba,0xe8,0x98,0xae,0x88,0x8e,0x01,0x00
	,0x00,0x04,0x03,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x62,0x9e,0xd9,0xde};
	int data_len = sizeof(buf);
	memcpy(Packet,buf,data_len);
	memcpy(Packet,EthHeader,14);
	return data_len;
}

size_t appendRequestIdentity(const uint8_t request[])
{
	uint8_t buf[] = 
	{0x00,0x0c,0x29,0xe0,0xef,0x27,0x58,0x66,0xba,0xe8,0x98,0xae,0x88,0x8e,0x01,0x00
	,0x00,0x05,0x01,0x01,0x00,0x05,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xee,0x01,0xde,0x2b};
	int data_len = sizeof(buf);
	memcpy(Packet,buf,data_len);
	memcpy(Packet,EthHeader,14);
	return data_len;
}

size_t appendRequestMD5(const uint8_t request[])
{
	uint8_t buf[] = 
	{0x00,0x0c,0x29,0xe0,0xef,0x27,0x58,0x66,0xba,0xe8,0x98,0xae,0x88,0x8e,0x01,0x00
	,0x00,0x1a,0x01,0x00,0x00,0x1a,0x04,0x10,0xd1,0x82,0x6c,0x79,0xca,0x26,0xd2,0x82
	,0xca,0x26,0xd2,0x82,0x00,0x00,0x00,0x00,0x10,0x80,0x00,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x23,0x3d,0x5f,0x0c};
	int data_len = sizeof(buf);
	memcpy(Packet,buf,data_len);
	memcpy(Packet,EthHeader,14);
	return data_len;
}

void sendFailPkt()
{
	uint8_t buf[] = 
	{0x08,0x9e,0x01,0x28,0xc9,0x55,0x58,0x66,0xba,0xe8,0x98,0xae,0x88,0x8e,0x01,0x00
	,0x00,0x07,0x04,0x02,0x00,0x07,0x08,0x01,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x4d,0xd7,0x84};
	int data_len = sizeof(buf);
	memcpy(Packet,buf,data_len);
	memcpy(Packet,EthHeader,14);
	auth_8021x_Sender();
	success_8021x = 0;
}

int set_unblock(int fd, int flags)
{
	int val;

	if((val = fcntl(fd, F_GETFL, 0)) < 0) 
	{
		LogWrite(ERROR,"%s", "fcntl F_GETFL error.");
		perror("fcntl F_GETFL error.");
		return EXIT_FAILURE;
	}
	val |= flags;

	if(fcntl(fd, F_SETFL, val) < 0) 
	{
		LogWrite(ERROR,"%s", "fcntl F_SETFL error");
		perror("fcntl F_SETFL error.");
		return EXIT_FAILURE;
	}
	return 0;
}

void initAuthenticationInfo()
{
	uint8_t MAC[6]= {0};
	GetMacFromDevice(MAC);

	memcpy(EthHeader, MAC, 6);
	memcpy(EthHeader+6, MAC, 6);
	EthHeader[12] = 0x88;
	EthHeader[13] = 0x8e;
	
	// 打印网络信息到前台显示	
	uint8_t ip[4]= {0};
	GetWanIpFromDevice(ip);
	LogWrite(INF,"%s %d.%d.%d.%d","IP :",ip[0],ip[1],ip[2],ip[3]);
	GetWanNetMaskFromDevice(ip);
	LogWrite(INF,"%s %d.%d.%d.%d","Netmask :",ip[0],ip[1],ip[2],ip[3]);
	GetWanGatewayFromDevice(ip);
	LogWrite(INF,"%s %d.%d.%d.%d","Gateway :",ip[0],ip[1],ip[2],ip[3]);
	GetWanDnsFromDevice(ip);
	LogWrite(INF,"%s %d.%d.%d.%d","Dns :",ip[0],ip[1],ip[2],ip[3]);
	LogWrite(INF,"%s %x:%x:%x:%x:%x:%x","MAC :",MAC[0],MAC[1],MAC[2],MAC[3],MAC[4],MAC[5]);
}

int main(int argc, char *argv[])
{	
	int on = 1;
	InitDeviceName();
	clientHandler = DRCOM_CLIENT;
	auth_8021x_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	fd_set fdR;
	
	if((setsockopt(auth_8021x_sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)  
	{  
		perror("setsockopt failed");  
		exit(EXIT_FAILURE);  
	}  
	
	//非阻塞(必须在bind前)
	if(set_unblock(auth_8021x_sock, O_NONBLOCK)<0)
	{
		LogWrite(ERROR,"%s","Set unblock failed.");
		perror("Set unblock failed!");
	}
	
	int result = checkWanStatus(auth_8021x_sock);
	if(result == 0)
	{
		LogWrite(ERROR,"%s","Client exit.");
		perror("Client Exit!");
		close(auth_8021x_sock);
		exit(EXIT_FAILURE);
	}
	initAuthenticationInfo();

	uint8_t recv_8021x_buf[ETH_FRAME_LEN] = {0};
	if(clientHandler==LOGOFF)
	{
		sendFailPkt();
		return 0;
	}

		LogWrite(INF,"%s","Drcom Mode.");

		unsigned char send_data[ETH_FRAME_LEN] = {0};
		int send_data_len = 0;
		char recv_data[ETH_FRAME_LEN] = {0};
		int recv_data_len = 0;
		struct sockaddr_in serv_addr,local_addr;
		int tryUdpRecvTimes = 0;

		//静态全局变量auth_udp_sock
		auth_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (auth_udp_sock < 0) 
		{
			//auth_udp_sock<0即错误
			LogWrite(ERROR,"%s","Create auth_udp_sock failed.");
			perror("Create auth_udp_sock failed.");
			exit(EXIT_FAILURE);
		}
		printf("auth_8021x_sock = %d  auth_udp_sock =%d",auth_8021x_sock,auth_udp_sock);
		// 非阻塞(必须在bind前)
		if(set_unblock(auth_udp_sock, O_NONBLOCK)<0)
		{
			LogWrite(ERROR,"%s","set unblock failed.");
			perror("set unblock failed.");
		}
		bzero(&serv_addr,sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(SERVER_PORT);
		bzero(&local_addr,sizeof(local_addr));
		local_addr.sin_family = AF_INET;
		local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		local_addr.sin_port = htons(SERVER_PORT);

		if((setsockopt(auth_udp_sock,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)  
		{  
			perror("setsockopt failed");  
			exit(EXIT_FAILURE);  
		}  
		
		bind(auth_udp_sock,(struct sockaddr *)&(local_addr),sizeof(struct sockaddr_in));


		send_data_len = Drcom_LOGIN_TYPE_Setter(send_data,recv_data);

		while(1)
		{
			FD_ZERO(&fdR); 
			FD_SET(auth_8021x_sock, &fdR); 
			FD_SET(auth_udp_sock, &fdR); 
			
			switch (select(auth_8021x_sock + auth_udp_sock, &fdR, NULL, NULL, NULL)) 
			{ 
				case -1: 
					LogWrite(ERROR,"%s","select socket failed.");
					perror("select socket failed.");
				break;
				case 0: 
				break;
				default: 
				if (FD_ISSET(auth_8021x_sock,&fdR)) 
				{ 
					if(auth_8021x_Receiver(recv_8021x_buf))
					{
																	
						// 过滤掉非0x888e的报文
						if(recv_8021x_buf[12]==0x88 && recv_8021x_buf[13]==0x8e)
						{
							perror("debug");
							auth_8021x_Handler(recv_8021x_buf);
						}
					}
				} 
				if (FD_ISSET(auth_udp_sock,&fdR)) 
				{
					perror("debug.haha");
					// 如果8021x协议认证成功并且心跳时间间隔大于设定值
					if(success_8021x)
					{
						perror("success_8021x");

						if(auth_UDP_Receiver(recv_data, recv_data_len))
						{
																		perror("debug1");
							// 过滤掉非drcom的报文
							if(recv_data[0]==0x07 || recv_data[0]==0xff)
							{
								send_data_len = Drcom_UDP_Handler(send_data, recv_data);
								auth_UDP_Sender(serv_addr, send_data, send_data_len);
							}
						}
					}
				}
			} 

			
		}
		close(auth_udp_sock);
	
	sendFailPkt(auth_8021x_sock);
	close(auth_8021x_sock);
	return 1;
}

typedef enum {MISC_0800=0x08, ALIVE_FILE=0x10, MISC_3000=0x30, MISC_2800=0x28} DRCOM_Type;
typedef enum {ALIVE_TYPE=0x00, FILE_TYPE=0x01} DRCOM_ALIVE_FILE_Type;
typedef enum {ALIVE_LOGIN_TYPE=0x02, ALIVE_HEARTBEAT_TYPE=0x06} DRCOM_ALIVE_Type;
typedef enum {MISC_2800_01_TYPE=0x01, MISC_2800_02_TYPE=0x02, MISC_2800_03_TYPE=0x03, MISC_2800_04_TYPE=0x04} DRCOM_MISC_2800_Type;
int Drcom_UDP_Handler(unsigned char *send_data, char *recv_data)
{
	int data_len = 0;
	// 根据收到的recv_data，填充相应的send_data
	if (recv_data[0] == 0xff)
	{
			LogWrite(INF,"%s%d%s%d","[HEARTBEAT] UDP_Server: Request (type:",recv_data[2],")!Response ALIVE data len=",data_len);
			data_len = udp_ALIVE_Setter(send_data,recv_data);
	}
	else if (recv_data[0] == 0x07)
	{
		switch (recv_data[4])
		{
			case 0x01:// MISC_0800
				LogWrite(INF,"%s%d%s%d","[LOGIN] UDP_Client: Request (type:",recv_data[2],")!Response LOGIN data len=",data_len);
				data_len = udp_LOGIN_Setter(send_data,recv_data);
			break;
			case 0x03:// INFO
				LogWrite(INF,"%s%d%s%d","[CLIENT INFO] UDP_Client: Request (type:",recv_data[2],")!Response INFO data len=",data_len);
				data_len = udp_INFO_Setter(send_data,recv_data);
			break;
			case 0x0b:
				switch (recv_data[5])
				{
					case 0x01: //MISC_2800_01_TYPE
						LogWrite(INF,"%s%d%s%d","[MISC_2800_01] UDP_Server: Request (type:",recv_data[2],")!Response MISC_2800_02 data len=",data_len);
						data_len = udp_MISC_2800_02_Setter(send_data,recv_data);
					break;
					case 0x03: //MISC_2800_03_TYPE
						LogWrite(INF,"%s%d%s%d","[MISC_2800_03] UDP_Server: Request (type:",recv_data[2],")!Response MISC_2800_04 data len=",data_len);
						data_len = udp_MISC_2800_04_Setter(send_data,recv_data);
					break;
				}
			break;
		}
	}
	return data_len;
}

void auth_8021x_Handler(uint8_t recv_data[])
{
	// 收到Start，回复ResponseID包
	if ((EAP_Code)recv_data[15] == 0x01)
	{
		LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Client: Start.");
		packetlen = appendRequestIdentity(recv_data);
		LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Server: Request Identity!");
	}
	// 收到LOGOFF，回复FAIL包
	else if ((EAP_Code)recv_data[15] == 0x02)
	{	
		sendFailPkt(auth_8021x_sock);
		return ;
	}
	else if ((EAP_Code)recv_data[15] == 0x00)
	{
		// 如果收到ResponseID，回应RequestMD5
		if ((EAP_Code)recv_data[22] == 0x01)
		{
			LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Client: Response Identity!");
			packetlen = appendRequestMD5(recv_data);
			LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Server: Request MD5!");
		}
		// 如果收到ResponseMD5，回应SUCCESS
		else if ((EAP_Code)recv_data[22] == 0x04)
		{
			LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Client: Response MD5!");
			packetlen = appendSuccessPkt(recv_data);
			LogWrite(INF,"[%d] %s", (EAP_ID)recv_data[19],"Server: SUCCESS!");
			success_8021x = 1;
		}
	}
	// 发送
	LogWrite(INF,"%s%d","send packetlen = ",packetlen);
	auth_8021x_Sender();
	return ;
}
