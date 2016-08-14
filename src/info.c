#include "info.h"

/* ��̬����*/
static uint8_t	udp_server_ip[4] = {0};	// ip address
static uint8_t	ip[4] = {0};	// ip address
static uint8_t	mask[4] = {0};
static uint8_t	gateway[4] = {0};
static uint8_t	dns[4] = {0};
static uint8_t	MAC[6] = {0};
static unsigned char		ipaddr[16] = {0};
static unsigned char		udp_server_ipaddr[16] = {0};
static unsigned char		UserName[32] = {0};
static unsigned char		Password[32] = {0};
static unsigned char		DeviceName[32] = {0};
static unsigned char		HostName[32] = {0};
static unsigned char		Version[64] = {0};
static unsigned char		Hash[64] = {0};
static unsigned char		Debug[8] = {0};
/* ��̬����*/

/* ��̬����*/
const unsigned char GET_WAN_DEV[]="echo eth0"; // ��ȡwan������˿�
const unsigned char GET_WAN_MAC[]="echo 22:22:22:22:22:22"; // ��ȡwan��MAC��ַ
const unsigned char GET_WAN_IP[]="echo 102.0.0.1"; // ��ȡwan��IP��ַ
const unsigned char GET_WAN_NETMASK[]="echo 255.255.255.0"; // ��ȡwan��netmask
const unsigned char GET_WAN_GATEWAY[]="echo 102.0.0.1"; // ��ȡwan�����ص�ַ
const unsigned char GET_DNS[]="echo 202.112.17.33"; // ��ȡDNS��ַ
const unsigned char GET_HOST_NAME[]="echo SCUT"; // ��ȡ��������
const unsigned char GET_UDP_SERVER_IP[]="echo 202.112.17.33"; // ��ȡUDP��֤��������ַ
const unsigned char GET_VERSION[]="echo 4472434f4d00cf072a00332e31332e302d32342d67656e65726963"; // ��ȡ�汾��
const unsigned char GET_HASH[]="echo 915e3d0281c3a0bdec36d7f9c15e7a16b59c12b8"; // ��ȡHASHֵ
const unsigned char GET_DEBUG[]="echo 1"; // DEBUG����
/* ��̬����*/

int trim(char s[])  
{
	int n;
	for(n = strlen(s) - 1; n >= 0; n--)
	{
		if(s[n]!=' ' && s[n]!='\t' && s[n]!='\n' && s[n]!='\r')
		{
			break;
		}
		s[n] = '\0';
	}
	return n;
}

int checkInitForChar(unsigned char *str )
{
	int i =0;
	int result = 0;
	for(i=0;i<strlen(str);i++)
	{
		result += str[i];
	}
	return result;
}

int checkInit( uint8_t info[] ,int infoLen )
{
	int i =0;
	int result = 0;
	for(i=0;i<infoLen;i++)
	{
		result += info[i];
	}
	return result;
}

void hexStrToByte(unsigned char* source,unsigned  char* dest, int sourceLen)  
{
	short i;
	unsigned char highByte, lowByte;

	for (i = 0; i < sourceLen; i += 2)
	{
		highByte = toupper(source[i]);
		lowByte= toupper(source[i + 1]);

		if (highByte > 0x39)
		{
			highByte -= 0x37;
		}
		else
		{
			highByte -= 0x30;
		}

		if (lowByte > 0x39)
		{
			lowByte -= 0x37;
		}
		else
		{
			lowByte -= 0x30;
		}

		dest[i / 2] = (highByte << 4) | lowByte;
	}
	return ;
}

void transIP( unsigned char *str, uint8_t iphex[] )
{
	unsigned char *p;
	int count=0;
	p = strtok(str, ".");
	if(p != NULL)
	{
		iphex[count++] = atol(p);
		while(1)
		{
			p = strtok(NULL, ".");
			if(p == NULL)
			{
				break;
			}
			else
			{
				iphex[count++] = atol(p);
			}
		}
	}
}

void transMAC( unsigned char *str, uint8_t MAC[] ) 
{
	unsigned char *p;
	int count=0;
	p = strtok(str, ":");
	if(p != NULL)
	{
		MAC[count++] = strtoul(p,0,16);
		while(1)
		{
			p = strtok(NULL, ":");
			if(p == NULL)
			{
				break;
			}
			else
			{
				MAC[count++] = strtoul(p,0,16);
			}
		}
	}
}

void readInfoFromDevice( unsigned char buf[], const unsigned char *command )
{
	FILE *stream;
	stream = popen( command, "r" );
	if(stream == NULL)
	{
		printf("Command run error : %s", command);
	}
	else
	{
		fread( buf, sizeof(unsigned char), 64, stream); 
	}
	trim(buf);
}

void getIpInfoFromDevice( unsigned char buf[], const unsigned char *command )
{
	int sum = checkInitForChar( buf );
	if(sum != 0)
	{
		// �Ѿ���ʼ�����Ͳ���Ҫ�ٳ�ʼ����
		return;
	}
	readInfoFromDevice(buf, command);
}

void getIpFromDevice( uint8_t *info, const unsigned char *command )
{
	int sum = checkInit( info, 4 );
	if(sum != 0)
	{
		// �Ѿ���ʼ�����Ͳ���Ҫ�ٳ�ʼ����
		return;
	}
	unsigned char buf[16] = {0};
	getIpInfoFromDevice(buf, command);
	transIP(buf, info);
}

void GetWanIpAddressFromDevice(unsigned char info[])
{
	getIpInfoFromDevice(ipaddr, GET_WAN_IP);
	strcpy(info, ipaddr);
}

void GetUdpServerIpAddressFromDevice(unsigned char info[])
{
	getIpInfoFromDevice(udp_server_ipaddr, GET_UDP_SERVER_IP);
	strcpy(info, udp_server_ipaddr);
}

void GetUdpServerIpFromDevice(uint8_t info[])
{
	getIpFromDevice( udp_server_ip, GET_UDP_SERVER_IP );
	memcpy(info, udp_server_ip, 4);
}

void GetWanIpFromDevice(uint8_t info[])
{
	getIpFromDevice( ip, GET_WAN_IP );
	memcpy(info, ip, 4);
}

void GetWanNetMaskFromDevice(uint8_t info[])
{
	getIpFromDevice( mask, GET_WAN_NETMASK );
	memcpy(info, mask, 4);
}

void GetWanGatewayFromDevice(uint8_t info[])
{
	getIpFromDevice( gateway, GET_WAN_GATEWAY );
	memcpy(info, gateway, 4);
}

void GetWanDnsFromDevice(uint8_t info[])
{
	getIpFromDevice( dns, GET_DNS );
	memcpy(info, dns, 4);
}

void GetMacFromDevice(uint8_t info[])
{
	int sum = checkInit(MAC,6);
	if(sum != 0)
	{
		// �Ѿ���ʼ�����Ͳ���Ҫ�ٳ�ʼ����
		memcpy(info, MAC, 6);
		return;
	}
	unsigned char buf[16] = {0};
	readInfoFromDevice(buf, GET_WAN_MAC);
	transMAC(buf, MAC);
	memcpy(info, MAC, 6);
}

void GetHostNameFromDevice(unsigned char *info)
{
	int sum = checkInit(HostName,1);
	if(sum != 0)
	{
		// �Ѿ���ʼ�����Ͳ���Ҫ�ٳ�ʼ����
		strcpy(info,HostName);
		return;
	}
	unsigned char buf[64] = {0};
	readInfoFromDevice(buf, GET_HOST_NAME);
	strcpy(HostName,buf);
	strcpy(info,HostName);
}

int GetVersionFromDevice(unsigned char *info)
{
	int sum = checkInit(Version,5);
	if(sum != 0)
	{
		// �Ѿ���ʼ�����Ͳ���Ҫ�ٳ�ʼ����
		strcpy(info,Version);
		return;
	}
	unsigned char buf[64] = {0};
	readInfoFromDevice(buf, GET_VERSION);
	hexStrToByte( buf,  Version, strlen(buf) );
	// �п����зǳ����ַ���������memcpy��������ʵ���ַ�������
	memcpy(info, Version, strlen(buf)/2);
	return strlen(buf)/2;
}

void GetHashFromDevice(unsigned char *info)
{
	int sum = checkInit(Hash,8);
	if(sum != 0)
	{
		// �Ѿ���ʼ�����Ͳ���Ҫ�ٳ�ʼ����
		strcpy(info,Hash);
		return;
	}
	unsigned char buf[64] = {0};
	readInfoFromDevice(buf, GET_HASH);
	strcpy(Hash,buf);
	strcpy(info,Hash);
}

void GetDebugFromDevice(unsigned char *info)
{
	int sum = checkInit(Debug,8);
	if(sum != 0)
	{
		// �Ѿ���ʼ�����Ͳ���Ҫ�ٳ�ʼ����
		strcpy(info,Debug);
		return;
	}
	unsigned char buf[64] = {0};
	readInfoFromDevice(buf, GET_DEBUG);
	strcpy(Debug,buf);
	strcpy(info,Debug);
}

void InitUserName(unsigned char *initInfo)
{
	strcpy(UserName, initInfo);
}

void GetUserName(unsigned char *info)
{
	strcpy(info, UserName);
}

void InitPassword(unsigned char *initInfo)
{
	strcpy(Password, initInfo);
}

void GetPassword(unsigned char *info)
{
	strcpy(info, Password);
}

void SetDeviceName(unsigned char *initInfo)
{
	strcpy(DeviceName, initInfo);
}

void InitDeviceName()
{
	unsigned char buf[16] = {0};
	readInfoFromDevice(buf, GET_WAN_DEV);
	strcpy(DeviceName, buf);
}

void GetDeviceName(unsigned char *info)
{
	strcpy(info, DeviceName);
}


