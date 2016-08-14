#include "functions.h"
#include "md5.h"
#include "info.h"

void PrintDebugInfo(char *type, uint8_t info[], size_t packetlen)
{
	unsigned char debug[8] = {0};
	GetDebugFromDevice(debug);
	if(strcmp(debug,"1") == 0)
	{
		printf("\n*****************Send %s info***************************\n",type);
		int m,n=0;
		for(m=0;m<=packetlen-1;m++)
		{
			n++;
			if(n==17)
			{
				printf("\n");
				n=1;
			}
			printf("%02x ",info[m]);
		}
		printf("\n");
	}
}

void FillMD5Area(uint8_t digest[], uint8_t id, const char passwd[], const uint8_t srcMD5[])
{
	uint8_t	msgbuf[128]; // msgbuf = ‘id‘ + ‘passwd’ + ‘srcMD5’
	md5_state_t md5_msg;
	md5_init(&md5_msg);
	
	int	passlen = strlen(passwd);
	int msglen = 1 + passlen + 16;

	msgbuf[0] = id;
	memcpy(msgbuf+1, passwd, passlen);
	memcpy(msgbuf+1+passlen, srcMD5, 16);

	//(void)MD5(msgbuf, msglen, digest);
    md5_append(&md5_msg, msgbuf, msglen);
    md5_finish(&md5_msg, digest);
}
