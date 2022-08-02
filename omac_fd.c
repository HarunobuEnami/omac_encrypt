//メッセージ長4 bytesのバージョンの例
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include "terminal.h"
#include "lib.h"
#include"aes-omac1.h"
#define SENDING 1000

void print_usage(void);
int recieve_fd(struct sockaddr_can *addr, struct canfd_frame *frame, struct ifreq *ifr,const char *ifname);
int send_fd(struct sockaddr_can *addr, struct canfd_frame *frame, struct ifreq *ifr,const char *ifname);
int main(int argc,char *argv[])
{
    struct sockaddr_can addr;
	struct canfd_frame frame;
    struct ifreq ifr;
    int seq = 0;
    int nsec;
    FILE* f;
        init_Rnd_cdm(0x01d0);
    if(argc!=2)
    {
        print_usage();
    }
    if(strcmp(argv[1],"recieve")==0)
    {
        while(1){
             recieve_fd(&addr,&frame,&ifr,"can1");
             ++seq;
             printf("recieved %d frames\n",seq);
        }
       
    }else if (strcmp(argv[1],"send")==0){
      f = fopen("nsec.csv","w");
        while(1){
          if(seq==SENDING)
          {
            fclose(f);
            exit(0);
          } 
             nsec = send_fd(&addr,&frame,&ifr,"can0");
             usleep(12000); //11 msec(10000000 nsec)から怪しくなり始める
             fprintf(f,"%d\n",nsec);
             ++seq;
             printf("sent %d frames\n",seq);
        }
       
    } else{
        print_usage();
    }
    return 0;
}

void print_usage(void)
{
    fprintf(stderr,"usage : omac_fd (send / recieve)\n");
    exit(1);
}

int recieve_fd(struct sockaddr_can *addr, struct canfd_frame *frame, struct ifreq *ifr,const char *ifname)
{
    static unsigned char key[AES_BLOCK_SIZE];
    unsigned char MAC[AES_BLOCK_SIZE];
    int p_size=4;
    int s;
    int i;
    int mtu;
    int enable_canfd = 1;
    const int dropmonitor_on = 1;
    int nbytes;
    uint8_t plain [4];
    can_err_mask_t err_mask = CAN_ERR_MASK;
    uint32_t seq_num;
    static int ini_flg = 1;
    //struct msghdr msg;
    struct iovec iov = {
		.iov_base = frame,
	};
  struct msghdr msg = {
		.msg_iov = &iov,
	};

    strcpy(ifr->ifr_name, ifname);  
     ifr->ifr_ifindex = if_nametoindex(ifr->ifr_name);  
     if((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("Error while opening socket");
		return -1;
	}
  
  addr->can_family = AF_CAN;
  addr->can_ifindex = ifr->ifr_ifindex;
  mtu = ifr->ifr_mtu;

    if(setsockopt(s,SOL_CAN_RAW,CAN_RAW_FD_FRAMES,&enable_canfd,sizeof(enable_canfd)))
      {
       printf("error when enabling CAN FD support\n");
       return 1;
      }
  frame->len = (can_fd_len2dlc(frame->len));
  if (setsockopt(s, SOL_SOCKET, SO_RXQ_OVFL,
		       &dropmonitor_on, sizeof(dropmonitor_on)) < 0) {
		perror("setsockopt() SO_RXQ_OVFL not supported by your Linux Kernel");
	}

  if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &err_mask, sizeof(err_mask))) {
		perror("setsockopt()");
		return 1;
	}
    if (bind(s, ((struct sockaddr *) addr), sizeof(*addr)) < 0) {
			perror("bind");
			return -1;
		}
    
    msg.msg_name = addr;
    msg.msg_flags = 0;
      nbytes = recvfrom(s, frame, CANFD_MTU,0, (struct sockaddr*) addr, CANFD_MTU);
      printf("nbytes : %d\n",nbytes);
 
    for(i=0;i<p_size;++i)
    {
      plain[i] = frame->data[i];
    }
      printf("message : ");
    for(i=0;i<p_size;++i)
    {
      printf("%02x ",plain[i]);
    }
    
    printf("\nrecieved mac : ");
    for(i=p_size;i<8;++i)
    {
      printf("%02x ",frame->data[i]);
    }

    seq_num=0;
    seq_num += (uint32_t)frame->data[8];
    seq_num += ((uint32_t)(frame->data[9])<<8);
    seq_num += ((uint32_t)(frame->data[10])<<16);
    seq_num += ((uint32_t)(frame->data[11])<<24);
 if(ini_flg==1)
  {
    for(int i=0;i<AES_BLOCK_SIZE;i++){
		key[i]=Rnd_byte();
    printf("init Rnd_bytes : %02x\n",key[i]);
    ini_flg = 0;
    }
	} else if((seq_num&0x000000ff)==0xff){
    for(int i=0;i<AES_BLOCK_SIZE;i++){
		key[i]=Rnd_byte()^key[i];
    printf("new Rnd_bytes : %02x\n",key[i]);
    }
  }
	
  omac1_aes_128(key,plain,p_size,MAC);
     printf("\nchecked mac : ");
    for(i=p_size;i<8;++i)
    {
      printf("%02x ",MAC[i]);
    }
    putchar('\n');
    
    printf("seq num %08x\n",seq_num);
    printf("frame length %04x\n",frame->len);
    return nbytes;
}

int send_fd(struct sockaddr_can *addr, struct canfd_frame *frame, struct ifreq *ifr,const char *ifname)
{
    int s;
	int nbytes;
    int mtu;
    int enable_canfd = 1;
	struct timespec start_time, end_time;
  static	unsigned char key[AES_BLOCK_SIZE];
	unsigned char MAC[AES_BLOCK_SIZE];
	int p_size=4; //データ長
	int nsec;
	static uint32_t seq=0;

	uint8_t plain []= {0x01,0x02,0x03,0x04};

	
	
	printf("-------------------------------------------------\n");
	printf("key            ");
	for(int i=0;i<AES_BLOCK_SIZE;i++){
		printf("%x",key[i]);
		if((i%4) == 3)
			printf(" ");
	}
	printf("\n");
    strcpy(ifr->ifr_name, ifname);
    ifr->ifr_ifindex = if_nametoindex(ifr->ifr_name);
	if((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("Error while opening socket");
		return -1;
	}

    if (ioctl(s, SIOCGIFMTU, ifr) < 0) {
			perror("SIOCGIFMTU");
			return 1;
		}
		mtu = ifr->ifr_mtu;

		if (mtu != CANFD_MTU) {
			printf("CAN interface is not CAN FD capable - sorry.\n");
			return 1;
		}

    if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
			       &enable_canfd, sizeof(enable_canfd))){
			printf("error when enabling CAN FD support\n");
			return 1;
		}
    
    frame->len = can_fd_dlc2len(can_fd_len2dlc(frame->len));
        setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);

	strcpy(ifr->ifr_name, ifname);
	ioctl(s, SIOCGIFINDEX, ifr);

	addr->can_family = AF_CAN;
	addr->can_ifindex = ifr->ifr_ifindex;

	printf("%s at index %d\n", ifname, ifr->ifr_ifindex);
	if(bind(s,(struct sockaddr *)addr, sizeof(*addr)) < 0) {
		perror("Error in socket bind");
		return -2;
	}

	frame->can_id = 0x01;

	frame->len = 0x0c; //シーケンス番号やメッセージ長によって変える
	frame->len = 0x10; //シーケンス番号やメッセージ長によって変える
	frame->data[0] = plain[0];
	frame->data[1] = plain[1];
	frame->data[2] = plain[2];
	frame->data[3] = plain[3];
	clock_gettime(CLOCK_REALTIME, &start_time);
	
  if(seq==0)
  {
    for(int i=0;i<AES_BLOCK_SIZE;i++){
		key[i]=Rnd_byte();
    }
	}
  
    omac1_aes_128(key,plain,p_size,MAC);//cal

	
	int i;//insert
	for(i=p_size;i<8;i++){
		frame->data[i] = MAC[i]; //frame[0]~[3]にメッセージをframe[4]~[7]にmacの[4]~[7]を載せる
	}
	++seq;
	frame->data[8] = 0x000000ff&seq;
	frame->data[9] = ((0x0000ff00&seq)>>8) ;
	frame->data[10] = ((0x00ff0000&seq)>>16) ;
	frame->data[11] = ((0xff000000&seq)>>24) ;
	
if(((seq&0x000000ff)==0x00)&&seq!=0){
	for(i=p_size;i<12;i++){
		frame->data[i] = MAC[i]; //frame[0]~[3]にメッセージをframe[4]~[11]にmacの[4]~[11]を載せる
	}
	++seq;
	frame->data[12] = 0x000000ff&seq;
	frame->data[13] = ((0x0000ff00&seq)>>8) ;
	frame->data[14] = ((0x00ff0000&seq)>>16) ; //シーケンス番号を28 bitへ
  frame->data[15] = 0x0a; //オリジナルのDLC
}
if(((seq&0x000000ff)==0xff)&&seq!=0){
  clock_gettime(CLOCK_REALTIME, &start_time);
    for(int i=0;i<AES_BLOCK_SIZE;i++){
		key[i]=Rnd_byte()^key[i];
    	
    }
    clock_gettime(CLOCK_REALTIME, &end_time);
    nsec = end_time.tv_nsec - start_time.tv_nsec;
  }else {nsec = 0;}
	nbytes =write(s, frame, CANFD_MTU);


    printf("%d\n",nbytes);
	printf("Wrote %d bytes\n", nbytes);
	for(i=0;i<8;i++){
	printf("frame.data[%d] = %02x\n",i,frame->data[i]);
	}
		
	return nsec;

}