//メッセージ長8 bytesのバージョンの例
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
#include "./tiny-AES-c/aes.h"
#define PLAIN_BYTES 8
#define SENDING 1000
void print_usage(void);
int makeframe(struct canfd_frame *frame,uint8_t * plain,int frame_byte);
int initialize_can(struct canfd_frame *frame,struct sockaddr_can *addr,struct ifreq *ifr,const char *ifname,int canid,int frame_bytes);
int initialize_can2(struct canfd_frame *frame,struct sockaddr_can *addr,struct ifreq *ifr,const char *ifname,int canid,int frame_bytes);
int recieve_fd(struct sockaddr_can *addr, struct canfd_frame *frame, struct ifreq *ifr,const char *ifname);
void send_fd(struct sockaddr_can *addr, struct canfd_frame *frame, struct ifreq *ifr,const char *ifname);
void macgen(unsigned char *key,unsigned char * plain,int length,unsigned char *MAC,int mac_seq);
static void phex(uint8_t* str,int len);
const int origin_dlc[]={0,1,2,3,4,5,6,7,8,-1,-1,-1,9,-1,-1,-1,10,-1,-1,-1,11-1,-1,-1,12-1,-1,-1,-1,-1,-1,-1,13}; //n番目がn byteのときのDLCの値を示す．無効なbyte長は-1を返す
const int origin_dlc_inv[] ={0,1,2,3,4,5,6,7,8,12,16,20,24}; //n番目がDLCnのときのバイト長を示す
 uint8_t encrypt_key[16]= { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
  uint8_t iv[16]= { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
uint32_t seq;
int main(int argc,char *argv[])
{
    struct sockaddr_can addr;
	struct canfd_frame frame;
    struct ifreq ifr;
    int nsec;
    seq = 0;
    FILE* f;
        init_Rnd_cdm(0x01d0);
    if(argc!=2)
    {
        print_usage();
    }
    if(strcmp(argv[1],"recieve")==0)
    {
        while(1){
             
             recieve_fd(&addr,&frame,&ifr,"can0");
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
            
             send_fd(&addr,&frame,&ifr,"can1");
             ++seq;
             usleep(120000); //11 msec(10000000 nsec)から怪しくなり始める
             fprintf(f,"%d\n",nsec);

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

int makeframe(struct canfd_frame *frame,uint8_t * plain,int plain_byte) //フレームを作成し，その合計長をバイト単位で返す
{
  static unsigned char key[AES_BLOCK_SIZE];
  unsigned char MAC[AES_BLOCK_SIZE];
  uint32_t sending_seq = seq;
  int i;
memcpy(frame->data,plain,plain_byte);
 macgen(key,plain,plain_byte,MAC,seq);
for(i=plain_byte;i<plain_byte+8;++i)
{
  frame->data[i] = MAC[i];
}
	frame->data[(plain_byte+8)+0] = (uint8_t )0x000000ff&sending_seq;
	frame->data[(plain_byte+8)+1] =  (uint8_t )((0x0000ff00&sending_seq)>>8) ;
	frame->data[(plain_byte+8)+2] =  (uint8_t )((0x00ff0000&sending_seq)>>16) ;
	frame->data[(plain_byte+8)+3] = origin_dlc[plain_byte];
 
  return plain_byte+plain_byte+4;
}

int initialize_can(struct canfd_frame *frame,struct sockaddr_can *addr,struct ifreq *ifr,const char *ifname,int canid,int plain_bytes) //受信のときはframe_bytesを-1にする
{
  int s;
  int mtu;
  int enable_canfd = 1;
  const int dropmonitor_on = 1;
  can_err_mask_t err_mask = CAN_ERR_MASK;
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
		exit(-1);
	}
  if(plain_bytes!=-1)
  {
    if (ioctl(s, SIOCGIFMTU, ifr) < 0) {
			perror("SIOCGIFMTU");
			exit(1);
		}
		mtu = ifr->ifr_mtu;

		if (mtu != CANFD_MTU) {
			printf("CAN interface is not CAN FD capable - sorry.\n");
			exit(1);
		}
  }
  
    if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
			       &enable_canfd, sizeof(enable_canfd))){
			printf("error when enabling CAN FD support\n");
			exit(1);
		}
     setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);

	strcpy(ifr->ifr_name, ifname);
	ioctl(s, SIOCGIFINDEX, ifr);

	addr->can_family = AF_CAN;
	addr->can_ifindex = ifr->ifr_ifindex;
    if(plain_bytes==-1)
    {
      mtu = ifr->ifr_mtu;
      frame->len = can_fd_dlc2len(can_fd_len2dlc(frame->len));
    
        if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &err_mask, sizeof(err_mask))) {
		  perror("setsockopt()");
		  exit(1);
	}
     if (setsockopt(s, SOL_SOCKET, SO_RXQ_OVFL,
		       &dropmonitor_on, sizeof(dropmonitor_on)) < 0) {
		perror("setsockopt() SO_RXQ_OVFL not supported by your Linux Kernel");
	}
       printf("if\n");
    } else {
      frame->len = plain_bytes+4+8;
      frame->can_id = canid;
    }

       

	printf("%s at index %d\n", ifname, ifr->ifr_ifindex);
	if(bind(s,(struct sockaddr *)addr, sizeof(*addr)) < 0) {
		perror("Error in socket bind");
		exit(-2);
	}
  if(plain_bytes==-1)
  {
      msg.msg_name = addr;
       msg.msg_flags = 0;
  }
  printf("init OK");
  return s;
}

void macgen(unsigned char *key,unsigned char * plain,int length,unsigned char *MAC,int mac_seq)
{
   if(mac_seq==0)
  {
    for(int i=0;i<AES_BLOCK_SIZE;i++){
		key[i]=Rnd_byte();
    }
	}
   if(((seq&0x000000ff)==0xff)&&seq!=0){
    for(int i=0;i<AES_BLOCK_SIZE;i++){
		key[i]=Rnd_byte()^key[i];
    	
    }
  }
omac1_aes_128(key,plain,length,MAC);
}

void send_fd(struct sockaddr_can *addr, struct canfd_frame *frame, struct ifreq *ifr,const char *ifname)
{
  int s;
 static struct AES_ctx ctx;
  int length;
  uint8_t plain []= {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
 
  if(seq==0) {AES_init_ctx_iv(&ctx, encrypt_key, iv); }
  s = initialize_can2(frame,addr,ifr,ifname,0x02,PLAIN_BYTES);
  length=makeframe(frame,plain,PLAIN_BYTES);
  AES_CTR_xcrypt_buffer(&ctx, frame->data,length -4);
  write(s, frame, CANFD_MTU);
}
int recieve_fd(struct sockaddr_can *addr, struct canfd_frame *frame, struct ifreq *ifr,const char *ifname)
{
  int s;
  int i;
  uint32_t recieved_seq;
  static struct AES_ctx ctx;
  static unsigned char key[AES_BLOCK_SIZE];
  unsigned char MAC[AES_BLOCK_SIZE];
  int length;
  int nbytes;
  unsigned int address_length =CANFD_MTU;
  if(seq==0) {AES_init_ctx_iv(&ctx, encrypt_key, iv);}
  s = initialize_can2(frame,addr,ifr,ifname,0,-1);
  nbytes = recvfrom(s, frame, CANFD_MTU,0, (struct sockaddr*) addr, &address_length);
  AES_CTR_xcrypt_buffer(&ctx, frame->data,frame->len -4);
  recieved_seq=0;
  recieved_seq += (uint32_t)frame->data[(frame->len-1)-3]; //一番最後がDLCでそこから3歩下がるとシーケンス番号が始まる
  recieved_seq += ((uint32_t)(frame->data[(frame->len-1)-2])<<8);
  recieved_seq += ((uint32_t)(frame->data[(frame->len-1)-1])<<16);
  macgen(key,frame->data,origin_dlc_inv[frame->data[frame->len-1]],MAC,recieved_seq);
  printf("recieved message ");
  phex(frame->data,origin_dlc_inv[frame->data[frame->len-1]]);
  printf("generated mac : ");
  phex(MAC+origin_dlc_inv[frame->data[frame->len-1]],origin_dlc_inv[frame->data[frame->len-1]]);
  printf("recieved mac : ");
  phex(frame->data+origin_dlc_inv[frame->data[frame->len-1]],8);
  if(memcmp(frame->data+origin_dlc_inv[frame->data[frame->len-1]],MAC+origin_dlc_inv[frame->data[frame->len-1]],origin_dlc_inv[frame->data[frame->len-1]])==0)
  {
    printf("valid\n");
  }else{
    printf("invalid\n");
  }
  return nbytes;
}

static void phex(uint8_t* str,int len)
{
    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x ", str[i]);
    printf("\n");
}
int initialize_can2(struct canfd_frame *frame,struct sockaddr_can *addr,struct ifreq *ifr,const char *ifname,int canid,int frame_bytes) //受信時，idは0frame_bytesは-1にする
{
  int s;
  size_t mtu;
  int enable_canfd = 1;
  //recieve only
     const int dropmonitor_on = 1;
     int nbytes;
     socklen_t len = sizeof(addr);
    can_err_mask_t err_mask = CAN_ERR_MASK;
     struct iovec iov = {
		.iov_base = frame,
	};
  struct msghdr msg = {
		.msg_iov = &iov,
	};
  //______
 strcpy(ifr->ifr_name, ifname);  
ifr->ifr_ifindex = if_nametoindex(ifr->ifr_name);
     if((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("Error while opening socket");
		exit(-1);
	}
   if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
			       &enable_canfd, sizeof(enable_canfd))){
			printf("error when enabling CAN FD support\n");
			exit(1);
		}
 mtu = ifr->ifr_mtu;
 if(frame_bytes!=-1)
{
   if (ioctl(s, SIOCGIFMTU, ifr) < 0) {
			perror("SIOCGIFMTU");
			exit(1);
		}
     mtu = ifr->ifr_mtu;
    	if (mtu != CANFD_MTU) {
			printf("CAN interface is not CAN FD capable - sorry.\n");
			exit(1);
		}
}

 
if(frame_bytes!=-1)
{
    if (ioctl(s, SIOCGIFMTU, ifr) < 0) {
			perror("SIOCGIFMTU");
			exit(1);
		}
		mtu = ifr->ifr_mtu;
    if (mtu != CANFD_MTU) {
			printf("CAN interface is not CAN FD capable - sorry.\n");
			exit(1);
		}

}

  if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &err_mask, sizeof(err_mask))) {
		perror("setsockopt()");
		exit(1);
	}
   
     frame->len = can_fd_dlc2len(can_fd_len2dlc(frame->len));
     if(frame_bytes!=-1)
     {
       setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);
        ioctl(s, SIOCGIFINDEX, ifr);
        frame->len = frame_bytes+4+8;
      frame->can_id = canid;
     }
      addr->can_family = AF_CAN;
  addr->can_ifindex = ifr->ifr_ifindex;
  if(frame_bytes==-1)
  {
     if (setsockopt(s, SOL_SOCKET, SO_RXQ_OVFL,
		       &dropmonitor_on, sizeof(dropmonitor_on)) < 0) {
		perror("setsockopt() SO_RXQ_OVFL not supported by your Linux Kernel");
	}

  if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_ERR_FILTER, &err_mask, sizeof(err_mask))) {
		perror("setsockopt()");
		exit(1);
	}
  }
     if(bind(s,(struct sockaddr *)addr, sizeof( *addr)) < 0) {
		perror("Error in socket bind");
		exit(-2);
	}


  return s;
}