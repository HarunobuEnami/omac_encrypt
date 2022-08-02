CANDUMP = candump.c lib.c
CANSEND = cansend.c lib.c
OMACSEND = omacsend.c lib.c 
OMACSEND2 = omacsend2.c lib.c
OMACRECIEVE = omacrecieve.c lib.c
OMAC_FD = omac_fd.c lib.c
OMAC_FD2 = omac_fd_2.c lib.c ./tiny-AES-c/aes.c 
CC =gcc
CFLAG = -Iinclude -DAF_CAN=PF_CAN -DPF_CAN=29 -DSO_RXQ_OVFFSET_BITS=64 -D_GNU_L=40 -DSCM_TIMESTAMPING_OPT_STATS=54 -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE  -Wno-parentheses -O2 -Wall


candump: 
	$(CC) $(CANDUMP)  -o $@  $? $(CFLAG)


cansend:
	$(CC) $(CANSEND)  -o $@  $? $(CFLAG)

omacsend:
	$(CC) $(OMACSEND)  -o $@  $? $(CFLAG)

omacsend2:
	$(CC) $(OMACSEND2)  -o $@  $? $(CFLAG)

omacrecieve:
	$(CC) $(OMACRECIEVE)  -o $@  $? $(CFLAG)

omac_fd:
	$(CC) $(OMAC_FD)  -o $@  $? $(CFLAG)

omac_fd2:
	$(CC) $(OMAC_FD2)  -o $@  $? $(CFLAG)