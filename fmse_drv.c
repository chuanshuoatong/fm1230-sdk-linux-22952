
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/spi/spidev.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <errno.h>

int fd = -1;
int gpio_fd = -1;

#define SE_TYPE_SPI

void fmse_close(void)
{
	// 关闭设备节点
	close(fd);
	
	//close gpio fd
	//close(gpio_fd);
}

#ifdef SE_TYPE_SPI

//SPI CMD
#define SPI_CMD_GET_ID			0x9F
#define SPI_CMD_SEND_DATA		0x02
#define SPI_CMD_RECV_DATA		0x03
#define SPI_CMD_CHK_STATE		0x05

#define SPI_MIN_LEN				2
#define SPI_MAX_LEN				1024
#define WAIT_SE_TIMEOUT			10000

//time para
#define TCMD					16
#define TSEL					2
#define TCWT					1
#define TEND					1
#define TGUD					40

/*
	SPI CS控制分三种情况：
	1.cs 由硬件控制
	2.cs软件控制，在spi驱动中控制CS
	3.cs软件控制，在gpio驱动中控制CS
	
	note:
	CS的控制涉及到SE的Tend时间长短，会影响SE的SPI通信时序！！！
	建议在SPI通信结束后，驱动应该及时拉高CS，否则SPI通信可能超时，
	命令执行返回失败！
	*/
//spi chip select 
void se_select(uint8_t sel)
{
	uint8_t cs_select = 1;
	
	if(sel)
		cs_select = 1;	//select
	else	
		cs_select = 0;	//not select
	
	//1.CS由硬件控制时，此处为空，软件不需要做控制。
	
	//2.cs软件控制，在spi驱动中控制CS
	//ioctl(fd, SPI_IOC_WR_MODE, &cs_select);
	//如果需要，可以适当增加延时。
	//usleep(50);
	
	//3.cs软件控制，在gpio驱动中控制CS
	//write(gpio_fd, &cs_select, 1);
	//如果需要，可以适当增加延时。
	//usleep(50);

}

void se_init_spi(void)
{
	uint8_t msb = 0;
	uint8_t mode = 3;

	//init SPI MSB
	ioctl(fd, SPI_IOC_WR_LSB_FIRST, &msb);

	//init SPI mode3
	ioctl(fd, SPI_IOC_WR_MODE, &mode);
}

int fmse_open(char *devname)
{
	// 打开设备节点
    fd = open(devname, O_RDWR);
    if (fd < 0) {
        printf("fmse open device %s failed.\r\n", devname);
        return fd;
    }
	
	//init spi MSB,mode3
	se_init_spi();
	
	//for gpio device,open gpio fd!
	/*gpio_fd = open(GPIO_DEV_NAME, O_RDWR);
	if (gpio_fd < 0){
		printf("open %s fail\n", GPIO_DEV_NAME);
		return -1;
	}*/
	
	return 0;
}

//se send and receive
void se_send_recv(uint8_t *wbuf, uint16_t wlen, uint8_t *rbuf, uint16_t rlen)
{
	struct spi_ioc_transfer  xfer[2];
	uint16_t mdelay = 20;
	int len;
	
	memset(&xfer, 0, sizeof(xfer));
	
	xfer[0].bits_per_word = 8;
	xfer[0].speed_hz = 9600000;
	xfer[1].bits_per_word = 8;
	xfer[1].speed_hz = 9600000;

	if(wlen>1){
	//分两次发送，用于发送完cmd之后，增加延时，即Tcmd.
	xfer[0].tx_buf = (unsigned long)wbuf;
	xfer[0].rx_buf = (unsigned long)NULL;
	xfer[0].len = 1;
    xfer[0].delay_usecs = mdelay;
	xfer[1].tx_buf = (unsigned long)&wbuf[1];
	xfer[1].rx_buf = (unsigned long)NULL;
	xfer[1].len = wlen-1;
	len = ioctl(fd, SPI_IOC_MESSAGE(2), &xfer);
	}else{
		xfer[0].tx_buf = (unsigned long)wbuf;
		xfer[0].rx_buf = (unsigned long)NULL;
		xfer[0].len = wlen;
		xfer[0].delay_usecs = mdelay;	//如有需要，可以在发送后，适当增加延时，即Tcmd.
		xfer[1].tx_buf = (unsigned long)NULL;
		xfer[1].rx_buf = (unsigned long)rbuf;
		xfer[1].len = rlen;
		len = ioctl(fd, SPI_IOC_MESSAGE(2), &xfer);
	}
}

//get se device id
int se_get_devid(uint8_t *rbuf, uint16_t *rlen)
{
	uint8_t send_buf[4];
	uint16_t send_len;
	uint16_t recv_len;
	
	send_buf[0] = 0x9F;
	send_len = 1;
	recv_len = 7;
	se_select(1);
	se_send_recv(send_buf, send_len, rbuf, recv_len);
	se_select(0);
	*rlen = recv_len;
	return 0;
}

//check se state
char se_chk_state(int timeout)
{
	int i;
	uint8_t send_buf[4];
	uint8_t recv_buf[4];
	uint16_t send_len;
	uint16_t recv_len;
	
	for(i=0;i<timeout;i++){
		send_buf[0] = SPI_CMD_CHK_STATE;
		send_len = 1;
		recv_len = 1;
		se_select(1);
		se_send_recv(send_buf, send_len, recv_buf, recv_len);
		se_select(0);
		
		if(!recv_buf[0])
			break;
	}
	return recv_buf[0];
}

//se transceive
int se_transceive(uint8_t *sbuf, uint16_t slen, uint8_t *rbuf, uint16_t *rlen, int timeout)
{
	int i;
	uint8_t LenHi;
	uint8_t LenLo;
	uint8_t Lrc;
	uint8_t send_buf[1024];
	uint8_t recv_buf[300];
	uint16_t send_len;
	uint16_t recv_len;
	
	*rlen = 0;
	
	se_select(1);
	
	//send
	//send cmd head
	send_buf[0] = SPI_CMD_SEND_DATA;

	//send length
	LenHi = slen>>8;
	LenLo = slen;
	send_buf[1] = LenHi;
	send_buf[2] = LenLo;
	
	//calc lrc
	Lrc = 0xFF^LenHi^LenLo;
		
	for(i=0;i<slen;i++){	
		send_buf[3+i] = sbuf[i];
		Lrc ^= sbuf[i];
	}
	
	send_buf[3+slen] = Lrc;
	
	send_len = slen+4;
	recv_len = 0;
	se_send_recv(send_buf, send_len, NULL, recv_len);
	
	se_select(0);
	
	//chk state
	if(se_chk_state(timeout))
		return 12;

	usleep(TCMD);
	
	//recv
	//send cmd head
	//recv frame
	send_buf[0] = SPI_CMD_RECV_DATA;
	send_len = 1;
	recv_len = 300;
	se_select(1);
	se_send_recv(send_buf, send_len, recv_buf, recv_len);
	se_select(0);
	
	LenHi = recv_buf[0];
	LenLo = recv_buf[1];
	*rlen = LenHi<<8 | LenLo;
	//printf("LenHi=%x,LenLo=%x,rlen=%x\n",LenHi,LenLo,*rlen);
	
	if(*rlen < SPI_MIN_LEN || *rlen > SPI_MAX_LEN)
	{
		*rlen = 0;
		return 13;
	}
	
	recv_len = *rlen+3; // +3 是 recv_buf[0]、recv_buf[1] 以及最后的 Lrc
	
	//check lrc
	Lrc = 0xFF;
	for(i=0; i<recv_len; i++)
	{
		Lrc ^= recv_buf[i];
	}
	//printf("Lrc:%x,%x\n",Lrc,recv_buf[recv_len-1]);
	
	if(Lrc)
	{
		*rlen = 0;
		return 14;
	}
	
	memmove(rbuf, &recv_buf[2], *rlen);

	return 0;
}

#else
	
#define I2C_ADDR 			(0xe2>>1)
#define I2C_MIN_LEN			3
#define I2C_MAX_LEN			1024

int fmse_open(char *devname)
{
	// 打开设备节点
    fd = open(devname, O_RDWR);
    if (fd < 0) {
        printf("fmse open device %s failed.\r\n", devname);
        return fd;
    }
	
	//for gpio device,open gpio fd!
	/*gpio_fd = open(GPIO_DEV_NAME, O_RDWR);
	if (gpio_fd < 0){
		printf("open %s fail\n", GPIO_DEV_NAME);
		return -1;
	}*/
	
	return 0;
}

/*
 @ brife: fmse_send_bytes
 * tx_len: 发送数据长度
 * tx_buf: 发送数据
 */
int fmse_send_bytes(int fd, int tx_len, const unsigned char *tx_buf) {
    int ret = 0;
    struct i2c_rdwr_ioctl_data data;
    struct i2c_msg msg[1];
    unsigned char sendbuf[270] = {0};
	unsigned char end;
	int i;
	
	//send fmt:lo,lh,00,02,data,bcc!

    // 设置发送参数
    data.msgs = msg;
    data.nmsgs = 1;
    data.msgs[0].len = tx_len + 5;
    data.msgs[0].addr = I2C_ADDR;
    data.msgs[0].flags = 0; // write flag
    data.msgs[0].buf = sendbuf;
    sendbuf[0] = tx_len+3;
	sendbuf[1] = (tx_len+3)>>8;
	sendbuf[2] = 0;
	sendbuf[3] = 2;
    if (memcpy(sendbuf + 4, tx_buf, tx_len) == NULL) {
        return -11;
    }

    // 计算结尾字节
    end = sendbuf[0];
    for (i = 1; i < tx_len+4; i++) {
        end ^= sendbuf[i];
    }
    sendbuf[tx_len + 4] = end;

#ifdef I2C_FMSE_DBG
    // 打印发送数据
    printf("fmse send len %d:\n", tx_len + 5);
    dump_data(tx_len+5,sendbuf);
#endif

    // 发送数据
    ret = ioctl(fd, I2C_RDWR, (unsigned long) &data);
    if (ret < 0) {
        printf("fmse send data failed.\n");
        return ret;
    }
	
#ifdef I2C_FMSE_DBG
    printf("fmse send data success.\n");
#endif

    return 0;
}

/*
 @ brife: fmse_send_bytes_gatr
 */
int fmse_send_bytes_gatr(int fd) {
    int ret = 0;
    struct i2c_rdwr_ioctl_data data;
    struct i2c_msg msg[1];
    unsigned char sendbuf[5] = {3,0,0,0x30,0x33};
	
	//send fmt:lo,lh,00,30,data,bcc!

    // 设置发送参数
    data.msgs = msg;
    data.nmsgs = 1;
    data.msgs[0].len = 5;
    data.msgs[0].addr = I2C_ADDR;
    data.msgs[0].flags = 0; // write flag
    data.msgs[0].buf = sendbuf;

#ifdef I2C_FMSE_DBG
    // 打印发送数据
    printf("fmse send len %d:\n", 5);
    dump_data(5,sendbuf);
#endif

    // 发送数据
    ret = ioctl(fd, I2C_RDWR, (unsigned long) &data);
    if (ret < 0) {
        printf("fmse send data failed.\n");
        return ret;
    }
	
#ifdef I2C_FMSE_DBG
    printf("fmse send data success.\n");
#endif

    return 0;
}

int fmse_recv_len(int fd) {
    int ret = 0;
    struct i2c_rdwr_ioctl_data data;
    struct i2c_msg msg[1];
    unsigned char recvbuf[2] = {0};
	int i;
	int recvlen;
	unsigned char bcc;
	
	//recv fmt:lo,lh,00,00,data,bcc!

    // 设置接收参数
    data.msgs = msg;
    data.nmsgs = 1;
    data.msgs[0].len = 2;
    data.msgs[0].addr = I2C_ADDR;
    data.msgs[0].flags = 1; // read flag
    data.msgs[0].buf = recvbuf;

    // 接收数据
    ret = ioctl(fd, I2C_RDWR, (unsigned long) &data);
    if (ret < 0) {
        printf("fmse recv data failed.\n");
        return ret;
    }
    
#ifdef I2C_FMSE_DBG
	printf("fmse recv data success.\n");
#endif
	
    recvlen = recvbuf[0]|recvbuf[1]<<8;
	
#ifdef I2C_FMSE_DBG
	// 打印接收数据
	printf("fmse recv len %d:\n", recvlen);
#endif
	return recvlen;
}

/*
 @ brife: fmse_recv_bytes
 * rx_len: 接收数据长度
 * rx_buf: 接收数据
 * return value: received actual length!
 */
int fmse_recv_bytes(int fd, int rx_len, unsigned char *rx_buf) {
    int ret = 0;
    struct i2c_rdwr_ioctl_data data;
    struct i2c_msg msg[1];
    unsigned char recvbuf[270] = {0};
	int i;
	int recvlen;
	unsigned char bcc;
	
	//recv fmt:lo,lh,00,00,data,bcc!

    // 设置接收参数
    data.msgs = msg;
    data.nmsgs = 1;
    data.msgs[0].len = rx_len+2;
    data.msgs[0].addr = I2C_ADDR;
    data.msgs[0].flags = 1; // read flag
    data.msgs[0].buf = recvbuf;

    // 接收数据
    ret = ioctl(fd, I2C_RDWR, (unsigned long) &data);
    if (ret < 0) {
        printf("fmse recv data failed.\n");
        return ret;
    }
    
#ifdef I2C_FMSE_DBG
	printf("fmse recv data success.\n");
#endif
	
    recvlen = recvbuf[0]|recvbuf[1]<<8;
	
#ifdef I2C_FMSE_DBG
	// 打印接收数据
	printf("fmse recv len %d:\n", recvlen+2);
	dump_data(recvlen+2,recvbuf);
#endif

	if(recvlen<I2C_MIN_LEN||recvlen>I2C_MAX_LEN)
		return -22;
	
	//check sta
	if(recvbuf[3]){
		printf("recv sta err %x\n",recvbuf[3]);
		return -25;
	}

    // 校验数据
    bcc = recvbuf[0];
    for (i = 1; i < recvlen+2; i++) {
        bcc ^= recvbuf[i];
    }
    if (bcc) {
        return -23;
    }
	
#ifdef I2C_FMSE_DBG
    printf("fmse recv data check success.\n");
#endif	

    memcpy(rx_buf, recvbuf + 4, recvlen - 3);

    return (recvlen-3);	//actual length
}

/*
 @ brife: fmse_transfer
 * tx_len: 发送数据长度
 * tx_buf: 发送数据
 * rx_len: 接收数据长度
 * rx_buf: 接收数据
 * return value: received actual length!
 */
int se_transceive(uint8_t *sbuf, uint16_t slen, uint8_t *rbuf, uint16_t *rlen, int timeout)
{
    int ret = 0;
	int recv_len = 261;

    // 发送数据
    ret = fmse_send_bytes(fd, slen, sbuf);
    if (ret<0) {
		close(fd);
		return ret;
    }
	
	/* wait SE command process complete */
	if(timeout > 200000)
		sleep(20);
	usleep(timeout);
	
	//recv len
	ret = fmse_recv_len(fd);
	if (ret<0) {
		close(fd);
		return ret;
    }
	recv_len = ret; //recv length

    // 接收数据
    ret = fmse_recv_bytes(fd, recv_len, rbuf);
	if (ret<0) {
		close(fd);
		return ret;
    }
	*rlen = ret; //recv length
	
    return 0;
}

/*
 @ brife: fmse_transfer_gatr
 * rx_len: 接收数据长度
 * rx_buf: 接收数据
 */
int fmse_transfer_gatr(int rx_len, unsigned char *rx_buf) {
    int ret = 0;
	
    // 发送数据
    ret = fmse_send_bytes_gatr(fd);
    if (ret<0) {
		close(fd);
		return ret;
    }
	
	usleep(1000);

    // 接收数据
    ret = fmse_recv_bytes(fd, rx_len, rx_buf);
	if (ret<0) {
		close(fd);
		return ret;
    }
	
    return ret;	//recv length
}

//get se device id(device atr)
int se_get_devid(uint8_t *rbuf, uint16_t *rlen)
{
	int ret;
	int rxlen;
	uint8_t tmpbuf[32];
	
	rxlen=20;
    ret = fmse_transfer_gatr(rxlen,tmpbuf);
    if (ret<0) {
        printf("fmse_transfer_gatr error!\n");
		return 1;
    }
#ifdef I2C_SDK_DBG
	printf("fmse_transfer_gatr actual rxlen:%x!\n",ret);
#endif
	*rlen=ret-2;
	memcpy(rbuf,tmpbuf,*rlen);
	return 0;
}
	
#endif


/******************************************/
void dump_data(uint16_t len,uint8_t *buf)
{
	uint16_t i;
	
	for(i=0;i<len;i++)
	{
		printf("%02x,",buf[i]);
	}
	printf("\r\n");
}
/******************************************/
void StrToHex(uint8_t *pbDest, uint8_t *pbSrc, int nLen)
{
	uint8_t h1,h2;
	uint8_t s1,s2;
	int i;

	for (i=0; i<nLen; i++)
	{
		h1 = pbSrc[2*i];
		h2 = pbSrc[2*i+1];

		s1 = toupper(h1) - 0x30;
		if (s1 > 9) 
		s1 -= 7;

		s2 = toupper(h2) - 0x30;
		if (s2 > 9) 
		s2 -= 7;

		pbDest[i] = s1*16 + s2;
	}
}
/******************************************/

