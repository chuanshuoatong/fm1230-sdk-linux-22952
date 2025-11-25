
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fmse_drv.h"
#include "fmse_cmd.h"
#include "tdes.h"

#define WAIT_SE_TIMEOUT			200000
#define WAIT_SE_LTIMEOUT		3000000

//fmse sdk cmd
/********************************************************************
* Function: select file
* Input Parameter:
* fid: file id
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t SelectFile(uint16_t fid, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x00\xa4\x00\x00\x02",wlen);
	wbuf[5] = fid>>8;
	wbuf[6] = fid;
	wlen += 2;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: verify PIN
* Input Parameter:
* pin_len: input PIN length
* pin: input PIN buffer
* Output Parameter:None
* Return: SW
*********************************************************************/
uint16_t VerifyPIN(uint8_t *pin, uint16_t pin_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x00\x20\x00\x00\x03",wlen);
	wbuf[4] = pin_len;
	memmove(wbuf+5, pin, pin_len);
	wlen += pin_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret)
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
	else
		sw = 0xFF00 | ret;
	
	return sw;
}

/********************************************************************
* Function: generate random num
* Input Parameter:
* in_len: the dest length of random num
* Output Parameter:
* out_buf: the return data buffer
* Return: SW
*********************************************************************/
uint16_t GetChallenge(uint16_t in_len, uint8_t *out_buf)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x00\x84\x00\x00\x02",wlen);
	wbuf[4] = in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		memmove(out_buf, rbuf, in_len);
	}else{
		sw = 0xFF00 | ret;
		memset(out_buf,0,in_len);
	}
	
	return sw;
}

/********************************************************************
* Function: generate RSA key pair
* Input Parameter:
* p1p2: key type and data block flag and RSA type
* Fid: the Fid that save the dest RSA Key Pair
       input 4Bytes Fid format: public key fid + private key fid
       single 2Bytes Fid format:high byte + low byte
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t GenRSAKeyPair(uint16_t p1p2, uint32_t Fid, uint8_t *rbuf, uint16_t *rlen)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char inbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x52\x00\x00\x08",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	inbuf[0] = 0xc0;
	inbuf[1] = 0x02;
	inbuf[2] = Fid>>24;
	inbuf[3] = Fid>>16;
	inbuf[4] = 0xc2;
	inbuf[5] = 0x02;
	inbuf[6] = Fid>>8;
	inbuf[7] = Fid;
	memmove(wbuf+5, inbuf, 8);
	wlen += 8;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, rlen, WAIT_SE_LTIMEOUT);

	if(!ret)
		sw = rbuf[*rlen-2]<<8 | rbuf[*rlen-1];
	else
		sw = 0xFF00 | ret;
	
	return sw;
}

/********************************************************************
* Function: write binary file
* Input Parameter:
* sfi: file start position to read
* inlen: file length to read
* inbuf: input data buffer
* Output Parameter:
* rbuf: the return data buffer
* rlen: the return data length
* Return: SW
*********************************************************************/
uint16_t WriteBinary(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x00\xd6\x00\x00\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
	}else{
		sw = 0xFF00 | ret;
	}
	
	return sw;
}

/********************************************************************
* Function: read binary file
* Input Parameter:
* p1p2: file start position to read
* in_len: file length to read
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t ReadBinary(uint16_t p1p2, uint16_t in_len, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x00\xb0\x00\x00\x86",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: RSA public key calculate
* Input Parameter:
* p1p2: key type and data block flag and RSA type
* in_len: file length to read
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t RSAPubKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x76\x40\x00\x87",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: RSA private key calculate
* Input Parameter:
* p1p2: key type and data block flag and RSA type
* in_len: file length to read
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t RSAPriKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memcpy(wbuf,"\x80\x58\x40\x00\x87",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memcpy(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: generate SM2 key pair
* Input Parameter:
* p1p2: key type and data block flag and SM2 type
* Fid: the Fid that save the dest SM2 Key Pair
       input 4Bytes Fid format: public key fid + private key fid
       single 2Bytes Fid format:high byte + low byte
* Output Parameter:none
* Return: SW
*********************************************************************/
uint16_t GenSM2KeyPair(uint32_t Fid, uint8_t *rbuf, uint16_t *rlen)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char inbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x50\x00\x00\x08",wlen);
	inbuf[0] = 0xc0;
	inbuf[1] = 0x02;
	inbuf[2] = Fid>>24;
	inbuf[3] = Fid>>16;
	inbuf[4] = 0xc2;
	inbuf[5] = 0x02;
	inbuf[6] = Fid>>8;
	inbuf[7] = Fid;
	memmove(wbuf+5, inbuf, 8);
	wlen += 8;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, rlen, WAIT_SE_TIMEOUT);

	if(!ret)
		sw = rbuf[*rlen-2]<<8 | rbuf[*rlen-1];
	else
		sw = 0xFF00 | ret;
	
	return sw;
}

/********************************************************************
* Function: SM2 public key calculate
* Input Parameter:
* p1p2: key type and data block flag and SM2 type
* in_len: file length to read
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t SM2PubKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x5c\x00\x00\x14",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen+=in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: SM2 public key calculate (more block function)
* Input Parameter:
* p1p2: key type and data block flag and SM2 type
* inlen: file length to read
* inbuf: input data buffer
* sig_len: input signature length.
* sm2_sig: input signature data.
* Output Parameter:
* rbuf: the return data buffer
* rlen: the return data length
* Return: SW
*********************************************************************/
uint16_t SM2PubKeyCalEx(uint16_t inlen, uint8_t *inbuf, uint16_t remianmsglen, uint8_t *remianmsg, uint16_t sig_len, uint8_t *sm2_sig, uint8_t *rbuf, uint16_t *rlen)
{
    uint16_t SW;
    uint16_t framelen = 0;

    uint8_t buf[255];

    //首包
    SW = SM2PubKeyCal(0x0102, inlen, inbuf, rbuf, rlen);

    if (SW != 0x9000)
    {
        printf("SM2PubKeyCal_head_sw1=%x!\r\n",SW);
        return SW;
    }

    while ( remianmsglen > 0 )
    {
        if (remianmsglen > 251)
        {
            framelen = 251;
            remianmsglen -= 251;
        }
        else
        {
            framelen = remianmsglen;
        }
        buf[0] = 0xC1;
        buf[1] = 0x82;
        buf[2] = 0x00;
        buf[3] = framelen;
        memcpy( buf+4, remianmsg, framelen);
        remianmsg += framelen;
        framelen += 4;
        SW = SM2PubKeyCal(0x0202, framelen, buf, rbuf, rlen);
        if (SW != 0x9000)
        {
            printf("SM2PubKeyCal_body_sw1=%x!\r\n",SW);
            return SW;
        }

        if (framelen < 255)
            break;

    }

    //尾包
    buf[0] = 0xC1;
    buf[1] = 0x82;
    buf[2] = 0x00;
    buf[3] = sig_len;
    memcpy( buf+4, sm2_sig, sig_len);
    SW = SM2PubKeyCal(0x0302, sig_len+4, buf, rbuf, rlen);

    printf("SM2PriKeyCal_tail_sw1=%x!\r\n",SW);

    return SW;
}

/********************************************************************
* Function: SM2 private key calculate
* Input Parameter:
* p1p2: key type and data block flag and SM2 type
* in_len: file length to read
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t SM2PriKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x6e\x00\x00\x75",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: SM2 private key calculate (more block function)
* Input Parameter:
* inlen: file length to read
* inbuf: input data buffer
* remianmsglen: the length of remain message
* remianmsg: the buffer of remain message
* Output Parameter:
* rbuf: the return data buffer
* rlen: the return data length
* Return: SW
*********************************************************************/
uint16_t SM2PriKeyCalEx(uint16_t inlen, uint8_t *inbuf, uint16_t remianmsglen, uint8_t *remianmsg, uint8_t *rbuf, uint16_t *rlen)
{
    uint16_t SW;
    uint8_t buf[255];

    if ( remianmsglen == 0 )
    {
        SW = SM2PriKeyCal(0x0002, inlen, inbuf, rbuf, rlen);
    }
    else
    {
        //首包
        SW = SM2PriKeyCal(0x0102, inlen, inbuf, rbuf, rlen);

        if (SW != 0x9000)
        {
            printf("SM2PriKeyCal_head_sw1=%x!\r\n",SW);
            return SW;
        }

        while ( remianmsglen > 251 )
        {
            buf[0] = 0xC1;
            buf[1] = 0x82;
            buf[2] = 0x00;
            buf[3] = 251;
            memcpy( buf+4, remianmsg, 251);
            SW = SM2PriKeyCal(0x0202, 255, buf, rbuf, rlen);
            if (SW != 0x9000)
            {
                printf("SM2PriKeyCal_body_sw1=%x!\r\n",SW);
                return SW;
            }

            remianmsglen -= 251;
            remianmsg += 251;
        }

        //尾包
        buf[0] = 0xC1;
        buf[1] = 0x82;
        buf[2] = 0x00;
        buf[3] = remianmsglen;
        memcpy( buf+4, remianmsg, remianmsglen);
        SW = SM2PriKeyCal(0x0302, remianmsglen+4, buf, rbuf, rlen);
    }

    printf("SM2PriKeyCal_tail_sw1=%x!\r\n",SW);

	return SW;
}

/********************************************************************
* Function: generate ECC key pair
* Input Parameter:
* p1p2: key type and data block flag and ECC type
* Fid: the Fid that save the dest ECC Key Pair
       input 4Bytes Fid format: public key fid + private key fid
       single 2Bytes Fid format:high byte + low byte
* Output Parameter:none
* Return: SW
*********************************************************************/
uint16_t GenECCKeyPair(uint32_t Fid, uint8_t *rbuf, uint16_t *rlen)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char inbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x30\x0D\x00\x08",wlen);
	inbuf[0] = 0xC0;
	inbuf[1] = 0x02;
	inbuf[2] = Fid>>24;
	inbuf[3] = Fid>>16;
	inbuf[4] = 0xC2;
	inbuf[5] = 0x02;
	inbuf[6] = Fid>>8;
	inbuf[7] = Fid;
	memmove(wbuf+5, inbuf, 8);
	wlen += 8;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, rlen, WAIT_SE_TIMEOUT);

	if(!ret)
		sw = rbuf[*rlen-2]<<8 | rbuf[*rlen-1];
	else
		sw = 0xFF00 | ret;
	
	return sw;
}

/********************************************************************
* Function: ECC public key calculate
* Input Parameter:
* p1p2: key type and data block flag and ECC type
* in_len: file length to read
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t ECCPubKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x3C\x0D\x01\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen+=in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: ECC private key calculate
* Input Parameter:
* p1p2: key type and data block flag and ECC type
* in_len: file length to read
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t ECCPriKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x3E\x0D\x01\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: import session key
* Input Parameter:
* p1p2: key type and data block flag and type
* in_len: file length to read
* in_buf: input session key buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t ImportSessionKey(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x5a\x01\x10\x12",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: data encrypt and decrypt
* Input Parameter:
* p1p2: key type and data block flag and type
* in_len: file length to read
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t DataEnDecrypt(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen = 5;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wbuf[0] = 0x80;
	wbuf[1] = 0xda;
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: import SM2 key
* Input Parameter:
* p1p2: key type and data block flag and SM2 type
* in_len: SM2 key length
* in_buf: input SM2 key buffer
* Output Parameter: none
* Return: SW
*********************************************************************/
uint16_t ImportSM2Key(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\xd2\x00\x00\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
	}else{
		sw = 0xFF00 | ret;
	}
	
	return sw;
}

/********************************************************************
* Function: Data Compress
* Input Parameter:
* p1p2: key type and data block flag and type
* in_len: data length
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t DataCompress(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\xe4\x00\x03\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += wbuf[4];
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: import RSA key
* Input Parameter:
* p1p2: key type and data block flag and RSA type
* inlen: rsa key length
* inbuf: input rsa key buffer
* Output Parameter: none
* Return: SW
*********************************************************************/
uint16_t InstallRSAKey(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\xe6\x00\x00\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
	}else{
		sw = 0xFF00 | ret;
	}
	
	return sw;
}

/********************************************************************
* Function: calculate SM2 session key
* Input Parameter:
* p1p2: key type and data block flag
* inlen: sm2 key length
* inbuf: input sm2 key buffer
* Output Parameter:
* rbuf: the return data buffer
* rlen: the return data length
* Return: SW
*********************************************************************/
uint16_t CalcSM2SessionKey(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\xea\x00\x03\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += wbuf[4];
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: calculate ECC session key
* Input Parameter:
* p1p2: key type and data block flag
* inlen: ecc key length
* inbuf: input ecc key buffer
* Output Parameter:
* rbuf: the return data buffer
* rlen: the return data length
* Return: SW
*********************************************************************/
uint16_t ECDH(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x39\x00\x03\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += wbuf[4];
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}
/********************************************************************
* Function: select AID
* Input Parameter:
* aid    : input aid data
* aid_len: input aid length
* Output Parameter:
* rbuf: the return data buffer
* rlen: the return data length
* Return: SW
*********************************************************************/
uint16_t SelectAID(uint8_t *aid,uint16_t aid_len,uint8_t *rbuf,uint16_t *rlen)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x00\xA4\x04\x00\x00",wlen);
	wbuf[4] = aid_len;
	memmove(wbuf+5, aid, aid_len);
	wlen += wbuf[4];
	dump_data(wlen,wbuf);
    // wbuf = 00,a4,04,00,0c,54,65,6d,70,6f,72,61,72,79,2e,4d,46,
    // wlen = 17
	ret = se_transceive(wbuf, wlen, rbuf, rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[*rlen-2]<<8 | rbuf[*rlen-1];
		*rlen = *rlen-2;
	}else{
		sw = 0xFF00 | ret;
		*rlen = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: get se uid
* rbuf: the return data buffer
* rlen: the return data length
* Return: SW
*********************************************************************/
uint16_t GetUID(uint8_t *rbuf, uint16_t *rlen)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\xCA\xFF\x80\x08",wlen);
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[*rlen-2]<<8 | rbuf[*rlen-1];
		*rlen = *rlen-2;
	}else{
		sw = 0xFF00 | ret;
		*rlen = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: generate ED25519 key pair
* Input Parameter:
* p1p2: key type and data block flag and RSA type
* Fid: the Fid that save the dest ED25519 Key Pair
       input 4Bytes Fid format: public key fid + private key fid
       single 2Bytes Fid format:high byte + low byte
* Output Parameter:none
* Return: SW
*********************************************************************/
uint16_t ED25519_GenKeyPair(uint32_t Fid, uint8_t *rbuf, uint16_t *rlen)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char inbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x27\x00\x00\x08",wlen);
	inbuf[0] = 0xc0;
	inbuf[1] = 0x02;
	inbuf[2] = Fid>>24;
	inbuf[3] = Fid>>16;
	inbuf[4] = 0xc2;
	inbuf[5] = 0x02;
	inbuf[6] = Fid>>8;
	inbuf[7] = Fid;
	memmove(wbuf+5, inbuf, 8);
	wlen += 8;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, rlen, WAIT_SE_TIMEOUT);

	if(!ret)
		sw = rbuf[*rlen-2]<<8 | rbuf[*rlen-1];
	else
		sw = 0xFF00 | ret;
	
	return sw;
}

/********************************************************************
* Function: import ED25519 key
* Input Parameter:
* p1p2: key type and data block flag and ED25519 type
* in_len: ED25519 key length
* in_buf: input ED25519 key buffer
* Output Parameter: none
* Return: SW
*********************************************************************/
uint16_t ED25519_ImportKey(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x26\x00\x00\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
	}else{
		sw = 0xFF00 | ret;
	}
	
	return sw;
}

/********************************************************************
* Function: ED25519 public key calculate
* Input Parameter:
* p1p2: key type and data block flag and ED25519 type
* in_len: file length to read
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t ED25519_PubKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x29\x00\x00\x87",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: ED25519 private key calculate
* Input Parameter:
* p1p2: key type and data block flag and ED25519 type
* in_len: file length to read
* in_buf: input data buffer
* Output Parameter:
* out_buf: the return data buffer
* out_len: the return data length
* Return: SW
*********************************************************************/
uint16_t ED25519_PriKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\x28\x00\x00\x87",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}

/********************************************************************
* Function: extern authentication
* Input Parameter:
* inlen: file length to read
* inbuf: input data buffer
* Output Parameter:
* Return: SW
*********************************************************************/
uint16_t ExternAuth(uint16_t in_len, uint8_t *in_buf)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memcpy(wbuf,"\x00\x82\x00\x00\x10",wlen);
	/*wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;*/
	memcpy(wbuf+5, in_buf, in_len);
	wlen += in_len;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
	}else{
		sw = 0xFF00 | ret;
	}
	
	return sw;
}
/********************************************************************
* Function: Init For Encrypt
* Input Parameter:
* p1p2: option
* Output Parameter:
* Return: SW
*********************************************************************/
uint16_t InitForEncrypt(uint16_t p1p2)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memcpy(wbuf,"\x80\x1A\x00\x00\x00",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
	}else{
		sw = 0xFF00 | ret;
	}
	
	return sw;
}
/********************************************************************
* Function: Des Encrypt
* Input Parameter:
* p1p2: option
* inlen: file length to read
* inbuf: input data buffer
* Output Parameter:
* rbuf: the return data buffer
* rlen: the return data length
* Return: SW
*********************************************************************/
uint16_t DesEncrypt(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len)
{
	unsigned char wbuf[CMD_BUF_SIZE];
	unsigned char rbuf[CMD_BUF_SIZE];
	uint16_t wlen;
	uint16_t rlen;
	uint8_t ret;
	uint16_t sw;
	
	wlen = 5;
	memmove(wbuf,"\x80\xFB\x00\x00\x20",wlen);
	wbuf[2] = p1p2>>8;
	wbuf[3] = p1p2;
	wbuf[4] = in_len;
	memmove(wbuf+5, in_buf, in_len);
	wlen += wbuf[4];
	dump_data(wlen,wbuf);
	ret = se_transceive(wbuf, wlen, rbuf, &rlen, WAIT_SE_TIMEOUT);

	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		*out_len = rlen-2;
		memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		*out_len = 0;
	}
	
	return sw;
}
/**
* @brife WriteKey2 with MAC
*/
uint16_t WriteKey2(uint8_t type, uint8_t ver, uint8_t id, uint16_t inlen, uint8_t *inbuf)
{
	uint8_t rbuf[256];
	uint16_t rlen;
	uint8_t cmd[5] = {0x84,0xD4,0x00,0x00,0x00};
	unsigned char key[16] = {0x99,0xF3,0xF0,0x40,0xF1,0xB6,0x54,0x1A,0x05,0x25,0x53,0x1A,0xF8,0x5B,0x1B,0x07};
    unsigned char rnd[4];
	unsigned char outbuf[260];
	int ret;
	uint16_t sw;
	uint8_t sbuf[256];

	sbuf[0] = type;
	sbuf[1] = ver;
	sbuf[2] = id;
	memcpy(rnd,inbuf+16,4);
	inlen -= 4;
	memcpy(sbuf+3,inbuf,inlen);
	//sm4_mac3Calc(cmd,inlen,inbuf,key,rnd,outbuf);
	ret = DES3_mac3Calc(cmd,inlen+3,sbuf,key,rnd,outbuf);
	
	//dump_data(ret,outbuf);
	ret = se_transceive(outbuf,ret,rbuf,&rlen,WAIT_SE_TIMEOUT);
	if(!ret){
		sw = rbuf[rlen-2]<<8 | rbuf[rlen-1];
		//*out_len = rlen-2;
		//memmove(out_buf, rbuf, *out_len);
	}else{
		sw = 0xFF00 | ret;
		//*out_len = 0;
	}
	
	return sw;
}

/****************** SE SDK API ********************/
/*
 @brief
 param list:
 rbuf   : read uid data
 rlen   : read uid data length
*/
uint8_t get_uid(uint8_t *rbuf, uint16_t *rlen)
{
	uint16_t sw;
	uint16_t tlen;
	uint8_t tbuf[256];
	//54656D706F726172792E4D46
	uint8_t aid[12]={0x54,0x65,0x6d,0x70,\
					 0x6f,0x72,0x61,0x72,\
					 0x79,0x2e,0x4d,0x46};
	sw = SelectAID(aid,12,tbuf,&tlen);
	if(sw != 0x9000)
		return 1;
	sw = GetUID(tbuf,&tlen);
	if(sw != 0x9000)
		return 2;
	*rlen = tlen;
	memcpy(rbuf,tbuf,*rlen);
	return 0;
}

//key pairs fmt:N+E+D
uint8_t importKeyPairs(const uint8_t *key,uint8_t type,uint16_t p_len,uint16_t pub_Fid,uint16_t pri_Fid)
{
    uint16_t sw;
    uint8_t buf[300];
	uint16_t i,ofs;

	ofs = 0;
	if(type == TYPE_RSA){
	if(p_len != 900)//0x384
		return 2;
	//N
    buf[0]=0xc0;
    buf[1]=0x02;
    buf[2]=pub_Fid>>8;
    buf[3]=pub_Fid;
    buf[4]=0xc3;
    buf[5]=0x82;
    buf[6]=0x01;
    buf[7]=0x00;
    memcpy(buf+8,key,0x100);
	ofs=ofs+0x100;
    sw=InstallRSAKey(0x2301,0x88,buf);
    if(sw!=0x9000)
        return 3;
    sw=InstallRSAKey(0x6301,0x80,buf+0x88);
    if(sw!=0x9000)
        return 4;
	//E
	buf[0]=0xc0;
    buf[1]=0x02;
    buf[2]=pub_Fid>>8;
    buf[3]=pub_Fid;
    buf[4]=0xc9;
    buf[5]=0x04;
    memcpy(buf+6,key+ofs,4);
	ofs=ofs+0x04;
	sw=InstallRSAKey(0x0301,0x0a,buf);
    if(sw!=0x9000)
        return 5;
	for(i=0;i<5;i++){
		buf[0]=0xc2;
		buf[1]=0x02;
		buf[2]=pri_Fid>>8;
		buf[3]=pri_Fid;
		buf[4]=0xc4+i;
		buf[5]=0x81;
		buf[6]=0x80;
		memcpy(buf+7,key+ofs,0x80);
		sw=InstallRSAKey(0x0301,0x87,buf);
		if(sw!=0x9000)
			return (6+i);
		ofs=ofs+0x80;
	}
	//E
	buf[0]=0xc2;
    buf[1]=0x02;
    buf[2]=pri_Fid>>8;
    buf[3]=pri_Fid;
    buf[4]=0xc9;
    buf[5]=0x04;
    memcpy(buf+6,key+0x100,4);
	sw=InstallRSAKey(0x0301,0x0a,buf);
    if(sw!=0x9000)
        return 11;
	}else if(type == TYPE_SM2){
		/* sm2 ... */
	}else if(type == TYPE_ED25519){
		if(p_len != 0x40)//pbk+prk
			return 2;
		//pub key
		buf[0]=0xc0;
		buf[1]=0x02;
		buf[2]=pub_Fid>>8;
		buf[3]=pub_Fid;
		buf[4]=0xca;
		buf[5]=0x20;
		memcpy(buf+6,key,0x20);
		ofs=ofs+0x20;
		sw = ED25519_ImportKey(0x4000,0x26,buf);
		if(sw!=0x9000)
			return 3;
		//pri key
		buf[0]=0xc2;
		buf[1]=0x02;
		buf[2]=pri_Fid>>8;
		buf[3]=pri_Fid;
		buf[4]=0xcb;
		buf[5]=0x20;
		memcpy(buf+6,key+ofs,0x20);
		ofs=ofs+0x100;
		sw = ED25519_ImportKey(0x4080,0x26,buf);
		if(sw!=0x9000)
			return 4;
	}
    return 0;
}

uint8_t exportPubKey(uint8_t *pubkey,uint16_t *p_len,uint16_t pub_Fid)
{
    uint16_t sw;
    uint8_t rbuf[300];
    uint16_t rlen;

	sw = SelectFile(pub_Fid, rbuf, &rlen);
	//printf("SelectFile:sw=%04x,rlen=%d\r\n",sw,rlen);
	
    sw=ReadBinary(0x0,0xe0,rbuf,&rlen);//224
    if(sw!=0x9000)
        return 1;
    sw=ReadBinary(0xe0,0x26,rbuf+0xe0,&rlen);//38
    if(sw!=0x9000)
        return 2;

    memcpy(pubkey,rbuf,0x106);
    *p_len = 0x106;

    return 0;
}

/**
  * @brief  sm2_verify_signature
  * @param  ida_len, input ida data length.
			sm2_ida, input ida data.
			msg_len, input message length.
			sm2_msg, input message.
			sig_len, input signature length.
			sm2_sig, input signature data.
			fid : sm2 public key fid!
  * @retval verify result, 0: success.
  */
uint8_t sm2_verify_sig(uint16_t fid,
						uint16_t ida_len, const uint8_t *sm2_ida, 
						uint16_t msg_len, const uint8_t *sm2_msg, 
						uint16_t sig_len, const uint8_t *sm2_sig)
{
    uint8_t wbuf[256];
    uint8_t rbuf[8];
    uint16_t wlen,rlen,sw;
    uint16_t remainlen = 0;
    uint16_t framelen = 0;

    rlen = ida_len + msg_len + sig_len;
    if(rlen > SE_BUFF_SIZE)
        return 1;

    if ( (msg_len + ida_len) > 0xF5 )
    {
        framelen = 0xF5 - ida_len;
        remainlen = msg_len - framelen;
    }
    else
    {
        framelen = msg_len;
    }

	//ida
	wbuf[0]=0xc2;
	wbuf[1]=ida_len;
	wlen=2;
	memcpy(wbuf+wlen,sm2_ida,ida_len);
	wlen+=ida_len;
	//msg
	wbuf[wlen++] = 0xC0;
    wbuf[wlen++] = 0x02;
    wbuf[wlen++] = fid>>8;
    wbuf[wlen++] = fid;
    wbuf[wlen++] = 0xC1;
    wbuf[wlen++] = 0x82;
    wbuf[wlen++] = 0x00;
    //wbuf[wlen++] = msg_len+sig_len;
    wbuf[wlen++] = framelen;
	memcpy(wbuf+wlen,sm2_msg,framelen);
    sm2_msg += framelen;
	wlen+=framelen;
	//memcpy(wbuf+wlen,sm2_sig,sig_len);
	//wlen+=sig_len;
	sw = SM2PubKeyCalEx(wlen, wbuf, remainlen, (uint8_t *)sm2_msg, sig_len, (uint8_t *)sm2_sig, rbuf, &rlen);
	printf("verify_sig_SM2PubKeyCal:sw=%x,rlen=%x!\r\n",sw,rlen);

	if(sw!=0x9000)
		return 2;
	
	return 0;
}

/**
  * @brief  sm2_signature
  * @param  ida_len, input ida data length.
			sm2_ida, input ida data.
			msg_len, input message length.
			sm2_msg, input message.
			p_sig_sz : output signature data length.
			sig : output signature data.
			fid : sm2 private key fid!
  * @retval verify result, 0: success.
  */
uint8_t sm2_signature(uint16_t fid,
				uint16_t ida_len, const uint8_t *sm2_ida,
				uint16_t msg_len, const uint8_t *sm2_msg,
				uint8_t *sig, uint16_t *p_sig_sz)
{
    uint16_t sw;
    uint16_t slen;
    uint8_t buf[256];
    uint16_t remainlen = 0;
    uint16_t framelen = 0;

    slen = ida_len + msg_len;
    if(slen > SE_BUFF_SIZE)
        return 1;

    if ( (msg_len + ida_len) > 0xF5 )
    {
        framelen = 0xF5 - ida_len;
        remainlen = msg_len - framelen;
    }
    else
    {
        framelen = msg_len;
    }

	buf[0]=0xc2;
	buf[1]=0x02;
	buf[2]=fid>>8;
	buf[3]=fid;
	buf[4]=0xc1;
	buf[5]=0x82;
	buf[6]=0x00;
	buf[7]=framelen;
	slen = 8;
	memcpy(buf+8,sm2_msg,framelen);
    sm2_msg += framelen;
	slen += framelen;
	buf[8+framelen]=0xc3;
	buf[9+framelen]=ida_len;
	slen += 2;
	memcpy(buf+10+framelen,sm2_ida,ida_len);
	slen += ida_len;

	sw = SM2PriKeyCalEx( slen, buf, remainlen, (uint8_t *)sm2_msg, sig, p_sig_sz);
	printf("SM2PriKeyCal_sw1=%x!\r\n",sw);
	if(sw!=0x9000){
		return 2;
	}
    return 0;
}

/**
  * @brief  rsa2048_verify_signature
  * @param  
			msg_len, input message length.
			rsa_msg, input message.
			sig_len, input signature length.
			rsa_sig, input signature data.
			fid : rsa public key fid!
  * @retval verify result, 0: success.
  */
uint8_t rsa2048_verify_sig(uint16_t fid,
						uint16_t msg_len, const uint8_t *rsa_msg, 
						uint16_t sig_len, const uint8_t *rsa_sig)
{
	uint8_t buf[300];
	uint8_t rbuf[300];
	uint16_t rlen,sw;

	if(msg_len!=256 || sig_len!=256)
		return 1;
	
	buf[0]=0xc0;
	buf[1]=0x02;
	buf[2]=fid>>8;
	buf[3]=fid;
	buf[4]=0xc1;
	buf[5]=0x82;
	buf[6]=0x01;
	buf[7]=0x00;
	memcpy(buf+8,rsa_sig,sig_len);
	
	sw = RSAPubKeyCal(0x4102,0x88,buf,rbuf,&rlen);
	printf("RSAPubKeyCal_sw1=%x!\r\n",sw);
	if(sw!=0x9000){
		return 2;
	}
	sw = RSAPubKeyCal(0x4302,0x80,buf+0x88,rbuf,&rlen);
	printf("RSAPubKeyCal_sw2=%x!\r\n",sw);
	if(sw!=0x9000){
		return 3;
	}

	if(memcmp(rbuf,rsa_msg,msg_len))
		return 4;
	
	return 0;
}


/**
  * @brief  rsa2048_signature
  * @param  
			msg_len, input message length.
			rsa_msg, input message.
			p_sig_sz : output signature data length.
			sig : output signature data.
			fid : rsa private key fid!
  * @retval verify result, 0: success.
  */
uint8_t rsa2048_signature(uint16_t fid,
				uint16_t msg_len, const uint8_t *rsa_msg,
				uint8_t *sig, uint16_t *p_sig_sz)
{
    uint16_t sw;
    uint8_t buf[300];

	if(msg_len!=256)
		return 1;

	buf[0]=0xc2;
	buf[1]=0x02;
	buf[2]=fid>>8;
	buf[3]=fid;
	buf[4]=0xc1;
	buf[5]=0x82;
	buf[6]=0x01;
	buf[7]=0x00;
	memcpy(buf+8,rsa_msg,msg_len);
   
	sw = RSAPriKeyCal(0x4102,0x88,buf,sig,p_sig_sz);
	printf("RSAPriKeyCal_sw1=%x!\r\n",sw);
	if(sw!=0x9000){
		return 2;
	}
	sw = RSAPriKeyCal(0x4302,0x80,buf+0x88,sig,p_sig_sz);
	printf("RSAPriKeyCal_sw2=%x!\r\n",sw);
	if(sw!=0x9000){
		return 3;
	}
	*p_sig_sz=256;
	
    return 0;
}

/*
 @brief
 param list:
 mode:  0:aes encrypt. 
		1:aes decrypt.
 inbuf: input data hex format
 inlen: input data length
 outbuf: output data hex format
 outlen: output data length
*/
uint8_t aes_calc(uint8_t mode,uint8_t *key,uint16_t keylen,uint8_t *inbuf,uint16_t inlen,uint8_t *outbuf,uint16_t *outlen)
{
    uint8_t sbuf[256],rbuf[8];
	uint16_t slen,rlen,sw;
    
	if(inlen<16||inlen>240)
		return 1;
	sbuf[0]=0xc1;
	sbuf[1]=keylen;
	memcpy(sbuf+2,key,keylen);
	slen=keylen+2;
	sw=ImportSessionKey(0x0710,slen,sbuf,rbuf,&rlen);
	if(sw!=0x9000){
		printf("ImportSessionKey sw : %x\n", sw);
		return 2;
	}
	memset(sbuf,0,4);
	sbuf[3]=rbuf[0];
	memcpy(sbuf+4,inbuf,inlen);
	slen=inlen+4;
	if(mode){
		sw=DataEnDecrypt(0x00c0,slen,sbuf,outbuf,outlen);
	}else{
		sw=DataEnDecrypt(0x0040,slen,sbuf,outbuf,outlen);
	}
	if(sw!=0x9000){
		printf("DataEnDecrypt sw : %x\n", sw);
		return 3;
	}
	return 0;
}

/*
 @brief
 param list:
 mode:  0:sm4 encrypt. 
		1:sm4 decrypt.
 inbuf: input data hex format
 inlen: input data length
 outbuf: output data hex format
 outlen: output data length
*/
uint8_t sm4_calc(uint8_t mode,uint8_t *key,uint8_t *inbuf,uint16_t inlen,uint8_t *outbuf,uint16_t *outlen)
{
	uint8_t sbuf[256],rbuf[256];
	uint16_t slen,rlen,sw;
	
	if(inlen<8||inlen>248)
		return 1;
	sbuf[0]=0xc1;
	sbuf[1]=0x10;
	memcpy(sbuf+2,key,0x10);
	slen=0x12;
	sw=ImportSessionKey(0x0210,slen,sbuf,rbuf,&rlen);    
	if(sw!=0x9000)
		return 2;
	memset(sbuf,0,4);
	sbuf[3]=rbuf[0];
	memcpy(sbuf+4,inbuf,inlen);
	slen=inlen+4;
	if(mode){
		sw=DataEnDecrypt(0x00c0,slen,sbuf,outbuf,outlen);
	}else{
		sw=DataEnDecrypt(0x0040,slen,sbuf,outbuf,outlen);
	}
	if(sw!=0x9000)
		return 3;
	return 0;
}

/*
 @brief
 param list:
 pin    : input pin data
 pbk_fid: input public key fid
 rbuf   : output public key data hex format
 rlen   : output public key data length
*/
uint8_t get_pub_key(uint8_t *pin, uint16_t pbk_fid, uint8_t *rbuf, uint16_t *rlen)
{
	uint16_t sw;

	//sel file df01
	sw = SelectFile(0xdf01, rbuf, rlen);
	if (sw != 0x9000)
	{
		return 0xef;
	}
	//verify pin
	sw = VerifyPIN(pin,3);
	if (sw != 0x9000)
	{
		return 0xee;
	}
	//export pub key
	sw = exportPubKey(rbuf, rlen, pbk_fid);
	if (sw)
	{
		return 0xed;
	}
	
	return 0;
}

/*
 @brief
 param list:
 mode   : extern key or internal key selcet,
 		eg. ECDH_EXTPBK_SM4 or ECDH_INTPBK_SM4 ...
 prk_fid: input private key fid
 pubkey : input public key data or fid
 rbuf   : output public key data hex format
 rlen   : output public key data length
*/
uint8_t ecdh_calc_key( uint16_t mode, uint16_t prk_fid, uint8_t *pubkey, uint8_t *rbuf, uint16_t *rlen)
{
	uint16_t sw;
	uint16_t slen = 0;
	uint8_t sbuf[256];

	sbuf[0] = 0xC2;
	sbuf[1] = 0x02;
	sbuf[2] = prk_fid>>8;
	sbuf[3] = prk_fid&0xFF;
	if(mode&0x8000){
		sbuf[4] = 0xC1;
		sbuf[5] = 0x40;
		memmove(sbuf+slen,pubkey,0x40);
		slen = 0x46;
	}else{
		sbuf[4] = 0xC0;
		sbuf[5] = 0x02;
		sbuf[6] = pubkey[0];
		sbuf[7] = pubkey[1];
		slen = 8;
	}

	sw = ECDH(mode, slen, sbuf, rbuf, rlen);
	if (sw != 0x9000)
	{
		return 0xec;
	}

	return 0;
}

/*
 @brief
 param list:
 fid    : binary file fid
 ofs    : offset 
 inlen  : write length
 inbuf  : write data
*/
uint8_t write_bin(uint16_t fid, uint16_t ofs, uint16_t inlen, uint8_t *inbuf)
{
	uint16_t sw;
	uint16_t tlen;
	uint8_t tbuf[256];
	sw = SelectFile(fid,tbuf,&tlen);
	if(sw != 0x9000)
		return 1;
	tlen = inlen;
	memcpy(tbuf,inbuf,tlen);
	sw = WriteBinary(ofs,tlen,tbuf);
	if(sw != 0x9000)
		return 2;
	return 0;
}

/*
 @brief
 param list:
 fid    : binary file fid
 ofs    : offset 
 inlen  : read length
 rbuf   : read data
 rlen   : read data length
*/
uint8_t read_bin(uint16_t fid, uint16_t ofs, uint16_t inlen, uint8_t *rbuf, uint16_t *rlen)
{
	uint16_t sw;
	uint16_t tlen;
	uint8_t tbuf[256];
	sw = SelectFile(fid,tbuf,&tlen);
	if(sw != 0x9000)
		return 1;
	sw = ReadBinary(ofs,inlen,tbuf,&tlen);
	if(sw != 0x9000)
		return 2;
	*rlen = tlen-2;
	memcpy(rbuf,tbuf,*rlen);
	return 0;
}

//alg:1-SHA1,2-SHA256,3-SM3
uint8_t hash(uint8_t alg,uint8_t *ibuf,uint16_t ilen,uint8_t *obuf,uint16_t *olen)
{	
	uint16_t i,sw,p1p2,cnt,mod,ofs,slen,rlen;
	uint8_t rbuf[256];
	uint8_t sbuf[256]={0xc1,0};

	ofs = 0;
	if(ilen>255){
		cnt=ilen/255;
		mod=ilen%255;
		if(mod)cnt++;
		p1p2=alg;
		//0xc1xx+data!
		sw=DataCompress(p1p2,0xff,ibuf,obuf,olen);
		ilen-=0xff;
		cnt--;
		p1p2=0x0200|alg;
		for(i=0;i<cnt;i++){
			if(i==cnt-1)
				p1p2=0x0300|alg;
			ofs+=0xff*i;
			sw=DataCompress(p1p2,0xff,ibuf+ofs,obuf,olen);
			if(sw!=0x9000)break;
		}
	}else{
		p1p2=0x0100|alg;
		//0xc1xx+data!
		sbuf[0]=0xc1;
		sbuf[1]=ilen;
		memcpy(sbuf+2,ibuf,ilen);
		slen=ilen+2;
		sw=DataCompress(p1p2,slen,sbuf,rbuf,&rlen);
	}
	printf("DataCompress_sw=%x,rlen=%x\r\n",sw,rlen);
	if(sw!=0x9000)
		return 1;

	*olen=rlen;
	memcpy(obuf,rbuf,*olen);
	
	return 0;
}

/**
  * @brief  ed25519_verify_signature
  * @param  
			msg_len, input message length.
			msg, input message.
			sig_len, input signature length.
			sig, input signature data.
			fid : public key fid!
  * @retval verify result, 0: success.
  */
uint8_t ed25519_verify_sig(uint16_t fid,
						uint16_t msg_len, const uint8_t *msg, 
						uint16_t sig_len, const uint8_t *sig)
{
	uint8_t buf[300];
	uint8_t rbuf[300];
	uint16_t rlen,sw;

	/*if(msg_len!=256 || sig_len!=256)
		return 1;*/
	
	buf[0]=0xc0;
	buf[1]=0x02;
	buf[2]=fid>>8;
	buf[3]=fid;
	buf[4]=0xc1;
	buf[5]=0x82;
	//buf[6]=0x01;
	//buf[7]=0x00;
	buf[6]=0x00;
	buf[7]=sig_len;
	memcpy(buf+8,sig,sig_len);
	
	sw = ED25519_PubKeyCal(0x0000,sig_len+8,buf,rbuf,&rlen);
	printf("RSAPubKeyCal_sw1=%x!\r\n",sw);
	if(sw!=0x9000){
		return 2;
	}
	/*sw = ED25519_PubKeyCal(0x0003,0x80,buf+0x88,rbuf,&rlen);
	printf("RSAPubKeyCal_sw2=%x!\r\n",sw);
	if(sw!=0x9000){
		return 3;
	}*/
	
	return 0;
}

/**
  * @brief  ed25519_signature
  * @param  
			msg_len, input message length.
			msg, input message.
			p_sig_sz : output signature data length.
			sig : output signature data.
			fid : private key fid!
  * @retval verify result, 0: success.
  */
uint8_t ed25519_signature(uint16_t fid,
				uint16_t msg_len, const uint8_t *msg,
				uint8_t *sig, uint16_t *p_sig_sz)
{
    uint16_t sw;
    uint8_t buf[300];

	/*if(msg_len!=256)
		return 1;*/

	buf[0]=0xc2;
	buf[1]=0x02;
	buf[2]=fid>>8;
	buf[3]=fid;
	buf[4]=0xc1;
	buf[5]=0x82;
	//buf[6]=0x01;
	//buf[7]=0x00;
	buf[6]=0x00;
	buf[7]=msg_len;
	memcpy(buf+8,msg,msg_len);
   
	sw = ED25519_PriKeyCal(0x0000,msg_len+8,buf,sig,p_sig_sz);
	printf("RSAPriKeyCal_sw1=%x!\r\n",sw);
	if(sw!=0x9000){
		return 2;
	}
	/*sw = ED25519_PriKeyCal(0x0003,0x80,buf+0x88,sig,p_sig_sz);
	printf("RSAPriKeyCal_sw2=%x!\r\n",sw);
	if(sw!=0x9000){
		return 3;
	}
	*p_sig_sz=256;*/
	
    return 0;
}

/* 
* @brief mode:0-DES,1-SM4
*/
uint8_t ext_auth(uint8_t mode,uint8_t *key)
{
	uint8_t rnd[16];
    uint8_t tbuf[16]={0};
	uint16_t sw;
	//sm4_context ctx;
	int i;

	srand(255);
	for( i = 0 ; i < 16 ; i++ ) {
		tbuf[i] = rand();
	}
	sw=GetChallenge(8,rnd);
	if(sw!=0x9000)
		return 1;
	if(mode){
		/*sm4_setkey_enc(&ctx,key);
		memset(rnd+8,0,8);
    	sm4_crypt_ecb(&ctx,SM4_ENCRYPT,16,rnd,tbuf);
		sm4_setkey_enc(&ctx,tbuf);
		memset(tbuf,0,16);
    	sm4_crypt_ecb(&ctx,SM4_ENCRYPT,16,tbuf,rnd);
		memcpy(tbuf,rnd,16);
		for(i=0;i<8;i++){
			rnd[i] = tbuf[i]^tbuf[i+8];
		}*/
		memset(tbuf,0,16);
	}else{
	    //des3_ecb_encrypt(tbuf,rnd,8,key,16);
		DES3(key,rnd,tbuf,0);
	    //des_ecb_encrypt(rnd,tbuf+8,8,tbuf);
		DES(tbuf,tbuf+8,rnd,0);
	}
    memcpy(tbuf,rnd,8);
	sw=ExternAuth(16,tbuf);
	printf("ExternAuth_sw=%x\r\n",sw);
	if(sw!=0x9000)
		return 2;
	return 0;
}
