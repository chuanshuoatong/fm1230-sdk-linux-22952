
//demo.c
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fmse_drv.h"
#include "fmse_cmd.h"
#include "fmse_demo.h"

static unsigned char read_id_only = 0;

/*********************** se test ********************************/
static uint8_t sm2_msg[12] = {
	0x12,0x34,0x56,0x12,0x34,0x56,0x12,0x34,0x56,0x12,0x34,0x56
	};
static uint8_t sm2_ida[16] = {
	0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38
	};
static uint8_t pin[3] = {0x11,0x22,0x33};
static uint8_t sm2_sig[256];
static uint16_t sm2_sig_len;
static uint8_t sm2_msg_ex[2048];
/************************************************************************/
int aes_demo(void)
{
	uint16_t sw = 0;
	unsigned char wbuf[256];
	unsigned char rbuf[256];
	uint16_t rlen;
	int ret;
	
	memset(wbuf, 0, sizeof(wbuf));
	memset(rbuf, 0, sizeof(rbuf));
	
	sw = SelectFile(0xDF01, rbuf, &rlen);
	if (sw != 0x9000){
		printf("SelectFile SW : %x\r\n",sw);
		return 0xFD;
	}

	sw = VerifyPIN(pin,3);
	if (sw != 0x9000){
		printf("VerifyPIN SW : %x\r\n",sw);
		return 0xFC;
	}
	
	printf("AES test:\r\n");
	memset(wbuf, 0x55, 0x10);	//test plain
	//aes encrypt
	ret = aes_calc(0, wbuf, 0x10, wbuf, 16, rbuf, &rlen);
	if(ret) printf("aes_calc: %d\r\n",ret);
	dump_data(rlen, rbuf);
	//aes decrypt
	ret = aes_calc(1, wbuf, 0x10, rbuf, 16, rbuf, &rlen);
	if(ret) printf("aes_calc: %d\r\n",ret);
	dump_data(rlen, rbuf);
	
	if(memcmp(rbuf,wbuf,0x10))
		printf("AES encrypt & decrypt test fail\n");
	else
		printf("AES encrypt & decrypt test success\n");
	
	return ret;
}

/*
 * FMSE binary file read & write demo
 * @param NONE
*/
uint8_t se_file_demo(void)
{
	uint16_t sw = 0;
	uint16_t rlen = 0;
	uint8_t rbuf[0x100];
	uint8_t inbuf[0x100];
	int i;
	int ofs;
	#define WR_FID		0x0A01

	printf("FMSE binary file read & write demo:\n");
	
	/* se file read write test flow */
	sw = SelectFile(0xDF01, rbuf, &rlen);
	if (sw != 0x9000){
		printf("SelectFile SW : %x\r\n",sw);
		return 0xFD;
	}

	sw = VerifyPIN(pin,3);
	if (sw != 0x9000){
		printf("VerifyPIN SW : %x\r\n",sw);
		return 0xFC;
	}

	sw = SelectFile(WR_FID, rbuf, &rlen);
	if (sw != 0x9000){
		printf("SelectFile SW : %x\r\n",sw);
		return 0xFB;
	}

	memset(inbuf, 0x5A, 0x100);
	ofs = 0;
	for(i=0;i<2;i++){
		sw = WriteBinary(ofs, 0x80, inbuf+ofs);
		if (sw != 0x9000){
			printf("WriteBinary SW : %x\r\n",sw);
			return 0xFA;
		}
		ofs += 0x80;
	}
	
	memset(rbuf, 0, 0x100);
	ofs = 0;
	for(i=0;i<2;i++){
		sw = ReadBinary(ofs, 0x80, rbuf+ofs, &rlen);
		if (sw != 0x9000){
			printf("ReadBinary SW : %x\r\n",sw);
			return 0xF9;
		}
		ofs += 0x80;
	}
	
	dump_data(0x100, rbuf);
	
	if(memcmp(inbuf,rbuf,0x100))
		printf("Read & Write Binary 256Bytes fail\n");
	else
		printf("Read & Write Binary 256Bytes success\n");
	
	return 0;
}

int rsa2048_demo(void)
{
	uint16_t sw = 0;
	int ret;
	uint16_t rlen;
	uint8_t rbuf[270];
	uint8_t inbuf[270];
	
	sw = SelectFile(0xDF01, rbuf, &rlen);
	if (sw != 0x9000){
		printf("SelectFile SW : %x\r\n",sw);
		return 0xFD;
	}

	sw = VerifyPIN(pin,3);
	if (sw != 0x9000){
		printf("VerifyPIN SW : %x\r\n",sw);
		return 0xFC;
	}
	
	//gen rsa2048 key pair
	sw = GenRSAKeyPair(RSA2048, FILE_ID_11, rbuf, &rlen);
	printf("GenRSAKeyPair:sw=%04x\r\n", sw);
	if(sw != 0x9000) goto _test_fail;
	ret = SelectFile(PUB_FID_01,rbuf,&rlen);
	if (ret != 0x9000)
	{
		printf("SelectFile ret = %x!\n\r", ret);
		return ret;
	}
	//key len:256+6=262
	sw = ReadBinary(0, 0xE0, rbuf, &rlen);
	printf("ReadBinary:sw=%04x,rlen=%x\r\n", sw, rlen);
	if(sw != 0x9000) goto _test_fail;
	memcpy(inbuf, rbuf, 0xe0);
	sw = ReadBinary(0x00E0, 0x26, rbuf, &rlen);
	printf("ReadBinary:sw=%04x,rlen=%x\r\n", sw, rlen);
	if(sw != 0x9000) goto _test_fail;
	memcpy(inbuf + 0xe0, rbuf, 0x26);
	/*SE RSA2048 PUB KEY Format:
	  Length(2B)+Key(256B)+Exp(4B)!!!*/
	printf("RSA2048 public key:\r\n");
	dump_data(262, inbuf);
	
	/* rsa signature/verify signature test! */
	//RSA PRI key calc_signature
	memcpy(inbuf, "\xc2\x02\x0A\x91\xc1\x82\x01\x00", 8);
	memset(inbuf+8, 0x55, 0x80);	//test plain head
	sw = RSAPriKeyCal(0x4102, 0x88, inbuf, rbuf, &rlen);
	printf("RSAPriKeyCal:sw=%04x,rlen=%d\r\n", sw, rlen);
	if(sw != 0x9000) goto _test_fail;
	memset(inbuf, 0x55, 0x80);	//test plain tail
	sw = RSAPriKeyCal(0x4302, 0x80, inbuf, rbuf, &rlen);
	printf("RSAPriKeyCal2:sw=%04x,rlen=%d\r\n", sw, rlen);
	printf("RSA PRI key calc_signature\n");
	dump_data(rlen, rbuf);
	if(sw != 0x9000) goto _test_fail;
	//RSA PUB key calc_verify
	memset(inbuf, 0, sizeof(inbuf));
	memcpy(inbuf, "\xc0\x02\x0A\x01\xc1\x82\x01\x00", 8);
	memcpy(inbuf+8, rbuf, 0x80);	//input sig head
	sw = RSAPubKeyCal(0x4102, 0x88, inbuf, rbuf, &rlen);
	printf("RSAPubKeyCal:sw=%04x,rlen=%d\r\n", sw, rlen);
	if(sw != 0x9000) goto _test_fail;
	memcpy(inbuf, rbuf+0x80, 0x80);	//input sig tail
	sw = RSAPubKeyCal(0x4302, 0x80, inbuf, rbuf, &rlen);
	printf("RSAPubKeyCal2:sw=%04x,rlen=%d\r\n", sw, rlen);
	printf("RSA PUB key calc_verify\n");
	dump_data(rlen, rbuf);
	if(sw != 0x9000) goto _test_fail;
	
	printf("RSA2048 signature & verify success\n");
	
	return 0;
	
_test_fail:
	printf("rsa2048_demo err\n");
	return 1;
}

/*
sm2 demo:
get_uid
gen_sm2_keypairs
get sm2 pubk
sm2 sig
sm2 verify
*/
int sm2_demo(void)
{
	uint16_t sw = 0;
	uint16_t rlen = 0;
	uint8_t rbuf[512];
	int ret;
	int i;
	for(i=0;i<sizeof(sm2_msg_ex);i++){
		sm2_msg_ex[i] = i;
	}
	
	//get devid
	se_get_devid(rbuf, &rlen);
	printf("devid_rlen=%d,device_id:\n",rlen);
	dump_data(rlen,rbuf);

    if (read_id_only)
        return 0;

	ret = get_uid(rbuf,&rlen);
	printf("get_uid:%d\n",ret);
	dump_data(rlen, rbuf);
	
	sw = SelectFile(0xDF01, rbuf, &rlen);
	if (sw != 0x9000){
		printf("SelectFile SW : %x\r\n",sw);
		return 0xFD;
	}
	sw = VerifyPIN(pin,3);
	if (sw != 0x9000){
		printf("VerifyPIN SW : %x\r\n",sw);
		return 0xFC;
	}
	sw = GenSM2KeyPair(FILE_ID_22, rbuf, &rlen);
	if(sw != 0x9000) return sw;
	printf("GenSM2KeyPair:sw=%04x\r\n", sw);
	//key len:64=0x40
	sw = ReadBinary(0, 0x40, rbuf, &rlen);
	if(sw != 0x9000) return sw;
	printf("ReadBinary:sw=%04x,rlen=%d\r\n", sw, rlen);
	printf("SE SM2 public key:\r\n");
	dump_data(rlen, rbuf);
	
	printf("****************************************************\n");
	ret=sm2_signature(PRI_FID_02,sizeof(sm2_ida),sm2_ida,
					sizeof(sm2_msg),sm2_msg,rbuf,&rlen);
	printf("sm2_signature_ret=%x,rlen=%d\r\n",ret,rlen);
	if(!ret){
		dump_data(rlen,rbuf);
		memcpy(sm2_sig,rbuf,rlen);
		sm2_sig_len = rlen;
	}
	ret=sm2_verify_sig(PUB_FID_02,sizeof(sm2_ida),sm2_ida,
					sizeof(sm2_msg),sm2_msg,sm2_sig_len,sm2_sig);
	printf("sm2_verify_sig_ret=%x\r\n",ret);
	
	if(!ret)
		printf("sm2 signature & verify success\n");
	else
		printf("sm2 signature & verify fail\n");
	
	printf("****************************************************\n");
	printf("start long message sm2 signature & verify demo\n");
	ret=sm2_signature(PRI_FID_02,sizeof(sm2_ida),sm2_ida,
						sizeof(sm2_msg_ex),sm2_msg_ex,rbuf,&rlen);
	printf("sm2_signature_ret = %x,rlen = %d\r\n", ret, rlen);
	if(!ret){
		dump_data(rlen,rbuf);
		memcpy(sm2_sig,rbuf,rlen);
		sm2_sig_len = rlen;
	}
	ret=sm2_verify_sig(PUB_FID_02,sizeof(sm2_ida),sm2_ida,
						sizeof(sm2_msg_ex),sm2_msg_ex,sm2_sig_len,sm2_sig);
	printf("sm2_verify_sig_ret = %x\r\n", ret);
	
	if(!ret)
		printf("long message sm2 signature & verify success\n");
	else
		printf("long message sm2 signature_ex & verify fail\n");
	
	printf("****************************************************\n");
	return ret;
}

int ecc_demo(void)
{
	uint16_t sw = 0;
	uint16_t rlen = 0;
	uint8_t rbuf[512];
	int ret;
	uint8_t msg[8]={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
	uint8_t hbuf[128];
	uint16_t hlen;
	uint8_t sig[128];
	uint16_t sig_len;
	
	sw = SelectFile(0xDF01, rbuf, &rlen);
	if (sw != 0x9000){
		printf("SelectFile SW : %x\r\n",sw);
		return 0xFD;
	}
	sw = VerifyPIN(pin,3);
	if (sw != 0x9000){
		printf("VerifyPIN SW : %x\r\n",sw);
		return 0xFC;
	}
	sw = GenECCKeyPair(FILE_ID_11, rbuf, &rlen);
	if(sw != 0x9000) return sw;
	printf("GenECCKeyPair:sw=%04x\r\n", sw);
	//key len:64=0x40
	sw = ReadBinary(0, 0x40, rbuf, &rlen);
	if(sw != 0x9000) return sw;
	printf("ReadBinary:sw=%04x,rlen=%d\r\n", sw, rlen);
	printf("SE ECC public key:\r\n");
	dump_data(rlen, rbuf);
	
	//hash SHA256
	ret = hash(SHA256,msg,sizeof(msg),hbuf,&hlen);
	if(ret){
		printf("HASH ERR!\r\n");
		return 0xFB;
	}
	printf("HASH result len %d:\r\n",hlen);
	dump_data(hlen,hbuf);
	memcpy(rbuf,"\xC2\x02\x0A\x91\xC1\x82\x00\x20",8);
	memcpy(rbuf+8,hbuf,hlen);
	rbuf[7] = hlen;
	rlen = hlen+8;
	//ecc signature
	sw = ECCPriKeyCal(P256_SHA256,rlen,rbuf,sig,&sig_len);
	printf("ecc signature sw=%x,rlen=%x\r\n", sw, sig_len);
	if(sw!=0x9000){
		printf("ecc signature fail\n");
		return 0xFA;
	}
	printf("ECC signature result len %d:\r\n",sig_len);
	dump_data(sig_len,sig);
	//ecc verify
	memcpy(rbuf,"\xC0\x02\x0A\x01\xC1\x82\x00\x60",8);
	memcpy(rbuf+8,hbuf,hlen);
	memcpy(rbuf+8+hlen,sig,sig_len);
	rbuf[7] = hlen+sig_len;
	rlen = hlen+sig_len+8;
	sw = ECCPubKeyCal(P256_SHA256,rlen,rbuf,sig,&sig_len);
	printf("ecc verify sw=%x\r\n", sw);
	if(sw!=0x9000){
		printf("ecc verify fail\n");
		return 0xF9;
	}
	printf("ecc signature & verify success\n");
	return 0;
}

int ed25519_demo(void)
{
	int ret;
	uint16_t fid;
	uint8_t msg[12] = {0x12,0x34,0x56,0x12,0x34,0x56,
						0x12,0x34,0x56,0x12,0x34,0x56};
	uint16_t msg_len = 12;
	uint8_t res_buf[256];
	uint16_t res_len;
	uint8_t sig[256];
	uint16_t sig_sz;
	uint16_t keys_len = 0x40;
	uint8_t keys[0x40]={/* fmt : public key + private key */
		0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c,
		0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb
	};
	//99F3F040F1B6541A0525531AF85B1B07
	uint8_t auth_key[16]={0x99,0xF3,0xF0,0x40,0xF1,0xB6,0x54,0x1A,0x05,0x25,0x53,0x1A,0xF8,0x5B,0x1B,0x07};
	uint8_t sbuf[256];
	uint16_t slen;
	
	ret = VerifyPIN(pin,3);
	if (ret != 0x9000){
		printf("VerifyPIN SW : %x\r\n",ret);
		return 0xFC;
	}
	
	ret = ext_auth(EXT_AUTH_DES, auth_key);
	if (ret)
	{
		printf("ext_auth ret = %x!\n\r", ret);
		return ret;
	}
	
	/*ret = importKeyPairs(keys,TYPE_ED25519,keys_len,0x0008,0x0998);
	if (ret)
	{
		printf("importKeyPairs ret = %x!\n\r", ret);
		return ret;
	}*/
	
	ret = ED25519_GenKeyPair(FILE_ID_88,keys,&keys_len);
	if (ret != 0x9000)
	{
		printf("ED25519_GenKeyPair ret = %x!\n\r", ret);
		return ret;
	}
	ret = SelectFile(PUB_FID_08,keys,&keys_len);
	if (ret != 0x9000)
	{
		printf("SelectFile ret = %x!\n\r", ret);
		return ret;
	}
	ret = ReadBinary(0,0x20,keys,&keys_len);
	if (ret != 0x9000)
	{
		printf("ReadBinary ret = %x!\n\r", ret);
		return ret;
	}
	printf("PUB KEY:\n");
	dump_data(keys_len,keys);
	
	//SHA256
	sbuf[0] = 0xC0;
	sbuf[1] = 0x02;
	sbuf[2] = 0x00;
	sbuf[3] = 0x03;
	sbuf[4] = 0xC1;
	sbuf[5] = msg_len;
	memcpy(sbuf+6,msg,msg_len);
	slen = msg_len + 6;
	ret = DataCompress(0x8102,slen,sbuf,res_buf,&res_len);
	if (ret != 0x9000)
	{
		printf("SHA256 ret = %x!\n\r", ret);
		return ret;
	}
	printf("SHA256:\n");
	dump_data(res_len,res_buf);
	
	fid = PRI_FID_08;
	ret = ed25519_signature(fid,msg_len,msg,res_buf,&sig_sz);
	if (ret)
	{
		printf("ed25519_signature ret = %x!\n\r", ret);
		return ret;
	}
	printf("SIG:\n");
	dump_data(sig_sz,res_buf);
	
	memcpy(sig, msg, msg_len);
	memcpy(sig + msg_len, res_buf, sig_sz);
	sig_sz += msg_len;
	fid = PUB_FID_08;
	ret = ed25519_verify_sig(fid,msg_len,msg,sig_sz,sig);
	if (ret)
	{
		printf("ed25519_verify_sig ret = %x!\n\r", ret);
		return ret;
	}
	
	printf("ED25519 signature & verify success\n");
	
	return 0;
}

int cmac_demo(void)
{
	uint16_t sw = 0;
	int ret;
	uint8_t sbuf[256];
	uint16_t slen;
	uint8_t rbuf[256];
	uint16_t rlen;
	uint8_t tkey[20]={0x99,0xF3,0xF0,0x40,0xF1,0xB6,0x54,0x1A,0x05,0x25,0x53,0x1A,0xF8,0x5B,0x1B,0x07};
	uint8_t td[32]={0x99,0xF3,0xF0,0x40,0xF1,0xB6,0x54,0x1A,0x05,0x25,0x53,0x1A,0xF8,0x5B,0x1B,0x07,
				0x99,0xF3,0xF0,0x40,0xF1,0xB6,0x54,0x1A,0x05,0x25,0x53,0x1A,0xF8,0x5B,0x1B,0x07};
				
	#define KEY_TYPE	0x0B
	#define KEY_VER		0x00
	#define KEY_ID		0x07
	
	printf("CMAC calculate demo:\n");
	
	sw = SelectFile(0xDF01, rbuf, &rlen);
	if (sw != 0x9000){
		printf("SelectFile SW : %x\r\n",sw);
		return 0xFD;
	}

	sw = VerifyPIN(pin,3);
	if (sw != 0x9000){
		printf("VerifyPIN SW : %x\r\n",sw);
		return 0xFC;
	}
	
	ret = GetChallenge(4,rbuf);
	if (ret != 0x9000)
	{
		printf("GetChallenge ret = %x!\n\r", ret);
		return ret;
	}
	memcpy(tkey+16,rbuf,4);
	ret = WriteKey2(KEY_TYPE,KEY_VER,KEY_ID,20,tkey);
	if (ret != 0x9000)
	{
		printf("WriteKey2 ret = %x!\n\r", ret);
		return ret;
	}
	ret = InitForEncrypt(0x0B00);
	if (ret != 0x9000)
	{
		printf("InitForEncrypt ret = %x!\n\r", ret);
		return ret;
	}
	slen = 0x20;
	memcpy(sbuf,td,32);
	ret = DesEncrypt(0x1702,slen,sbuf,rbuf,&rlen);
	if (ret != 0x9000)
	{
		printf("DesEncrypt1 ret = %x!\n\r", ret);
		return ret;
	}
	ret = DesEncrypt(0x1302,slen,sbuf,rbuf,&rlen);
	if (ret != 0x9000)
	{
		printf("DesEncrypt2 ret = %x!\n\r", ret);
		return ret;
	}
	ret = DesEncrypt(0x1302,slen,sbuf,rbuf,&rlen);
	if (ret != 0x9000)
	{
		printf("DesEncrypt3 ret = %x!\n\r", ret);
		return ret;
	}
	ret = DesEncrypt(0x1102,slen,sbuf,rbuf,&rlen);
	if (ret != 0x9000)
	{
		printf("DesEncrypt4 ret = %x!\n\r", ret);
		return ret;
	}
	printf("CMAC result:\n");
	dump_data(rlen,rbuf);
}

/********************* DEMO TEST ENTRY **********************************/
int main(int argc, char *argv[])
{
	int ret;
    char dev_name[32] = {0};

    if (argc < 2) {
        printf("Usage: se_demo /dev/spidevX.Y [-id]\n");
        printf("       -id: read chip id only\n");
        return 0;
    }

    if (argv[2] != NULL && (strcmp(argv[2], "-id") == 0))
        read_id_only = 1;

    strncpy(dev_name, argv[1], sizeof("/dev/spidevX.Y"));
	
	ret = fmse_open(dev_name);
	if (ret < 0){
		printf("open %s fail\n", dev_name);
		return -1;
	}
	
#ifdef SM2_DEMO_TEST
	sm2_demo();
#endif
#ifdef ECC_DEMO_TEST
	ecc_demo();
#endif
#ifdef RSA2048_DEMO_TEST
	rsa2048_demo();
#endif
#ifdef AES_DEMO_TEST
	aes_demo();
#endif
#ifdef FILE_RW_DEMO_TEST
	se_file_demo();
#endif
#ifdef CMAC_DEMO_TEST
	cmac_demo();
#endif
#ifdef ED25519_DEMO_TEST
	ed25519_demo();
#endif

	fmse_close();
	
	return 0;
}

