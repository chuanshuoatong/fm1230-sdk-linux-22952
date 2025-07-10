
#ifndef __SE_CMD_H__
#define __SE_CMD_H__

#include <stdint.h>
#include <stdio.h>

//param define
#define FILE_ID_11			0x0A010A91
#define FILE_ID_22			0x0A020A92
#define PRI_FID_01			0x0A91
#define PUB_FID_01			0x0A01
#define PRI_FID_02			0x0A92
#define PUB_FID_02			0x0A02

#define FILE_ID_88			0x00080998
#define PUB_FID_08			0x0008
#define PRI_FID_08			0x0998

#define FILE_ID_99			0x00090999
#define PUB_FID_09			0x0009
#define PRI_FID_09			0x0999

#define SHA1			1
#define SHA256			2
#define SM3				3

#define PKCS1			0
#define PKCS8			1

#define EXT_AUTH_DES	0
#define EXT_AUTH_SM4	1

//ECDH
#define ECDH_EXTPBK_SM4		0x8D02
#define ECDH_INTPBK_SM4		0x0D02

//key pairs type
#define TYPE_RSA		0
#define TYPE_SM2		1
#define TYPE_ED25519	2

#define RSA1024			0x0000
#define RSA1280			0x0100
#define RSA2048			0x0200

//ECC
#define SECG_P256		0x0D
#define X962_P256		0x0D
#define P256_SHA256		(0x0D01)

//APDU
#define APDU_MAX_LEN		(0xFF)
#define SE_BUFF_SIZE		(2303)
#define CMD_BUF_SIZE		(260)
#define MAX_BUFF_SIZE		(2377)

//SE CMD
uint16_t SelectFile(uint16_t fid, uint8_t *out_buf, uint16_t *out_len);
uint16_t VerifyPIN(uint8_t *pin, uint16_t pin_len);
uint16_t GetChallenge(uint16_t in_len, uint8_t *out_buf);
uint16_t GenRSAKeyPair(uint16_t p1p2, uint32_t Fid, uint8_t *rbuf, uint16_t *rlen);
uint16_t WriteBinary(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf);
uint16_t ReadBinary(uint16_t p1p2, uint16_t in_len, uint8_t *out_buf, uint16_t *out_len);
uint16_t RSAPubKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t RSAPriKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t GenSM2KeyPair(uint32_t Fid, uint8_t *rbuf, uint16_t *rlen);
uint16_t SM2PubKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t SM2PriKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t GenECCKeyPair(uint32_t Fid, uint8_t *rbuf, uint16_t *rlen);
uint16_t ECCPubKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t ECCPriKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t ImportSessionKey(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t DataEnDecrypt(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t ImportSM2Key(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf);
uint16_t DataCompress(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t InstallRSAKey(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf);
uint16_t CalcSM2SessionKey(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t ECDH(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t ED25519_ImportKey(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf);
uint16_t ED25519_PubKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t ED25519_PriKeyCal(uint16_t p1p2, uint16_t in_len, uint8_t *in_buf, uint8_t *out_buf, uint16_t *out_len);
uint16_t ED25519_GenKeyPair(uint32_t Fid, uint8_t *rbuf, uint16_t *rlen);
uint16_t ExternAuth(uint16_t in_len, uint8_t *in_buf);
uint16_t WriteKey2(uint8_t type, uint8_t ver, uint8_t id, uint16_t inlen, uint8_t *inbuf);


//user API
/*
* key : private key & public key data
* type : key pairs type
* p_len : key pairs length
* pub_Fid : public key fid
* pri_Fid : private key fid
*/
uint8_t importKeyPairs(const uint8_t *key,uint8_t type,uint16_t p_len,uint16_t pub_Fid,uint16_t pri_Fid);
uint8_t exportPubKey(uint8_t *pubkey,uint16_t *p_len,uint16_t pub_Fid);
uint8_t sm2_verify_sig(uint16_t fid,
						uint16_t ida_len, const uint8_t *sm2_ida, 
						uint16_t msg_len, const uint8_t *sm2_msg, 
						uint16_t sig_len, const uint8_t *sm2_sig);
uint8_t sm2_signature(uint16_t fid,
				uint16_t ida_len, const uint8_t *sm2_ida,
				uint16_t msg_len, const uint8_t *sm2_msg,
				uint8_t *sig, uint16_t *p_sig_sz);
uint8_t rsa2048_verify_sig(uint16_t fid,
						uint16_t msg_len, const uint8_t *rsa_msg, 
						uint16_t sig_len, const uint8_t *rsa_sig);
uint8_t rsa2048_signature(uint16_t fid,
				uint16_t msg_len, const uint8_t *rsa_msg,
				uint8_t *sig, uint16_t *p_sig_sz);
uint8_t aes_calc(uint8_t mode,uint8_t *key,uint16_t keylen,uint8_t *inbuf,uint16_t inlen,uint8_t *outbuf,uint16_t *outlen);
uint8_t sm4_calc(uint8_t mode,uint8_t *key,uint8_t *inbuf,uint16_t inlen,uint8_t *outbuf,uint16_t *outlen);
uint8_t get_pub_key(uint8_t *pin, uint16_t pbk_fid, uint8_t *rbuf, uint16_t *rlen);
uint8_t ecdh_calc_key( uint16_t mode, uint16_t prk_fid, uint8_t *pubkey, uint8_t *rbuf, uint16_t *rlen);
uint8_t write_bin(uint16_t fid, uint16_t ofs, uint16_t inlen, uint8_t *inbuf);
uint8_t read_bin(uint16_t fid, uint16_t ofs, uint16_t inlen, uint8_t *rbuf, uint16_t *rlen);
uint8_t hash(uint8_t alg,uint8_t *ibuf,uint16_t ilen,uint8_t *obuf,uint16_t *olen);

uint16_t SelectAID(uint8_t *aid,uint16_t aid_len,uint8_t *rbuf,uint16_t *rlen);
uint16_t GetUID(uint8_t *rbuf, uint16_t *rlen);

uint8_t get_uid(uint8_t *rbuf, uint16_t *rlen);

/*
* fid : key fid
* msg_len : message length
* msg : message data
* sig_len : signature length
* sig : signature data
*/
uint8_t ed25519_verify_sig(uint16_t fid,
						uint16_t msg_len, const uint8_t *msg, 
						uint16_t sig_len, const uint8_t *sig);

/*
* fid : key fid
* msg_len : message length
* msg : message data
* sig : signature data
* p_sig_sz : signature length
*/						
uint8_t ed25519_signature(uint16_t fid,
				uint16_t msg_len, const uint8_t *msg,
				uint8_t *sig, uint16_t *p_sig_sz);

#endif


