//算法所在的网址：http://www.adultedu.tj.cn/~dzsw/learn/D6Z3J.htm
//IP置换
//IP置换规则数据

#ifndef __FMSE_DES_H__
#define __FMSE_DES_H__

#define DES_ENCRYPT 0
#define DES_DECRYPT 1
extern void DES(unsigned char *key, unsigned char *data_in, unsigned char *data_out, int mode);
extern void DES3(unsigned char *key, unsigned char *data_in, unsigned char *data_out, int mode);
extern int DES3_MAC( unsigned char *MACKEY, unsigned char *InitData,int SourDataLen, unsigned char *SourData,unsigned char *MACData);
extern int TripleDES(char DESType, unsigned char *TripleDESKey, int SourDataLen, unsigned char *SourceData, unsigned char *DestData, unsigned char *DestDataLen);
extern int DES3_mac3Calc( unsigned char *cmdHead,unsigned int inBufLen,unsigned char *inBuf,unsigned char *key,unsigned char *random,unsigned char *outBuf );
#endif
