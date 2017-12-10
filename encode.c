#include "openssl-1.1.0g/include/openssl/aes.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define max_size 500

int file_size(FILE * fp)  
{  
    if(!fp) return -1;  
    fseek(fp,0L,SEEK_END);  
    int size=ftell(fp);  
    fclose(fp);  
    return size;  
}  

unsigned char* str2hex(char *str) {
    unsigned char *ret = NULL;
    int str_len = strlen(str);
    int i = 0;
    assert((str_len%2) == 0);
    ret = (char *)malloc(str_len/2);
    for (i =0;i < str_len; i = i+2 ) {
        sscanf(str+i,"%2hhx",&ret[i/2]);
    }
    return ret;
}
char *padding_buf(char *buf,int size, int *final_size) {
    char *ret = NULL;
    int pidding_size = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
    int i;
    *final_size = size + pidding_size;
    ret = (char *)malloc(size+pidding_size);
    memcpy( ret, buf, size);
    if (pidding_size!=0) {
        for (i =size;i < (size+pidding_size); i++ ) {
            ret[i] = 0;
        }
    }
    return ret;
}
void printf_buff(char *buff,int size) {
    int i = 0;
    for (i=0;i<size;i ++ ) {
        printf( "%02X ", (unsigned char)buff[i] );
        if ((i+1) % 8 == 0) {
            printf("\n");
        }
    }
    printf("\n\n\n\n");
}

void get_str(char *buff,int size){
    int i = 0;
    for (i=0;i<size;i ++ ) {
        printf( "%02X ", (unsigned char)buff[i] );
        if ((i+1) % 8 == 0) {
            printf("\n");
        }
    }
}

void encrpyt_buf(char *raw_buf, char **encrpy_buf, int len ) {
    AES_KEY aes;
    unsigned char *key = str2hex("8cc72b05705d5c46f412af8cbed55aad");
    unsigned char *iv = str2hex("667b02a85c61c786def4521b060265e8");
    AES_set_encrypt_key(key,128,&aes);
    AES_cbc_encrypt(raw_buf,*encrpy_buf,len,&aes,iv,AES_ENCRYPT);
    free(key);
    free(iv);
}
void decrpyt_buf(char *raw_buf, char **encrpy_buf, int len ) {
    AES_KEY aes;
    unsigned char *key = str2hex("8cc72b05705d5c46f412af8cbed55aad");
    unsigned char *iv = str2hex("667b02a85c61c786def4521b060265e8");
    AES_set_decrypt_key(key,128,&aes);
    AES_cbc_encrypt(raw_buf,*encrpy_buf,len,&aes,iv,AES_DECRYPT);
    free(key);
    free(iv);
}
int main(int argn, char *argv[] ) {
    char *raw_buf = NULL;
    char *after_padding_buf = NULL;
    int padding_size = 0;
    char *encrypt_buf = NULL;
    char *decrypt_buf = NULL;
    char str[max_size] = "0";
    int i;
    // 1
    FILE * f,*f1;
    FILE * f2,* f3;
    int size = 0;
    f = fopen("test.zip","rb+");
    size = file_size(f);

    f1 = fopen("test.zip","rb+");
    printf("\n%d\n",size);
    fread(str,sizeof(char),size,f1);
    printf("%s\n",str);
    raw_buf = (char *)malloc(sizeof(str));
    //memcpy(raw_buf,"life's a struggle",17);
    //printf("------------------raw_buf\n");
    //printf_buff(str,sizeof(str));
    // 2
    after_padding_buf = padding_buf(str,max_size,&padding_size);
    //printf("\n%d\n",padding_size);
    //printf("------------------after_padding_buf\n"); #扩展位数
    //printf_buff(after_padding_buf,padding_size);
    // 3
    encrypt_buf = (char *)malloc(padding_size);
    encrpyt_buf(after_padding_buf,&encrypt_buf, padding_size);
    f2 = fopen("test2.zip","w+");
    //fwrite(encrpyt_buf,sizeof(char),padding_size,f2);
    //fprintf(f2,"%s",encrypt_buf);
    for(i=0;i<padding_size;i++)
      fputc(encrypt_buf[i],f2);
    fclose(f2);
    printf("------------------encrypt_buf\n");
    printf_buff(encrypt_buf,padding_size);
    printf("\n%s\n",encrypt_buf);
    fclose(f1);
    free(raw_buf);
    free(after_padding_buf);
    free(encrypt_buf);
    return 0;
}
