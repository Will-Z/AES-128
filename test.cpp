#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

// Enable both ECB and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DECB=1
#define CBC 1
#define ECB 1

#include "aes.h"

static void phex(uint8_t* str);
static void test_encrypt_ecb(void);
static void test_decrypt_ecb(uint8_t Aset[][16]);
static void test_encrypt_ecb_verbose(void);
static void test_encrypt_cbc(void);
static void test_decrypt_cbc(void);
static void create_Aset(int num);
static void create_equation_set();

uint8_t Aset[256][16];
int SS[256];
bool Eq[2048][2049];

int main(void)
{
    //test_encrypt_cbc();
    //test_decrypt_cbc();

    //test_encrypt_ecb();
    //test_decrypt_ecb();

    for (int i = 0; i < 256; i++) {
        FILE *fout;

        create_Aset(i);      //生成A-set
        //printf("%d : ", i);
        test_decrypt_ecb(Aset);
        fout = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/pi.txt", "a");
        fprintf(fout, "\n");
        fclose(fout);
    }  //256*256 pi    "pi.txt"

    create_equation_set();
  

    return 0;
}

static void create_equation_set() {
    FILE *fin;
    int num;
    fin = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/pi.txt", "r");
    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 256; j++) {
            fscanf(fin, "%d", &num);
            for (int k = 0; k < 8; k++) {
                if (num & (1 << k))
                    Eq[i * 8 + k][num * 8 + k] = 1;
                else
                    Eq[i * 8 + k][num * 8 + k] = 0;
            }
        }
    for (int i = 0; i < 2048; i++)
        Eq[i][2049] = 0;
    fclose(fin);

    int n = 2048, q0 = 0, q1 = 0, p = 0, x, temp;
    bool res[2048];

    memset(res, 0, sizeof(bool) * 2048);

    for (int i = 0; i < n; i++) {   // i枚举n个未知数
        x = -1;
        for (int j = p; j < n; j++)
            if (Eq[j][i]) {
                x = j;
                break;
            }
        if (x >= 0) {
            if (x != p) {
                for (int k = i; k <= n; k++) {   //两行交换
                    temp = Eq[x][k];
                    Eq[x][k] = Eq[p][k];
                    Eq[p][k] = temp;
                }
            }
            for (int j = p + 1; j < n; j++)
                if (Eq[j][i])
                    for (int k = i; k <= n; k++)
                        Eq[j][k] ^= Eq[p][k];
            p++;
        } else {                    //遇到自由元
            res[i] = 1;             //定为1
            for (int j = 0; j < p; j++)   //找到前面xi系数为1的方程 全部带入xi值XOR掉
                if (Eq[j][i]) {
                    Eq[j][i] = 0;
                    Eq[j][n] ^= 1;
                }
        }
    }
    p--;
    for (int i = n - 1; i >= 0; i--) {
        if (!res[i]) {
            res[i] = Eq[p][n];
            for (int j = 0; j < p; j++)
                if (Eq[j][i]) {
                    Eq[j][i] ^= Eq[p][i];
                    Eq[j][n] ^= Eq[p][n];
                }
            p--;
        }
    }

    /*
    FILE *fout;
    fout = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/res.txt", "w");
    for (int i = 0; i <2048; i++)
        fprintf(fout, "x%d = %d\n", i, res[i]);
    fclose(fout);
    */

    int point = 0;
    for (int i = 0; i < 256; i++) {
        int num = 0;
        for (int j = 0; j < 8; j++)
            num += res[i * 8 + j] * pow(2, 7 - j);
        SS[i] = num;
    }


}


static void create_Aset(int num) {
    memset(Aset[0], 0, sizeof(Aset[0]));
    Aset[0][1] = (uint8_t) num;
    for (int i = 1; i < 256; i++) {
        memset(Aset[i], 0, sizeof(Aset[i]));
        Aset[i][0] = Aset[i - 1] [0] + 1;
        Aset[i][1] = (uint8_t) num;
    }

}



// prints string as hex
static void phex(uint8_t* str)
{
    unsigned char i;
    for(i = 0; i < 16; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

static void test_encrypt_ecb_verbose(void)
{
    // Example of more verbose verification

    uint8_t i, buf[16], buf2[16];

    // 128bit key
    uint8_t key[16] =        { (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16, (uint8_t) 0x28, (uint8_t) 0xae, (uint8_t) 0xd2, (uint8_t) 0xa6, (uint8_t) 0xab, (uint8_t) 0xf7, (uint8_t) 0x15, (uint8_t) 0x88, (uint8_t) 0x09, (uint8_t) 0xcf, (uint8_t) 0x4f, (uint8_t) 0x3c };
    // 512bit text
    uint8_t plain_text[16] = { (uint8_t) 0x6b, (uint8_t) 0xc1, (uint8_t) 0xbe, (uint8_t) 0xe2, (uint8_t) 0x2e, (uint8_t) 0x40, (uint8_t) 0x9f, (uint8_t) 0x96, (uint8_t) 0xe9, (uint8_t) 0x3d, (uint8_t) 0x7e, (uint8_t) 0x11, (uint8_t) 0x73, (uint8_t) 0x93, (uint8_t) 0x17, (uint8_t) 0x2a};

    memset(buf, 0, 16);
    memset(buf2, 0, 16);

    // print text to encrypt, key and IV
    printf("ECB encrypt verbose:\n\n");
    printf("plain text:\n");
    phex(plain_text);
    printf("\n");

    printf("key:\n");
    phex(key);
    printf("\n");

    // print the resulting cipher as 4 x 16 byte strings
    printf("ciphertext:\n");
    AES128_ECB_encrypt(plain_text, key, buf);
    phex(buf);
    printf("\n");
}


static void test_encrypt_ecb(void)
{
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t in[]  = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t out[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
    uint8_t buffer[16];

    AES128_ECB_encrypt(in, key, buffer);

    printf("ECB encrypt: \n");
    printf("plain_text:\n");
    phex(in);
    printf("\n\n");
    printf("cipher_text:\n");
    phex(buffer);
    printf("--------------------------------------------------------------------------------\n");


    /*

    if(0 == strncmp((char*) out, (char*) buffer, 16))
    {
        printf("SUCCESS!\n");
    }
    else
    {
        printf("FAILURE!\n");
    }
    */
}


static void test_decrypt_ecb(uint8_t Aset[][16])
{
    uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t in[16];
    uint8_t out[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
    uint8_t buffer[16];

    for(int i = 0; i < 256; i++) {
        AES128_ECB_decrypt(Aset[i], key, buffer);
    }

    /*
    AES128_ECB_decrypt(cipher, key, buffer);

    printf("ECB decrypt: ");
    printf("cipher_text:\n");
    phex(in);
    printf("\n\n");
    printf("plain_text:\n");
    phex(buffer);
    printf("--------------------------------------------------------------------------------\n");

    */
}


