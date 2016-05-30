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
static void calc_SS();
static void calc_kk();
static int affine(int num);
static void calc_DD();
static void calc_M32();         //计算 32*32的 M矩阵
static void read_M32();
static void calc_AM();          //计算 A逆
static bool judgeR(int x[32]);

uint8_t Aset[256][16];
int v[8] = {0, 1, 0, 1, 0, 1, 1, 1};
int SS[256];                 //S'
int kk[16];                  //k'
bool Eq[2048][2049];         //方程系数矩阵
int A[8][8];                //仿射矩阵
int AM[8][8];               //A的逆
uint8_t plain_text[256][16]; // 明文
int DD[256][4];              //D'
int M[32][32];              //32*32的 M矩阵
static const uint8_t sbox[256] =   {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

int main(void)
{
    //test_encrypt_cbc();
    //test_decrypt_cbc();

    //test_encrypt_ecb();
    //test_decrypt_ecb();



   //测试 affine()
    FILE *Ain;
    Ain = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/A.txt", "r");
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            fscanf(Ain, "%d", &A[i][j]);

    fclose(Ain);





/*//
    FILE *Aaffine_table;
    Aaffine_table = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/Aaffine_table.txt", "w");
    for (int i = 0; i < 256; i++)
        fprintf(Aaffine_table, "%d:   %d\n",i, affine(i));
    fclose(Aaffine_table);
*/



    // 生成SS
    for (int i = 0; i < 256; i++)
        SS[i] = affine(sbox[i ^ key[0]]);
        //SS[i] = sbox[i];  //  先假设  S' 等于 S盒




 /*   //  输出S'  SS[]
    FILE *SSout;
    SSout = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/SS_table.txt", "w");
    for (int i = 0; i < 256; i++)
        fprintf(SSout, "%d:  %d\n", i, SS[i]);
    fclose(SSout);

    FILE *AMin;
    AMin = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/AM.txt", "r");
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            fscanf(AMin, "%d", &A[i][j]);

    fclose(AMin);



    int SSS[256];
    for (int i = 0; i < 256; i++)
        SSS[i] = affine(SS[i ^ key[0]]);

    FILE *SSSout;
    SSSout = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/SSS_table.txt", "w");
    for (int i = 0; i < 256; i++)
        fprintf(SSout, "%d:   %d   %d  %d\n", i,sbox[i], SS[i], SSS[i]);
    fclose(SSSout);


*/

/*  //将 0-255 对应的affine 打印到 affine.txt
    FILE *Aout;
    Aout = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/affine.txt", "w");
    for (int i = 0; i < 256; i++)
        fprintf(Aout, "%d:  %d\n", i, affine(i));
    fclose(Aout);
*/

/*

    for (int i = 0; i < 256; i++) {
        FILE *fout;

        create_Aset(i);      //生成A-set
        //printf("%d : ", i);
        test_decrypt_ecb(Aset);
        fout = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/pi.txt", "a");
        fprintf(fout, "\n");
        fclose(fout);
    }  //256*256  明文第一个字节    "pi.txt"

    calc_SS();      //计算S'    SS[]

*/
/*
    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 16; j++)
            plain_text[i][j] = (int)affine(plain_text[i][j]);
*/



/*      //print plain_text
    FILE *ffout;
    ffout = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/plain_text.txt", "w");
    for(int i = 0; i < 256; i++) {
    //    fprintf(ffout, "%d:  ", i);
        for (int j = 0; j <16; j++)
            fprintf(ffout, "0x%.2x ",plain_text[i][j]);
        fprintf(ffout, "\n");
    }
    fclose(ffout);

*/
    //test_encrypt_ecb();

/*
    for (int i = 0; i < 16; i++)
        //kk[i] = -1;
        kk[i] = key[i];    //先假设  k'等于key
*/
    calc_kk();
/*   // 打印kk[]
    for (int i = 0; i < 16; i++)
        printf("%d:  %d   %d\n",i, key[i],  kk[i]);
    printf("\n");
/*

/*
    FILE *AMin;
    AMin = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/AM.txt", "r");
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            fscanf(AMin, "%d", &A[i][j]);

    fclose(AMin);
*/
/*
    FILE *AMaffine_table;
    AMaffine_table = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/AMaffine_table.txt", "w");
    for (int i = 0; i < 256; i++)
        fprintf(AMaffine_table, "%d:   %d\n",i, affine(i));
    fclose(AMaffine_table);
*/

/*  //----------------------------------------------------------


    create_Aset(0);    //  // 使用第二个位置是 num_Aset 的这个 Aset
    for (int i = 0; i < 256; i++)
        AES128_ECB_decrypt(Aset[i], key, plain_text[i]);
    calc_DD();
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < 4; j++) {
            DD[i][j] = affine(DD[i][j]);
        }
    }

    uint8_t matrix[16];
    uint8_t output[16];

    for (int i = 0; i <256; i++) {
        for (int j = 0; j < 16; j++)
            matrix[j] = 0x00;
        for (int j = 0; j < 4; j++)
            matrix[j] =(uint8_t) DD[i][j];
        test_DD(matrix, key, output);
    }
*///---------------------------------------------------------------



    calc_AM();
    // 打印AM[]
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++)
            printf("%d ", AM[i][j]);
        printf("\n");
    }


    //------------------------------------------
    /*
    int ans_key[16];
    int ans_sbox[256];

    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            A[i][j] = AM[i][j];

    for (int k = 0; k < 256; k++) {
        int count = 0;
        for (int i = 0; i < 256; i++)
            if (affine(SS[i]) == sbox[i ^ k])
                count++;
        if (count == 256)
            ans_key[0] = k;
    }
    for (int i = 1; i < 16; i++)
        ans_key[i] = kk[i] ^ ans_key[0];


    for (int i = 0; i < 256; i++)
        ans_sbox[i ^ ans_key[0]] = affine(SS[i]);
    for (int i = 0; i < 256; i++)
        printf("%d:   %.2x\n", i, ans_sbox[i]);

*/
    //------------------------------------------
    return 0;
}

static bool judgeR(int x[32]) {
    int count = 0;  //统计 1 的个数
    for (int i = 0; i < 256; i++) {

        int y[32];                          //将DD 化成32比特的形式存在y[]中
        for (int l = 0; l < 4; l++) {
           // printf("%d ", DD[i][l]);
            for (int k = 0; k < 8; k++) {
                if (DD[i][l] & (1 << k))      //低位在前
                    y[7 - k + l * 8] = 1;
                else
                    y[7 - k + l * 8] = 0;
            }
        }
//        for (int j = 0; j < 32; j++)
//            printf("%d ",y[j]);
//        printf("\n");
        //printf("\n");
//        printf("%d:   ", i);
//        for (int j = 0; j < 32; j++)
//            printf("%d ", y[j]);
//        printf("\n");
        int sum = 0;
        for (int j = 0; j < 32; j++)
            //sum ^= x[j] ^ y[j];
            if (x[j])
                sum ^= y[j];
        if (sum)
            count++;
    }
    if (count == 128)   // 0 和 1 各有  128个  符合  R性质
        return true;
    else
        return false;

}

//======================================================================================================================
static void calc_AM() {
    int count[256];
    memset(count, 0, sizeof(int) * 256);

/*   //将DD打印到DD.txt
    FILE *DDout;
    DDout = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/DD.txt", "w");
    for (int i = 0; i < 256; i++) {
        //fprintf(DDout, "%d:  ", i);
        for (int j = 0; j < 4; j++)
            fprintf(DDout, "%d ", DD[i][j]);
        fprintf(DDout, "\n");
    }
    fclose(DDout);
*/

    for (int i = 0; i < 8; i++)    //将 AM[0] 固定为  1000 0000
        AM[0][i] = 0;
    AM[0][7] = 1;



    for (int i = 1; i < 8; i++)
        for (int j = 0; j < 8; j++)
            AM[i][j] = -1;




    int x[32];
    int a[8];
//------------------------------------------------------------------------------- 计算 AM[1] (a1, a0^a1, a0, a0)
    //printf("<%d>----------------------\n", 1);
    for (int num_Aset = 0; num_Aset < 256; num_Aset++) {

        create_Aset(num_Aset);    //  // 使用第二个位置是 num_Aset 的这个 Aset
        for (int i = 0; i < 256; i++)
            AES128_ECB_decrypt(Aset[i], key, plain_text[i]);
        calc_DD();


        for (int i = 16; i <= 23; i++)
            x[i] = AM[0][i - 16];
        for (int i = 24; i <= 31; i++)
            x[i] = AM[0][i - 24];
        for (int num = 0; num < 256; num++) {              //枚举 2^8
            for (int k = 0; k < 8; k++) {
                if (num & (1 << k))                       //低位数在前
                    a[7 - k] = 1;
                else
                    a[7 - k] = 0;
            }
         for (int k = 0; k < 8; k++)
                x[k] = a[k];
            for (int k = 8; k <= 15; k++)
                x[k] = a[k - 8] ^ AM[0][k - 8];
            if (judgeR(x))
                count[num]++;

        }
    }
    for (int i = 0; i < 256; i++)
        if (count[i] == 256) {
            for (int j = 0; j < 8; j++)
                if (i & (1 << j))
                    AM[1][7 - j] = 1;
                else
                    AM[1][7 - j] = 0;
        }
 //    for (int i = 0; i < 8; i++)
//        printf("%d ",AM[1][i]);

//--------------------------------------------------------------------------------计算AM[2] (a2, a1^a2, a1, a1)

    //printf("<%d>----------------------\n", 2);
    // 先假定 AM[1] 0100 0000
//    for (int i = 0; i < 8; i++)
//        AM[1][i] = 0;
//    AM[1][1] = 1;
    memset(count, 0, sizeof(int) * 256);


    for (int num_Aset = 0; num_Aset < 256; num_Aset++) {

        create_Aset(num_Aset);    //  // 使用第二个位置是 num_Aset 的这个 Aset
        for (int i = 0; i < 256; i++)
            AES128_ECB_decrypt(Aset[i], key, plain_text[i]);
        calc_DD();

        for (int i = 16; i <= 23; i++)
            x[i] = AM[1][i - 16];
        for (int i = 24; i <= 31; i++)
            x[i] = AM[1][i - 24];

        for (int num = 0; num < 256; num++) {
            for (int k = 0; k < 8; k++) {
                if (num & (1 << k))
                    a[7 - k] = 1;
                else
                    a[7 - k] = 0;
            }
            for (int k = 0; k < 8; k++)
                x[k] = a[k];
            for (int k = 8; k <= 15; k++)
                x[k] = a[k - 8] ^ AM[1][k - 8];

            if (judgeR(x))
                count[num]++;

        }
    }
    for (int i = 0; i < 256; i++)
        if (count[i] == 256) {
            for (int j = 0; j < 8; j++)
                if (i & (1 << j))
                    AM[2][7 - j] = 1;
                else
                    AM[2][7 - j] = 0;
        }

//    for (int i = 0; i < 8; i++)
//        printf("%d ", AM[2][i]);

//-----------------------------------------------------------------------------计算AM[3] (a3, a2^a3, a2, a2)
    // 先假定 AM[2] 0010 0000
//    for (int i = 0; i < 8; i++)
//        AM[2][i] = 0;
//    AM[2][2] = 1;

    memset(count, 0, sizeof(int) * 256);

    for (int num_Aset = 0; num_Aset < 256; num_Aset++) {
        create_Aset(num_Aset);    //  // 使用第二个位置是 num_Aset 的这个 Aset
        for (int i = 0; i < 256; i++)
            AES128_ECB_decrypt(Aset[i], key, plain_text[i]);
        calc_DD();

        for (int i = 16; i <= 23; i++)
            x[i] = AM[2][i - 16];
        for (int i = 24; i <= 31; i++)
            x[i] = AM[2][i - 24];

        for (int num = 0; num < 256; num++) {
            for (int k = 0; k < 8; k++) {
                if (num & (1 << k))
                    a[7 - k] = 1;
                else
                    a[7 - k] = 0;
            }
            for (int k = 0; k < 8; k++)
                x[k] = a[k];
            for (int k = 8; k <= 15; k++)
                x[k] = a[k - 8] ^ AM[2][k - 8];

            if (judgeR(x))
                count[num]++;
        }
    }
    for (int i = 0; i < 256; i++)
        if (count[i] == 256) {

            for (int j = 0; j < 8; j++)
                if (i & (1 << j))
                    AM[3][7 - j] = 1;
                else
                    AM[3][7 - j] = 0;
        }


//    for (int i = 0; i < 8; i++)
//        printf("%d ",AM[3][i]);

//---------------------------------------------------------------------------计算AM[4] (a0^a4, a0^a3^a4, a3, a3)
   // 先假定 AM[3] 0001 0000
//    for (int i = 0; i < 8; i++)
//        AM[3][i] = 0;
//    AM[3][3] = 1;

    memset(count, 0, sizeof(int) * 256);

    for (int num_Aset = 0; num_Aset < 256; num_Aset++) {
        create_Aset(num_Aset);    //  // 使用第二个位置是 num_Aset 的这个 Aset
        for (int i = 0; i < 256; i++)
            AES128_ECB_decrypt(Aset[i], key, plain_text[i]);
        calc_DD();

        for (int i = 16; i <= 23; i++)
            x[i] = AM[3][i - 16];
        for (int i = 24; i <= 31; i++)
            x[i] = AM[3][i - 24];

        for (int num = 0; num < 256; num++) {
            for (int k = 0; k < 8; k++) {
                if (num & (1 << k))
                    a[7 - k] = 1;
                else
                    a[7 - k] = 0;
            }
            for (int k = 0; k < 8; k++)
                x[k] = a[k] ^ AM[0][k];
            for (int k = 8; k <= 15; k++)
                x[k] = a[k - 8] ^ AM[3][k - 8] ^ AM[0][k - 8];

            if (judgeR(x))
                count[num]++;
        }
    }
    for (int i = 0; i < 256; i++)
        if (count[i] == 256) {
            for (int j = 0; j < 8; j++)
                if (i & (1 << j))
                    AM[4][7 - j] = 1;
                else
                    AM[4][7 - j] = 0;
        }

 /*   for (int i = 0; i <256; i++)
        if (count[i] == 256)
            printf("%d\n",i);
*/


//    for (int i = 0; i < 8; i++)
//        printf("%d ",AM[4][i]);


//-------------------------------------------------------------------------计算AM[5] (a0^a5, a0^a4^a5, a4, a4)
    // 先假定 AM[4] 0001 0000
//    for (int i = 0; i < 8; i++)
//        AM[4][i] = 0;
//    AM[4][4] = 1;

    memset(count, 0, sizeof(int) * 256);

    for (int num_Aset = 0; num_Aset < 256; num_Aset++) {
        create_Aset(num_Aset);    //  // 使用第二个位置是 num_Aset 的这个 Aset
        for (int i = 0; i < 256; i++)
            AES128_ECB_decrypt(Aset[i], key, plain_text[i]);
        calc_DD();

        for (int i = 16; i <= 23; i++)
            x[i] = AM[4][i - 16];
        for (int i = 24; i <= 31; i++)
            x[i] = AM[4][i - 24];

        for (int num = 0; num < 256; num++) {
            for (int k = 0; k < 8; k++) {
                if (num & (1 << k))
                    a[7 - k] = 1;
                else
                    a[7 - k] = 0;
            }
            for (int k = 0; k < 8; k++)
                x[k] = a[k] ^ AM[0][k];
            for (int k = 8; k <= 15; k++)
                x[k] = a[k - 8] ^ AM[4][k - 8] ^ AM[0][k - 8];

            if (judgeR(x))
                count[num]++;
        }
    }
    for (int i = 0; i < 256; i++)
        if (count[i] == 256) {

            for (int j = 0; j < 8; j++)
                if (i & (1 << j))
                    AM[5][7 - j] = 1;
                else
                    AM[5][7 - j] = 0;
        }
//    for (int i = 0; i < 8; i++)
//        printf("%d ",AM[5][i]);

//----------------------------------------------------------------------计算AM[6] (a6, a5^a6, a5, a5)
   // 先假定 AM[5] 0001 0000
//    for (int i = 0; i < 8; i++)
//        AM[5][i] = 0;
//    AM[5][5] = 1;

    memset(count, 0, sizeof(int) * 256);

    for (int num_Aset = 0; num_Aset < 256; num_Aset++) {
        create_Aset(num_Aset);    //  // 使用第二个位置是 num_Aset 的这个 Aset
        for (int i = 0; i < 256; i++)
            AES128_ECB_decrypt(Aset[i], key, plain_text[i]);
        calc_DD();

        for (int i = 16; i <= 23; i++)
            x[i] = AM[5][i - 16];
        for (int i = 24; i <= 31; i++)
            x[i] = AM[5][i - 24];

        for (int num = 0; num < 256; num++) {
            for (int k = 0; k < 8; k++) {
                if (num & (1 << k))
                    a[7 - k] = 1;
                else
                    a[7 - k] = 0;
            }
            for (int k = 0; k < 8; k++)
                x[k] = a[k];
            for (int k = 8; k <= 15; k++)
                x[k] = a[k - 8] ^ AM[5][k - 8];

            if (judgeR(x))
                count[num]++;
        }
    }
    for (int i = 0; i < 256; i++)
        if (count[i] == 256) {

            for (int j = 0; j < 8; j++)
                if (i & (1 << j))
                    AM[6][7 - j] = 1;
                else
                    AM[6][7 - j] = 0;
        }
//    for (int i = 0; i < 8; i++)
//        printf("%d ",AM[6][i]);

//--------------------------------------------------------------------计算AM[7] (a0^a7, a0^a6^a7, a6, a6)
     // 先假定 AM[6] 0001 0000
//   for (int i = 0; i < 8; i++)
//       AM[6][i] = 0;
//   AM[6][6] = 1;

   memset(count, 0, sizeof(int) * 256);

   for (int num_Aset = 0; num_Aset < 256; num_Aset++) {
       create_Aset(num_Aset);    //  // 使用第二个位置是 num_Aset 的这个 Aset
       for (int i = 0; i < 256; i++)
           AES128_ECB_decrypt(Aset[i], key, plain_text[i]);
       calc_DD();

       for (int i = 16; i <= 23; i++)
           x[i] = AM[6][i - 16];
       for (int i = 24; i <= 31; i++)
           x[i] = AM[6][i - 24];

       for (int num = 0; num < 256; num++) {
           for (int k = 0; k < 8; k++) {
               if (num & (1 << k))
                   a[7 - k] = 1;
               else
                   a[7 - k] = 0;
           }
           for (int k = 0; k < 8; k++)
               x[k] = a[k] ^ AM[0][k];
           for (int k = 8; k <= 15; k++)
               x[k] = a[k - 8] ^ AM[6][k - 8] ^ AM[0][k - 8];

           if (judgeR(x))
               count[num]++;
       }
   }
    for (int i = 0; i < 256; i++)
        if (count[i] == 256) {
            //printf("!!!!    %d\n", i);
            for (int j = 0; j < 8; j++)
                if (i & (1 << j))
                    AM[7][7 - j] = 1;
                else
                    AM[7][7 - j] = 0;
        }
//    for (int i = 0; i < 8; i++)
//        printf("%d ",AM[7][i]);

}
//======================================================================================================================
static void read_M32() {
   FILE *in;
   in = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/M32.txt", "r");
   for (int i = 0; i < 32; i++)
       for (int j = 0; j < 32; j++)
           fscanf(in, "%d", & M[i][j]);
   fclose(in);
}




static void calc_M32() {
   int M[4][4] = {{2, 3, 1, 1,},
                  {1, 2, 3, 1},
                  {1, 1, 2, 3},
                  {3, 1, 1, 2}};

   int a[3][64];
   memset(a, 0, sizeof(int) * 192);
   for (int i = 0; i < 8; i++) {
       a[0][i * 9] = 1;
       a[2][i * 9] = 1;
   }
   int x = 1;
   for (int i = 0; i < 7; i++) {
       a[1][i * 9 + x] = 1;
       a[2][i * 9 + x] = 1;
   }
   a[1][56] = 1;
   a[2][56] = 1;

   int count = 0;
  for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {

      }

  }


}

static void calc_DD() {
  // printf("\n");
  // printf("%d %d %d %d", plain_text[0][0], kk[0], plain_text[0][0] ^ kk[0]  , SS[249]);
   for (int i = 0; i < 256; i++) {
       DD[i][0] = SS[(int)plain_text[i][0] ^ kk[0]];
       DD[i][1] = SS[(int)plain_text[i][5] ^ kk[5]];
       DD[i][2] = SS[(int)plain_text[i][10]^ kk[10]];
       DD[i][3] = SS[(int)plain_text[i][15] ^ kk[15]];
   }

}

static int affine(int num) {
   bool x[8];
   bool y[8];
   int ans = 0;

   for (int i = 0; i < 8; i++)
       if (num & (1 << i))
           x[7 - i] = 1;
       else
           x[7 - i] = 0;


   for (int i = 0; i < 8; i++) {
       y[i] = 0;
       for (int j = 0; j < 8; j++)
           if (A[i][j])
               y[i] ^= x[j];
       //y[i] ^= v[i];
   }


   for (int i = 0; i < 8; i++)
       if (y[i])
           ans += pow(2, 7 - i);

   return ans;

}

static void calc_kk() {   // 计算 k'
   int count[16][256];
   memset(count, 0, sizeof(int) * 16 * 256);

   for (int num_Aset = 0; num_Aset < 256; num_Aset++) {

       create_Aset(num_Aset);    //  // 使用第二个位置是 num_Aset 的这个 Aset
       for (int i = 0; i < 256; i++)
           AES128_ECB_decrypt(Aset[i], key, plain_text[i]);

       for (int i = 1; i < 16; i++) {
           for (int a = 0; a <= 255; a++) {
               int sum = 0;
               for (int j = 0; j <= 255; j++) {
                   sum ^= SS[a ^ plain_text[j][i]];
                   //printf("%d\n", SS[a ^ Aset[j][i]]);
               }
               if (sum == 0)
                   count[i][a]++;
           }
       }
   }
   kk[0] = 0;
   for (int i = 1; i < 16; i++) {
       for (int j = 0; j < 256; j++)
           if (count[i][j] == 256) {  // 在 256 个A-set中  都符合条件的才是我们所要的k'
               kk[i] = j;
               break;
           }
   }

}

static void calc_SS() {
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
    uint8_t in[] = {0x59, 0xcd, 0x18, 0x6e, 0xcf, 0x71, 0x04, 0x4b, 0x75, 0x72, 0x61, 0x80, 0xe7, 0x43, 0xd4, 0x40};
    uint8_t out[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};
    uint8_t buffer[16];


    FILE *output;
    output = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/Ak_SB_SR_.txt", "w");




        AK_SB_SR(in, key, buffer);
       // printf("%d: ", i);
        for (int j = 0; j < 16; j++) {
            fprintf(output, "%d  ", buffer[j]);
            if ( !((j + 1) % 4) )
                fprintf(output, "\n");
        }
        fprintf(output, "\n");






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


