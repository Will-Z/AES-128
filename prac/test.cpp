#include <iostream>
#include <stdio.h>
#include <math.h>
using namespace std;



int M[32][32];

int d[32];
int ans[32];




void calc() {

    for (int i = 0; i < 32; i++) {
        ans[i] = 0;
        for (int j = 0; j < 32; j++)
            if (M[i][j])
                ans[i] ^= d[j];
    }


    FILE *out;
    out = fopen("/Users/Will/Programming/Clion/prac/ans.txt", "a");
    for (int i = 0; i < 32; i++)
        fprintf(out, "%d ",ans[i]);
    fprintf(out, "\n");



/*
    int sum = 0;
    for (int i = 0; i < 8; i++)
        sum += ans[i] * pow(2, 7 - i);
    printf("%d ", sum);
    sum = 0;
    for (int i = 8; i < 16; i++)
        sum += ans[i] * pow(2, 15 - i);
    printf("%d ", sum);
    sum = 0;
    for (int i = 16; i < 24; i++)
        sum += ans[i] * pow(2, 23 - i);
    printf("%d ", sum);
    sum = 0;
    for (int i = 24; i < 32; i++)
        sum += ans[i] * pow(2, 31 - i);
    printf("%d\n ", sum);
*/





}

int main() {
    FILE *Min;
    Min = fopen("/Users/Will/Programming/Clion/prac/M32.txt", "r");
    for (int i = 0; i < 32; i++)
        for (int j = 0; j < 32; j++)
            fscanf(Min, "%d", &M[i][j]);
    fclose(Min);






    FILE *in;
    in = fopen("/Users/Will/Programming/Clion/prac/DD.txt", "r");




    for (int i = 0; i < 256; i++) {
        int num;
        for (int j = 0; j < 4; j++) {
            fscanf(in, "%d", &num);
            for (int k = 0; k < 8; k++)
                if (num & (1 << k))
                    d[j * 8 + 7 - k] = 1;
                else
                    d[j * 8 + 7 - k] = 0;
        }
        calc();
    }

}