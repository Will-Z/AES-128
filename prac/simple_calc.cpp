//
// Created by Will on 5/10/16.
//

#include <iostream>
#include <cmath>
using namespace std;

int main(){

    int A[256][16];
    int a[256];
    int x;

    FILE *in;
    in = fopen("/Users/Will/Programming/Clion/prac/MC_DD.txt", "r");
    for (int i = 0; i < 256; i++) {
    for (int j = 0; j < 32; j++)
        fscanf(in, "%d ", &A[i][j]);
    }
/*
    int num = 2;

    for (int i = 0; i < 256; i++)
        a[i] = A[i][num];

    for (int i = 0; i < 256; i++)
        for (int j = i + 1; j < 256; j++)
            if (a[i] > a[j]) {
                x = a[i];
                a[i] = a[j];
                a[j] = x;
            }

    for (int i = 0; i < 256; i++)
        printf("%d:   %d\n", i, a[i]);

*/

    int count;
    for (int i = 0; i < 32; i++) {
        count = 0;
        for (int j = 0; j < 256; j++)
            if(A[j][i])
                count++;
        printf("%d:     %d\n", i, count);
    }


    fclose(in);



}
