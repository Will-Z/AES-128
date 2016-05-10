//
// Created by Will on 5/9/16.
//

#include <iostream>
using namespace std;

int main() {
    FILE *in;
    in = fopen("/Users/Will/Programming/Clion/prac/check.txt", "r");

    int S[256][16];
    int a[256];

    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 4; j++)
            fscanf(in, "%d", &S[i][j]);

    int num = 3;
    for (int i = 0; i < 256; i++)
        a[i] = S[i][num];


    int sum = 0;
    int x;

    for (int i = 0; i < 256; i++)
        sum ^= a[i];




   printf("%d\n", a[1]);


}