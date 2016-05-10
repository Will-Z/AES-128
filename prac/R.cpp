//
// Created by Will on 5/9/16.
//

#include <iostream>
#include <stdio.h>
using namespace std;


int main() {


    FILE *in;
    in = fopen("/Users/Will/Programming/Clion/prac/ans.txt", "r");

    int ans[256][32];

    for (int i = 0; i < 256; i++)
        for (int j = 0; j < 32; j++)
            fscanf(in, "%d", &ans[i][j]);


    for (int i = 0; i < 32; i++) {
        int count = 0;
        for (int j = 0; j < 256; j++)
            if(ans[j][i])
                count++;

        printf("%d:  %d\n", i, count);
/*
        if (count == 128)
            printf("%d:   true\n",i);
        else
            printf("%d:   false\n",i);
*/

    }



}