//
// Created by Will on 5/5/16.
//



#include <stdio.h>
#include <iostream>

int main() {
    FILE *in;
    int sum = 0;
    uint8_t a[256] = {0x35, 0xcf, 0x16, 0xbf, 0x64, 0xaa, 0x06, 0x65, 0xae, 0xc9, 0xf4, 0xcc, 0xf5, 0x19, 0x06, 0x76, 0x46, 0xa9, 0xdf, 0x04, 0x9d, 0xbe, 0x23, 0x0e, 0xef, 0x57, 0xa7, 0x83, 0x1f, 0x64, 0x35, 0xe5, 0x48, 0x58, 0x8d, 0xdc, 0x23, 0xa6, 0xe3, 0xc4, 0xf7, 0x22, 0xbd, 0xa5, 0x27, 0x9e, 0x7f, 0xf9, 0x38, 0x0d, 0x4f, 0xec, 0x12, 0xc6, 0x40, 0x2d, 0xcc, 0xd9, 0x07, 0x48, 0x01, 0xa8, 0x87, 0xa2, 0xf2, 0x27, 0xca, 0x19, 0xa9, 0x74, 0xbb, 0x74, 0xb6, 0x09, 0x30, 0x82, 0x04, 0x01, 0x67, 0xb5, 0x8c, 0x5c, 0xf0, 0x7c, 0x5d, 0x9c, 0x0f, 0x8e, 0xbc, 0x63, 0xee, 0xd1, 0x58, 0xdd, 0x39, 0x40, 0x3b, 0x9d, 0xcf, 0x37, 0x83, 0xd0, 0xac, 0x1d, 0x1a, 0x28, 0x90, 0xb0, 0x08, 0x09, 0xb5, 0xa0, 0x17, 0x21, 0x96, 0xda, 0x5d, 0xe5, 0xbe, 0xb2, 0xf9, 0xcc, 0x2f, 0xfa, 0x7a, 0x7a, 0x05, 0x2e, 0x21, 0x8d, 0x3f, 0x49, 0xef, 0x8f, 0xa1, 0xe4, 0x32, 0xea, 0x3d, 0xef, 0x0b, 0xb0, 0x51, 0x2c, 0x25, 0x8b, 0x0a, 0x1a, 0x1b, 0xc5, 0x77, 0x24, 0xb9, 0xd8, 0x57, 0x93 };

    in = fopen("/Users/Will/Programming/Clion/tiny-AES128/Debug/text.txt", "r");

    for (int i = 0; i < 256; i++) {
        sum ^= a[i];
    }
    printf("%d\n", sum);
    return 0;



}