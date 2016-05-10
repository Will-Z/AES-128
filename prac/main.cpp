#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
using namespace std;

#define ll long long
const int MAXN = 2048, KS = 32, MAXN0 = (MAXN + 1) / KS + 1, INF = ~0U >> 2;
int n, n0, q, A[MAXN][MAXN0];
bool res[MAXN], res_ex = 1;
void init()
{
    freopen("arc.in", "r", stdin);
    int q0 = 0, q1 = 0, x, y;
    scanf("%d", &n);
    n0 = n / KS;
    q = n % KS;
    for (int i = 0; i < n; i++) {
        scanf("%d", &x);
        if (x & 1) {
            A[i][q0] |= 1 << q1;
            A[i][n0] |= 1 << q;
        }
        for (int j = 0; i < x; j++) {
            scanf("%d", &y);
            y--;
            A[i][y / KS] |= 1 << (y % KS);
        }
        if (q1 == KS - 1) {
            q0++;
            q1 = 0;
        }
        else
            q1++;
    }
    fclose(stdin);
}
void solve()
{
    int q0 = 0, q1 = 0, p = 0, x;
    ll tmp;
    for (int i = 0; i < n; i++) {
        x = -1;
        for (int j = p; j < n; j++)
            if (A[j][q0] & (1 << q1)) {
                x = j;
                break;
            }
        if (x >= 0) {
            if (x != p) {
                for(int k = q0; k <= n0; k++) {  //两行的交换
                    tmp = A[x][k];
                    A[x][k] = A[p][k];
                    A[p][k] = tmp;
                }
            }
            for (int j = p + 1; j < n; j++)
                if (A[j][q0] & (1 << q1))
                    for (int k = q0; k <= n0; k++)
                        A[j][k] ^= A[p][k];
            p++;
        } else {                                            //遇到自由元
            res[i] = 1;                                     //定为1
            for (int j = 0; j < p; j++)                     //找到前面xi系数为1的方程 全部带入xi的值XOR掉
                if (A[j][q0] & (1 << q1)) {
                    A[j][q0] &= ~(1 << q1);
                    A[j][n0] ^= 1 << q;
                }
        }
        if (q1 == KS - 1) {
            q0++;
            q1 = 0;
        }
        else
            q1++;
    }

    for (int i = p; i < n; i++)
        if (A[i][n0] & (1 << q)) {
            res_ex = 0;
            return;
        }
    p--;

    for (int i = n - 1; i >= 0; i--) {
        if (q1)
            q1--;
        else {
            q0--;
            q1 = KS - 1;
        }
        if (!res[i]) {
            res[i] = A[p][n0] & (1 << q);     // 相当于 倒三角系数矩阵 最下面的   xi 可以根据等号右边直接确定
            for (int j = 0; j < p; j++)
                if (A[j][q0] & (1 << q1)) {
                    A[j][q0] ^= A[p][q0];
                    if (q0 < n0)
                        A[j][n0] ^= A[p][n0];
                }
            p--;
        }
    }
}
void pri()
{
    freopen("arc.out", "w", stdout);
    if (res_ex) {
        int sum = 0;
        bool SPC = 0;
        for (int i = 0; i < n; i++)
            if (!res[i]) sum++;
        printf("%d\n", sum);
        for (int i = 0; i < n; i++)
            if (!res[i]) {
                if (SPC)
                    putchar(' ');
                else
                    SPC = 1;
                printf("%d", i + 1);
            }
        puts("");
    }
    else
        puts("Impossible");
    fclose(stdout);
}
int main()
{
    init();
    solve();
    pri();
    return 0;
}