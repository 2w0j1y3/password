#include<bits/stdc++.h>
using namespace std;
inline int getb(){
    char c;c=getchar();
    if(c==EOF)return -1;
    int y=c-'0',x=0;
    while(1){
        c=getchar();
        if(c>='8'||c==EOF)break;
        x=x*y+c-'0';
    }
    return x;
}
int main() {
//    freopen("text.txt","r",stdin);
//    freopen("work.txt","w",stdout);
    char c;c=getchar();
    int fir=getb();
    while(1){
        int x=getb();
        if(x==-1)break;
        printf("%c",char(x-fir));
    }

}
