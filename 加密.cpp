#include<bits/stdc++.h>
using namespace std;
inline string outb(int x){
    int y=rand()%4+4;
    string s;
    while(x){
        s=char(x%y+'0')+s;
        x/=y;
    }
    s=char(y+'0')+s;
    s=char('8'+rand()%2)+s;
    return s;
}
int main() 
{
//    freopen("text.txt","r",stdin);
//    freopen("work.txt","w",stdout);
    srand(time(0));
    int fir=rand();
    cout<<outb(fir);
    while(1){
        char c=getchar();
        if(c==EOF)break;
        cout<<outb(c+fir);
    }
    return 0;

}
