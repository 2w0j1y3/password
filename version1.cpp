#include<bits/stdc++.h>
using namespace std;

// 加密函数
string encrypt(const string& plain_text) {
    srand(time(0));
    int fir = rand();
    string cipher;

    auto outb = [&](int x) -> string {
        int y = rand() % 4 + 4;
        string s;
        while (x) {
            s = char(x % y + '0') + s;
            x /= y;
        }
        s = char(y + '0') + s;
        s = char('8' + rand() % 2) + s;
        return s;
    };

    cipher += outb(fir); 
    for (char ch : plain_text) {
        cipher += outb(ch + fir);
    }
    return cipher;
}

// 解密函数
string decrypt(const string& cipher_text) {
    int pos = 0;
    int len = cipher_text.size();

    auto getb = [&](int& p) -> int {
        if (p >= len) return -1;
        char c = cipher_text[p++];
        int y = c - '0';
        int x = 0;
        while (p < len) {
            c = cipher_text[p];
            if (c >= '8' || c == EOF) break;
            x = x * y + c - '0';
            p++;
        }
        return x;
    };

    if (pos < len && (cipher_text[pos] == '8' || cipher_text[pos] == '9')) pos++;
    int fir = getb(pos);
    string plain;

    while (true) {
        while (pos < len && (cipher_text[pos] == '8' || cipher_text[pos] == '9')) pos++;
        if (pos >= len) break;

        int x = getb(pos);
        if (x == -1) break;
        plain += char(x - fir);
    }
    return plain;
}

signed main() {
    string s;
    getline(cin, s);

    string mi = encrypt(s);
    cout<<mi<<'\n';
    string ming = decrypt(mi);
    cout<<ming<<"\n";
    
    return 0;
}