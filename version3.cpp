#include<bits/stdc++.h>
using namespace std;

const string sp_chars = "abcdefghijklmnopqrstuvwxyz!@#$%^&*_+-";
const int SP_MIN_LEN = 1;
const int SP_MAX_LEN = 3;
const int BASE_MIN = 4;
const int BASE_MAX = 35;
const size_t sp_char_count = sp_chars.size();

mt19937 rng(random_device{}());
uniform_int_distribution<> dist_sp(0, (int)sp_char_count - 1);
uniform_int_distribution<> dist_sp_len(SP_MIN_LEN, SP_MAX_LEN);
uniform_int_distribution<> dist_base(BASE_MIN, BASE_MAX);
uniform_int_distribution<> dist_int(0, INT_MAX);

inline void gen_sp(string& out) {
	int len = dist_sp_len(rng);
	for (int i = 0; i < len; ++i) {
		out += sp_chars[dist_sp(rng)];
	}
}

inline void to_base_str(int x, int base, string& out) {
	char buf[32];
	int idx = 0;
	
	if (x == 0) {
		buf[idx++] = '0';
	} else {
		while (x > 0) {
			int rem = x % base;
			buf[idx++] = char((rem < 10) ? ('0' + rem) : ('A' + rem - 10));
			x /= base;
		}
	}
	
	out += char((base < 10) ? ('0' + base) : ('A' + base - 10));
	while (idx > 0) out += buf[--idx];
}

string encrypt(const string& plain_text) {
	string cipher;
	cipher.reserve(plain_text.size() * 8);
	
	int fir = dist_int(rng);
	
	gen_sp(cipher);
	to_base_str(fir, dist_base(rng), cipher);
	
	for (char ch : plain_text) {
		gen_sp(cipher);
		to_base_str(ch ^ fir, dist_base(rng), cipher);
	}
	
	return cipher;
}

string decrypt(const string& cipher_text) {
	int pos = 0;
	int len = (int)cipher_text.size();
	string plain;
	plain.reserve(len / 4);
	
	auto to_val = [](char c) {
		return isdigit(c) ? (c - '0') : (c - 'A' + 10);
	};
	
	auto is_sp = [](char c) {
		return !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'));
	};
	
	auto getb = [&]() -> int {
		while (pos < len && is_sp(cipher_text[pos])) pos++;
		if (pos >= len) return -1;
		
		int base = to_val(cipher_text[pos++]);
		int x = 0;
		while (pos < len && !is_sp(cipher_text[pos])) {
			x = x * base + to_val(cipher_text[pos++]);
		}
		return x;
	};
	
	int fir = getb();
	while (true) {
		int val = getb();
		if (val == -1) break;
		plain += (char)(val ^ fir);
	}
	return plain;
}

signed main() {
	ios::sync_with_stdio(false); 
	cin.tie(nullptr);
	
	string s;
	getline(cin, s);
	
	string mi = encrypt(s);
	cout<< mi << '\n';
	
	string ming = decrypt(mi);
	cout<< ming << "\n";
	return 0;
}
