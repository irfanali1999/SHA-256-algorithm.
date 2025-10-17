#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <fstream>
#include <cstring>
using namespace std;

typedef unsigned int uint32;
typedef unsigned long long uint64;

uint32 rotr(uint32 x, uint32 n) { return (x >> n) | (x << (32 - n)); }

const uint32 k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2
};

void sha256(const string &input, vector<uint32> &digest) {
    digest = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    vector<uint8_t> msg(input.begin(), input.end());
    uint64 l = msg.size() * 8;
    msg.push_back(0x80);
    while ((msg.size() * 8) % 512 != 448) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i) msg.push_back(l >> (i * 8));

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32 w[64], a, b, c, d, e, f, g, h;
        for (int i = 0; i < 16; ++i)
            w[i] = (msg[chunk + 4*i] << 24) | (msg[chunk + 4*i + 1] << 16)
                 | (msg[chunk + 4*i + 2] << 8) | (msg[chunk + 4*i + 3]);
        for (int i = 16; i < 64; ++i) {
            uint32 s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
            uint32 s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        a=digest[0]; b=digest[1]; c=digest[2]; d=digest[3];
        e=digest[4]; f=digest[5]; g=digest[6]; h=digest[7];
        for (int i = 0; i < 64; ++i) {
            uint32 S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
            uint32 ch = (e & f) ^ ((~e) & g);
            uint32 temp1 = h + S1 + ch + k[i] + w[i];
            uint32 S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
            uint32 maj = (a & b) ^ (a & c) ^ (b & c);
            uint32 temp2 = S0 + maj;
            h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        digest[0]+=a; digest[1]+=b; digest[2]+=c; digest[3]+=d;
        digest[4]+=e; digest[5]+=f; digest[6]+=g; digest[7]+=h;
    }
}

string to_hex(const vector<uint32> &digest) {
    stringstream ss;
    for (int i = 0; i < 8; ++i)
        ss << hex << setw(8) << setfill('0') << digest[i];
    return ss.str();
}

int main() {
    ifstream file("bookofmark.txt");
    if (!file.is_open()) {
        cerr << "Error: Could not open mark.txt" << endl;
        return 1;
    }

    stringstream buffer;
    buffer << file.rdbuf();
    string input = buffer.str();

    vector<uint32> digest;
    sha256(input, digest);

    cout << "SHA256 Hash of Book of Mark: " << to_hex(digest) << endl;
    return 0;
}
