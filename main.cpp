#include <des.h>
#include <bitset>
#include <sstream>
#include <iostream>

using namespace std;

template<size_t N>
bitset<N> gen_random_bitset(){
    bitset<N> res;
    for (int i = 0; i < N; i++) {
        res[i] = rand() % 2;
    }
    return res;
}

string gen_key() {
    string res;
    for (int i = 0; i < des::BLOCK_SIZE; i++) {
        res += static_cast<char>(rand() & 255);
    }

    return res;
}

std::string hex_encode(std::string text) {
    std::string res;
    const char* c = text.c_str();
    char buf[3];

    while(*c != 0) {
        sprintf(buf, "%02X", static_cast<unsigned char>(*c));
        res += buf;
        c++;
    }

    return res;
}

std::string hex_decode(std::string str) {
    std::string tmp;
    const char *c = str.c_str();
    unsigned int x;

    while(*c != 0) {
        sscanf(c, "%2X", &x);
        tmp += x;
        c += 2;
    }

    return tmp;
}

int main() {
    string key = gen_key();
    string text = "hello world";
    string code = des::ecb_encrypt(text, key);


    cout << endl << "ECB mode: " << endl
        << "original text: " << text << endl
        << "encrypted text: " << hex_encode(code) << endl
        << "decrypted text: " << des::ecb_decrypt(code, key) << endl;

    uint64_t init = gen_random_bitset<64>().to_ullong();
    code = des::cbc_encrypt(text, key, init);

    cout << endl << "CBC mode: " << endl
        << "original text: " << text << endl
        << "encrpyted text: " << hex_encode(code) << endl
        << "decrypted text: " << des::cbc_decrypt(code, key, init) << endl;


    init = gen_random_bitset<64>().to_ullong();
    code = des::cfb_encrypt(text, key, init);

    cout << endl << "CFB mode: " << endl
        << "original text: " << text << endl
        << "encrpyted text: " << hex_encode(code) << endl
        << "decrypted text: " << des::cfb_decrypt(code, key, init) << endl;

    cout << endl << "Rivest' test:" << endl;
    des::Block x = des::read_block(hex_decode("9474B8E8C73BCA7D"));
    cout << "X0: "<< hex_encode(des::to_binstr(x)) << endl;
    for (int i = 1; i < 17; i++) {
        if (i % 2) {
            x = des::encrypt(x, x);
        } else {
            x = des::decrypt(x, x);
        }
    }

    cout << "X16: " << hex_encode(des::to_binstr(x)) << endl;
}