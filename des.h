#pragma once

#include <bitset>
#include <string>
#include <cstdint>
#include <vector>

namespace des {

const int BLOCK_SIZE = 64;
const int KEY_SIZE = 56;
const int ROUND_KEY_SIZE = 48;
const int ROUND_COUNT = 16;

typedef std::bitset<BLOCK_SIZE> Block;
typedef std::bitset<KEY_SIZE> Key;
typedef std::bitset<BLOCK_SIZE / 2> BlockPart;
typedef std::bitset<ROUND_KEY_SIZE> RoundKey;
typedef std::bitset<KEY_SIZE / 2> KeyPart;

Block encrypt(Block block, Key key);
Block decrypt(Block block, Key key);

Block encrypt(Block block, Block key_);
Block decrypt(Block block, Block key_);


// Режим электронной кодовой книги
std::string ecb_encrypt(std::string text, std::string key_);
std::string ecb_decrypt(std::string text, std::string key_);

// Режим сцепления блоков шифротекста
std::string cbc_encrypt(std::string text, std::string key_, uint64_t init);
std::string cbc_decrypt(std::string text, std::string key_, uint64_t init);

// Режим обратной связи по шифротексту
std::string cfb_encrypt(std::string text, std::string key_, uint64_t init);
std::string cfb_decrypt(std::string text, std::string key_, uint64_t init);

Block read_block(std::string input, int pos = 0);

template<size_t N>
std::string to_binstr(std::bitset<N> bits) {
    std::string res;
    int base = 2;
    for (int i = 0; i < bits.size(); i += 8) {
        int num = 0;
        for (int j = i; j < i + 8; j++) {
            num *= base;
            num += bits[j];
        }
        res += static_cast<char>(num);
    }

    return res;
}

}