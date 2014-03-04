#include <des.h>
#include <bitset>
#include <string>
#include <cmath>
#include <vector>
#include <sstream>
#include <cstdint>

namespace des {

namespace {

enum class EncryptionMode {
    ENCRYPT,
    DECRYPT,
};

enum class DesMode {
    ECB,
    CBC,
    CFB,
};

const int IP[BLOCK_SIZE] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

const int IP_INV[BLOCK_SIZE] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

const int PC1[KEY_SIZE] = {
    57,  49,  41,  33,  25,  17,  9,
    1,   58,  50,  42,  34,  26,  18,
    10,  2,   59,  51,  43,  35,  27,
    19,  11,  3,   60,  52,  44,  36,
    63,  55,  47,  39,  31,  23,  15,
    7,   62,  54,  46,  38,  30,  22,
    14,  6,   61,  53,  45,  37,  29,
    21,  13,  5,   28,  20,  12,  4,
};

const int PC2[ROUND_KEY_SIZE] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

const int E[ROUND_KEY_SIZE] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

template<size_t OUT, size_t IN>
void apply_permutation(const int* p, const std::bitset<IN>& in, std::bitset<OUT>& out) {
    for (int i = 0; i < out.size(); i++) {
        out[i] = in[p[i] - 1];
    }
}

Block apply_initp(Block block) {
    Block res;
    apply_permutation(IP, block, res);
    return res;
}

Block apply_initp_inv(Block block) {
    Block res;
    apply_permutation(IP_INV, block, res);
    return res;
}

RoundKey expand(BlockPart part)
{
    RoundKey res;
    apply_permutation(E, part, res);
    return res;
}

Key compress(Block block) {
    Key compressed;
    apply_permutation(PC1, block, compressed);
    return compressed;
}

RoundKey compress(Key key) {
    RoundKey compressed;
    apply_permutation(PC2, key, compressed);
    return compressed;
}

template<size_t N>
std::bitset<N> shift(std::bitset<N> target, int shift) {
    auto result = target;
    for (size_t i = 0; i < target.size(); i++) {
        result[i] = target[(i + shift) % target.size()];
    }
    return result;
}

const int S[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

const int P[32]= {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
};

BlockPart apply_pblock(BlockPart target) {
    BlockPart res;
    apply_permutation(P, target, res);
    return res;
}

BlockPart f(BlockPart block, RoundKey key) {

    auto expanded = expand(block);

    expanded ^= key;

    BlockPart subst;
    int current = 0;
    for (size_t k = 0; k < expanded.size(); k = k + 6) {
        int row = expanded[k] * 2 + expanded[k + 5];
        int col = expanded[k + 1] * 8 + expanded[k + 2] * 4 + expanded[k + 3] * 2 + expanded[k + 4];

        std::bitset<4> res(S[k / 6][row][col]);

        for (int i = 0; i < 4; i++) {
            subst[current + i] = res[4 - i - 1];
        }

        current += 4;
    }

    subst = apply_pblock(subst);
    return subst;
}

template<size_t N>
std::bitset<2 * N> combine(std::bitset<N> first, std::bitset<N> second) {
    std::bitset<2 * N> result;
    for(int i = 0; i < N; i++) {
        result[i] = first[i];
        result[i + N] = second[i];
    }
    return result;
}

template<size_t N>
void split(std::bitset<N> target, std::bitset<N / 2>& first, std::bitset<N / 2>& second) {
    for(int i = 0; i < N / 2; i++) {
        first[i] = target[i];
        second[i] = target[i + N / 2];
    }
}

std::vector<RoundKey> calculate_keys(Key key) {
    KeyPart left;
    KeyPart right;
    Key current_key = key;

    std::vector<RoundKey> keys(ROUND_COUNT);

    int shifts[16] = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    for (int round = 0; round < ROUND_COUNT; round++) {
        split(current_key, left, right);

        right = shift(right, shifts[round]);
        left = shift(left, shifts[round]);

        current_key = combine(left, right);

        keys[round] = compress(current_key);
    }

    return keys;
}

Block des(Block block, Key key, EncryptionMode mode) {
    auto keys = calculate_keys(key);
    auto result = apply_initp(block);

    BlockPart left, right;
    split(result, left, right);

    if (mode == EncryptionMode::DECRYPT) {
        std::reverse(keys.begin(), keys.end());
    }

    int round = 1;
    for (const auto& key_ : keys) {

        left = left ^ f(right, key_);
        if (round++ != 16) {
            std::swap(left, right);
        }
    }

    result = combine(left, right);

    result = apply_initp_inv(result);

    return result;
}

std::string ecb_handle_block(Block plain, Key key, EncryptionMode mode) {
    return to_binstr(des(plain, key, mode));
}

std::string cbc_handle_block(Block plain, Key key, EncryptionMode mode, Block& prev) {
        Block block_result;

        if (mode == EncryptionMode::ENCRYPT) {
            block_result = des(plain ^ prev, key,  mode);
            prev = block_result;
        } else if (mode == EncryptionMode::DECRYPT) {
            block_result = des(plain, key,  mode);
            block_result ^= prev;
            prev = plain;
        }

        return to_binstr(block_result);
}

std::string cfb_handle_block(Block plain, Key key, EncryptionMode mode, Block& prev) {
        Block block_result = encrypt(prev, key) ^ plain;
        prev = (mode == EncryptionMode::ENCRYPT ? block_result : plain);

        return to_binstr(block_result);
}

std::string des(
    std::string text,
    std::string key_,
    DesMode des_mode,
    EncryptionMode emode,
    uint64_t init = 0)
{
    Key key = compress(read_block(key_));
    std::string result;

    Block prev(init);
    for (int i = 0; i < text.size(); i += 8) {
        Block plain = read_block(text, i);
        switch(des_mode) {
        case DesMode::ECB:
            result += ecb_handle_block(plain, key, emode);
            break;
        case DesMode::CBC:
            result += cbc_handle_block(plain, key, emode, prev);
            break;
        case DesMode::CFB:
            result += cfb_handle_block(plain, key, emode, prev);
            break;
        }
    }

    return result;
}

}

Block encrypt(Block block, Block key_) {
    Key key = compress(key_);
    return encrypt(block, key);
}

Block decrypt(Block block, Block key_) {
    Key key = compress(key_);
    return decrypt(block, key);
}

Block encrypt(Block block, Key key) {
    return des(block, key, EncryptionMode::ENCRYPT);
}

Block decrypt(Block block, Key key) {
    return des(block, key, EncryptionMode::DECRYPT);
}

std::string ecb_encrypt(std::string text, std::string key) {
    return des(text, key, DesMode::ECB, EncryptionMode::ENCRYPT);
}

std::string ecb_decrypt(std::string text, std::string key) {
    return des(text, key, DesMode::ECB, EncryptionMode::DECRYPT);
}

std::string cbc_encrypt(std::string text, std::string key, uint64_t init) {
    return des(text, key, DesMode::CBC, EncryptionMode::ENCRYPT, init);
}

std::string cbc_decrypt(std::string text, std::string key, uint64_t init) {
    return des(text, key, DesMode::CBC, EncryptionMode::DECRYPT, init);
}

std::string cfb_encrypt(std::string text, std::string key, uint64_t init) {
    return des(text, key, DesMode::CFB, EncryptionMode::ENCRYPT, init);
}

std::string cfb_decrypt(std::string text, std::string key, uint64_t init) {
    return des(text, key, DesMode::CFB, EncryptionMode::DECRYPT, init);
}

Block read_block(std::string input, int pos) {
    uint64_t cur = 0;
    for (int j = pos; j < input.size() && j < pos + 8; j++) {
        cur *= 256;
        cur += static_cast<unsigned char>(input[j]);
    }

    Block block(cur);

    for (int i = 0; i < block.size() / 2; i++) {
        std::swap(block[i], block[block.size() - i - 1]);
    }

    return block;
}

}
