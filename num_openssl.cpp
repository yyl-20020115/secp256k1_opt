#include <assert.h>
#include <string>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#include "num_openssl.h"

namespace secp256k1 {

class Context {
private:
    BN_CTX *ctx;

    operator BN_CTX*() {
        return ctx;
    }

    friend class Number;
public:
    Context() {
        ctx = BN_CTX_new();
    }

    ~Context() {
        BN_CTX_free(ctx);
    }
};

Number::operator const BIGNUM*() const {
    return pb;
}

Number::operator BIGNUM*() {
    return pb;
}

Number::Number() {
    this->pb = BN_new();// BN_init(*this);
}

Number::~Number() {
    if (this->pb != nullptr) {
        BN_free(this->pb);
        this->pb = nullptr;
    }
}

Number::Number(const unsigned char *bin, int len) {
    this->pb = BN_new();// BN_init(*this);
    SetBytes(bin,len);
}

void Number::SetNumber(const Number &x) {
    BN_copy(this->pb, x);
}

Number::Number(const Number &x) {
    this->pb = BN_new();// BN_init(*this);
    BN_copy(this->pb, x);
}

Number &Number::operator=(const Number &x) {
    BN_copy(this->pb, x);
    return *this;
}

void Number::SetBytes(const unsigned char *bin, int len) {
    BN_bin2bn(bin, len, this->pb);
}

void Number::GetBytes(unsigned char *bin, int len) {
    int size = BN_num_bytes(this->pb);
    assert(size <= len);
    memset(bin,0,len);
    BN_bn2bin(this->pb, bin + len - size);
}

void Number::SetInt(int x) {
    if (x >= 0) {
        BN_set_word(this->pb, x);
    } else {
        BN_set_word(this->pb, -x);
        BN_set_negative(this->pb, 1);
    }
}

void Number::SetModInverse(const Number &x, const Number &m) {
    Context ctx;
    BN_mod_inverse(this->pb, x, m, ctx);
}

void Number::SetModMul(const Number &a, const Number &b, const Number &m) {
    Context ctx;
    BN_mod_mul(this->pb, a, b, m, ctx);
}

void Number::SetAdd(const Number &a1, const Number &a2) {
    BN_add(this->pb, a1, a2);
}

void Number::SetSub(const Number &a1, const Number &a2) {
    BN_sub(this->pb, a1, a2);
}

void Number::SetMult(const Number &a1, const Number &a2) {
    Context ctx;
    BN_mul(this->pb, a1, a2, ctx);
}

void Number::SetDiv(const Number &a1, const Number &a2) {
    Context ctx;
    BN_div(this->pb, NULL, a1, a2, ctx);
}

void Number::SetMod(const Number &a, const Number &m) {
    Context ctx;
    BN_nnmod(this->pb, a, m, ctx);
}

int Number::Compare(const Number &a) const {
    return BN_cmp(this->pb, a);
}

int Number::GetBits() const {
    return BN_num_bits(this->pb);
}

int Number::ShiftLowBits(int bits) {
    //BIGNUM* bn = *this;
    //int ret = BN_is_zero(bn) ? 0 : bn->d[0] & ((1 << bits) - 1);
    //BN_rshift(*this, *this, bits);
    int ret = 0;

    if (!BN_is_zero(this->pb))
    {
        //HIGH BITS are leading
        BN_ULONG val = 0;
        int s = BN_num_bits(this->pb);
        if (s >= sizeof(BN_ULONG) * 8) {
            BIGNUM* a = BN_new();
            BN_copy(a, this->pb);
            BN_mask_bits(a, sizeof(BN_ULONG) * 8);
            val = BN_get_word(a);
            BN_free(a);
        }
        else {
            val = BN_get_word(this->pb);
        }
        BN_rshift(this->pb, this->pb, bits);
        ret = val & ((1ULL << bits) - 1);
    }    
    return ret;
}

bool Number::IsZero() const {
    return BN_is_zero(this->pb);
}

bool Number::IsOdd() const {
    return BN_is_odd(this->pb);
}

bool Number::CheckBit(int pos) const {
    return BN_is_bit_set(this->pb, pos);
}

bool Number::IsNeg() const {
    return BN_is_negative(this->pb);
}

void Number::Negate() {
    BN_set_negative(this->pb, !IsNeg());
}

void Number::Shift1() {
    BN_rshift1(this->pb, this->pb);
}

void Number::Inc() {
    BN_add_word(this->pb,1);
}

void Number::SetHex(const std::string &str) {
    BN_hex2bn(&this->pb, str.c_str());
}

void Number::SetPseudoRand(const Number &max) {
    BN_pseudo_rand_range(this->pb, max);
}

void Number::SplitInto(int bits, Number &low, Number &high) const {
    BN_copy(low, this->pb);
    BN_mask_bits(low, bits);
    BN_rshift(high, this->pb, bits);
}

std::string Number::ToString() const {
    char *str = BN_bn2hex(this->pb);
    std::string ret(str);
    OPENSSL_free(str);
    return ret;
}

}
