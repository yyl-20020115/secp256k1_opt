#ifndef _SECP256K1_ECMULT_
#define _SECP256K1_ECMULT_

#include "group.h"
#include "num.h"

namespace secp256k1 {

template<typename G, int W> class WNAFPrecomp {
private:
    G pre[1 << (W-2)];

public:
    WNAFPrecomp() {}

    void Build(const G &base) {
        pre[0] = base;
        GroupElemJac x(base);
        GroupElemJac d; d.SetDouble(x);
        for (int i=1; i<(1 << (W-2)); i++) {
            x.SetAdd(d,pre[i-1]);
            pre[i].SetJac(x);
        }
    }

    WNAFPrecomp(const G &base) {
        Build(base);
    }

    void Get(G &out, int exp) const {
        assert((exp & 1) == 1);
        assert(exp >= -((1 << (W-1)) - 1));
        assert(exp <=  ((1 << (W-1)) - 1));
        if (exp > 0) {
            out = pre[(exp-1)/2];
        } else {
            out.SetNeg(pre[(-exp-1)/2]);
        }
    }
};

template<int B> class WNAF {
private:
    int naf[B+1];
    int used;

    void PushNAF(int num, int zeroes) {
        assert(used < B+1);
        for (int i=0; i<zeroes; i++) {
            naf[used++]=0;
        }
        naf[used++]=num;
    }

public:
    WNAF(const Number &exp, int w) : used(0) {
        int zeroes = 0;
        Number x;
        x.SetNumber(exp);
        int sign = 1;
        if (x.IsNeg()) {
            sign = -1;
            x.Negate();
        }
        while (!x.IsZero()) {
            while (!x.IsOdd()) {
                zeroes++;
                x.Shift1();
            }
            int word = x.ShiftLowBits(w);
            if (word & (1 << (w-1))) {
                x.Inc();
                PushNAF(sign * (word - (1 << w)), zeroes);
            } else {
                PushNAF(sign * word, zeroes);
            }
            zeroes = w-1;
        }
    }

    int GetSize() const {
        return used;
    }

    int Get(int pos) const {
        assert(pos >= 0 && pos < used);
        return naf[pos];
    }

    std::string ToString() {
        std::stringstream ss;
        ss << "(";
        for (int i=0; i<GetSize(); i++) {
            ss << Get(used-1-i);
            if (i != used-1)
                ss << ',';
        }
        ss << ")";
        return ss.str();
    }
};

void ECMultBase(GroupElemJac &out, const Number &gn);
void ECMult(GroupElemJac &out, const GroupElemJac &a, const Number &an, const Number &gn);

}

#endif
