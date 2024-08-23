#include <sstream>
#include <algorithm>
#include <assert.h>

#include "num.h"
#include "group.h"
#include "ecmult.h"

// optimal for 128-bit and 256-bit exponents
#define WINDOW_A 5

// larger numbers may result in slightly better performance, at the cost of
// exponentially larger precomputed tables. WINDOW_G == 13 results in 640 KiB.
#define WINDOW_G 14

namespace secp256k1 {

class ECMultConsts {
public:
    WNAFPrecomp<GroupElem,WINDOW_G> wpg;
    WNAFPrecomp<GroupElem,WINDOW_G> wpg128;
    GroupElem prec[64][16]; // prec[j][i] = 16^j * (i+1) * G
    GroupElem fin; // -(sum(prec[j][0], j=0..63))

    ECMultConsts() {
        const GroupElem &g = GetGroupConst().g;
        GroupElemJac g128j(g);
        for (int i=0; i<128; i++)
            g128j.SetDouble(g128j);
        GroupElem g128; g128.SetJac(g128j);
        wpg.Build(g);
        wpg128.Build(g128);
        GroupElemJac gg(g);
        GroupElem ad(g);
        GroupElemJac fn;
        for (int j=0; j<64; j++) {
            prec[j][0].SetJac(gg);
            fn.SetAdd(fn, gg);
            for (int i=1; i<16; i++) {
                gg.SetAdd(gg, ad);
                prec[j][i].SetJac(gg);
            }
            ad = prec[j][15];
        }
        fn.SetNeg(fn);
        fin.SetJac(fn);
    }
};

const ECMultConsts &GetECMultConsts() {
    static const ECMultConsts ecmult_consts;
    return ecmult_consts;
}

void ECMultBase(GroupElemJac &out, const Number &gn) {
    Number n; n.SetNumber(gn);
    const ECMultConsts &c = GetECMultConsts();
    out.SetAffine(c.prec[0][n.ShiftLowBits(4)]);
    for (int j=1; j<64; j++) {
        out.SetAdd(out, c.prec[j][n.ShiftLowBits(4)]);
    }
    out.SetAdd(out, c.fin);
}

void ECMult(GroupElemJac &out, const GroupElemJac &a, const Number &an, const Number &gn) {
    Number an1, an2;
    Number gn1, gn2;

    SplitExp(an, an1, an2);
//    printf("an=%s\n", an.ToString().c_str());
//    printf("an1=%s\n", an1.ToString().c_str());
//    printf("an2=%s\n", an2.ToString().c_str());
//    printf("an1.len=%i\n", an1.GetBits());
//    printf("an2.len=%i\n", an2.GetBits());
    gn.SplitInto(128, gn1, gn2);

    WNAF<128> wa1(an1, WINDOW_A);
    WNAF<128> wa2(an2, WINDOW_A);
    WNAF<128> wg1(gn1, WINDOW_G);
    WNAF<128> wg2(gn2, WINDOW_G);
    GroupElemJac a2; a2.SetMulLambda(a);
    WNAFPrecomp<GroupElemJac,WINDOW_A> wpa1(a);
    WNAFPrecomp<GroupElemJac,WINDOW_A> wpa2(a2);
    const ECMultConsts &c = GetECMultConsts();

    int size_a1 = wa1.GetSize();
    int size_a2 = wa2.GetSize();
    int size_g1 = wg1.GetSize();
    int size_g2 = wg2.GetSize();
    int size = std::max(std::max(size_a1, size_a2), std::max(size_g1, size_g2));

    out = GroupElemJac();
    GroupElemJac tmpj;
    GroupElem tmpa;

    for (int i=size-1; i>=0; i--) {
        out.SetDouble(out);
        int nw;
        if (i < size_a1 && (nw = wa1.Get(i))) {
            wpa1.Get(tmpj, nw);
            out.SetAdd(out, tmpj);
        }
        if (i < size_a2 && (nw = wa2.Get(i))) {
            wpa2.Get(tmpj, nw);
            out.SetAdd(out, tmpj);
        }
        if (i < size_g1 && (nw = wg1.Get(i))) {
            c.wpg.Get(tmpa, nw);
            out.SetAdd(out, tmpa);
        }
        if (i < size_g2 && (nw = wg2.Get(i))) {
            c.wpg128.Get(tmpa, nw);
            out.SetAdd(out, tmpa);
        }
    }
}

}
