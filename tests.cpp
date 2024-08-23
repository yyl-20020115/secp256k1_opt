#include <assert.h>

#include "num.h"
#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecdsa.h"

using namespace secp256k1;

void test_run_ecmult_chain() {
    // random starting point A (on the curve)
    FieldElem ax; ax.SetHex("8b30bbe9ae2a990696b22f670709dff3727fd8bc04d3362c6c7bf458e2846004");
    FieldElem ay; ay.SetHex("a357ae915c4a65281309edf20504740f0eb3343990216b4f81063cb65f2f7e0f");
    GroupElemJac a(ax,ay);
    // two random initial factors xn and gn
    Number xn; xn.SetHex("84cc5452f7fde1edb4d38a8ce9b1b84ccef31f146e569be9705d357a42985407");
    Number gn; gn.SetHex("a1e58d22553dcd42b23980625d4c57a96e9323d42b3152e5ca2c3990edc7c9de");
    // two small multipliers to be applied to xn and gn in every iteration:
    Number xf; xf.SetHex("1337");
    Number gf; gf.SetHex("7113");
    // accumulators with the resulting coefficients to A and G
    Number ae; ae.SetHex("01");
    Number ge; ge.SetHex("00");
    // the point being computed
    GroupElemJac x = a;
    const Number &order = GetGroupConst().order;
    for (int i=0; i<20000; i++) {
        // in each iteration, compute X = xn*X + gn*G;
        ECMult(x, x, xn, gn);
        // also compute ae and ge: the actual accumulated factors for A and G
        // if X was (ae*A+ge*G), xn*X + gn*G results in (xn*ae*A + (xn*ge+gn)*G)
        ae.SetModMul(ae, xn, order);
        ge.SetModMul(ge, xn, order);
        ge.SetAdd(ge, gn);
        ge.SetMod(ge, order);
        // modify xn and gn
        xn.SetModMul(xn, xf, order);
        gn.SetModMul(gn, gf, order);
    }
    std::string res = x.ToString();
    assert(res == "(D6E96687F9B10D092A6F35439D86CEBEA4535D0D409F53586440BD74B933E830,B95CBCA2C77DA786539BE8FD53354D2D3B4F566AE658045407ED6015EE1B2A88)");
    // redo the computation, but directly with the resulting ae and ge coefficients:
    GroupElemJac x2; ECMult(x2, a, ae, ge);
    std::string res2 = x2.ToString();
    assert(res == res2);
}

void test_point_times_order(const GroupElemJac &point) {
    // either the point is not on the curve, or multiplying it by the order results in O
    if (!point.IsValid())
        return;

    const GroupConstants &c = GetGroupConst();
    Number zero; zero.SetInt(0);
    GroupElemJac res;
    ECMult(res, point, c.order, zero); // calc res = order * point + 0 * G;
    assert(res.IsInfinity());
}

void test_run_point_times_order() {
    FieldElem x; x.SetHex("02");
    for (int i=0; i<500; i++) {
        GroupElemJac j; j.SetCompressed(x, true);
        test_point_times_order(j);
        x.SetSquare(x);
    }
    assert(x.ToString() == "7603CB59B0EF6C63FE6084792A0C378CDB3233A80F8A9A09A877DEAD31B38C45"); // 0x02 ^ (2^500)
}

void test_wnaf(const Number &number, int w) {
    Number x, two, t;
    x.SetInt(0);
    two.SetInt(2);
    WNAF<1023> wnaf(number, w);
    int zeroes = -1;
    for (int i=wnaf.GetSize()-1; i>=0; i--) {
        x.SetMult(x, two);
        int v = wnaf.Get(i);
        if (v) {
            assert(zeroes == -1 || zeroes >= w-1); // check that distance between non-zero elements is at least w-1
            zeroes=0;
            assert((v & 1) == 1); // check non-zero elements are odd
            assert(v <= (1 << (w-1)) - 1); // check range below
            assert(v >= -(1 << (w-1)) - 1); // check range above
        } else {
            assert(zeroes != -1); // check that no unnecessary zero padding exists
            zeroes++;
        }
        t.SetInt(v);
        x.SetAdd(x, t);
    }
    assert(x.Compare(number) == 0); // check that wnaf represents number
}

void test_run_wnaf() {
    Number range, min, n;
    range.SetHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"); // 2^1024-1
    min = range; min.Shift1(); min.Negate();
    for (int i=0; i<100; i++) {
        n.SetPseudoRand(range); n.SetAdd(n,min);
        test_wnaf(n, 4+(i%10));
    }
}

void test_ecdsa_sign_verify() {
    const GroupConstants &c = GetGroupConst();
    Number msg; msg.SetPseudoRand(c.order);
    Number key; key.SetPseudoRand(c.order);
    Number nonce;
    GroupElemJac pub; ECMultBase(pub, key);
    Signature sig;
    do {
        nonce.SetPseudoRand(c.order);
    } while(!sig.Sign(key, msg, nonce));
    assert(sig.Verify(pub, msg));
    msg.Inc();
    assert(!sig.Verify(pub, msg));
}

void test_run_ecdsa_sign_verify() {
    for (int i=0; i<1000; i++) {
        test_ecdsa_sign_verify();
    }
}

int main(void) {
    test_run_wnaf();
    test_run_point_times_order();
    test_run_ecmult_chain();
    test_run_ecdsa_sign_verify();
    return 0;
}
