/*
 * sb_fe.c: constant time prime-field element operations
 *
 * This file is part of Sweet B, a safe, compact, embeddable elliptic curve
 * cryptography library.
 *
 * Sweet B is provided under the terms of the included LICENSE file. All
 * other rights are reserved.
 *
 * Copyright 2017 Wearable Inc.
 *
 */

#include "sb_fe.h"
#include "sb_test.h"
#include "sb_sw_curves.h"

static const sb_fe_t SB_FE_MINUS_ONE =
    SB_FE_CONST(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);

void sb_fe_from_bytes(sb_fe_t dest[static const 1],
                      const sb_byte_t src[static const SB_ELEM_BYTES],
                      const sb_data_endian_t e)
{
    sb_wordcount_t src_i = 0;
    if (e == SB_DATA_ENDIAN_LITTLE) {
        src_i = SB_ELEM_BYTES - 1;
    }
    for (sb_wordcount_t i = 0; i < SB_FE_WORDS; i++) {
        sb_word_t t = 0;
        for (sb_wordcount_t j = 0; j < (SB_WORD_BITS / 8); j++) {
#if SB_MUL_SIZE != 1
            t <<= (sb_word_t) 8;
#endif
            t |= src[src_i];
            if (e == SB_DATA_ENDIAN_LITTLE) {
                src_i--;
            } else {
                src_i++;
            }
        }
        SB_FE_WORD(dest, SB_FE_WORDS - 1 - i) = t;
    }
}

void sb_fe_to_bytes(sb_byte_t dest[static const SB_ELEM_BYTES],
                    const sb_fe_t src[static const 1],
                    const sb_data_endian_t e)
{
    sb_wordcount_t dest_i = 0;
    if (e == SB_DATA_ENDIAN_LITTLE) {
        dest_i = SB_ELEM_BYTES - 1;
    }
    for (sb_wordcount_t i = 0; i < SB_FE_WORDS; i++) {
        sb_word_t t = SB_FE_WORD(src, SB_FE_WORDS - 1 - i);
        for (sb_wordcount_t j = 0; j < (SB_WORD_BITS / 8); j++) {
            dest[dest_i] = (sb_byte_t) (t >> (SB_WORD_BITS - 8));
#if SB_MUL_SIZE != 1
            t <<= (sb_word_t) 8;
#endif
            if (e == SB_DATA_ENDIAN_LITTLE) {
                dest_i--;
            } else {
                dest_i++;
            }
        }
    }
}

static inline sb_word_t sb_word_mask(sb_word_t a)
{
    SB_ASSERT((a == 0 || a == 1), "word used for ctc must be 0 or 1");
    return (sb_word_t) -a;
}

// Used to select one of b or c in constant time, depending on whether a is 0 or 1
static inline sb_word_t sb_ctc_word(sb_word_t a, sb_word_t b, sb_word_t c)
{
    return (sb_word_t) ((sb_word_mask(a) & (b ^ c)) ^ b);
}

sb_word_t sb_fe_equal(const sb_fe_t left[static const 1],
                      const sb_fe_t right[static const 1])
{
    sb_word_t r = 0;
    SB_UNROLL_WORDS_2(i, 0, {
        r |= SB_FE_WORD(left, i) ^ SB_FE_WORD(right, i);
    });
    // r | -r has bit SB_WORD_BITS - 1 set if r is nonzero
    // v ^ 1 is logical negation
    return ((r | ((sb_word_t) -r)) >> (sb_word_t) (SB_WORD_BITS - 1)) ^
           (sb_word_t) 1;
}

// Returns 1 if the bit is set, 0 otherwise
sb_word_t
sb_fe_test_bit(const sb_fe_t a[static const 1], const sb_bitcount_t bit)
{
    size_t word = bit >> SB_WORD_BITS_SHIFT;
    return (SB_FE_WORD(a, word) & ((sb_word_t) 1 << (bit & SB_WORD_BITS_MASK)))
        >> (bit & SB_WORD_BITS_MASK);
}

void sb_fe_set_bit(sb_fe_t a[static const 1], const sb_bitcount_t bit,
                   const sb_word_t v)
{
    size_t word = bit >> SB_WORD_BITS_SHIFT;
    sb_word_t w = SB_FE_WORD(a, word);
    w &= ~((sb_word_t) 1 << (bit & SB_WORD_BITS_MASK));
    w |= (v << (bit & SB_WORD_BITS_MASK));
    SB_FE_WORD(a, word) = w;
}

#ifdef SB_TEST

// bits must be < SB_WORD_BITS
// as used, this is one or two
static void sb_fe_rshift_w(sb_fe_t a[static const 1], const sb_bitcount_t bits)
{
    sb_word_t carry = 0;
    for (size_t i = SB_FE_WORDS - 1; i <= SB_FE_WORDS; i--) {
        sb_word_t word = SB_FE_WORD(a, i);
        SB_FE_WORD(a, i) = (word >> bits) | carry;
        carry = (sb_word_t) (word << (SB_WORD_BITS - bits));
    }
}

static void sb_fe_rshift(sb_fe_t a[static const 1], sb_bitcount_t bits)
{
    while (bits > SB_WORD_BITS) {
        sb_word_t carry = 0;
        for (size_t i = SB_FE_WORDS - 1; i <= SB_FE_WORDS; i--) {
            sb_word_t word = SB_FE_WORD(a, i);
            SB_FE_WORD(a, i) = carry;
            carry = word;
        }
        bits -= SB_WORD_BITS;
    }
    sb_fe_rshift_w(a, bits);
}

#endif

// dest MAY alias left or right
sb_word_t
sb_fe_add(sb_fe_t dest[static const 1], const sb_fe_t left[static const 1],
          const sb_fe_t right[static const 1])
{
    sb_word_t carry = 0;
    SB_UNROLL_WORDS_2(i, 0, {
        sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) +
                       (sb_dword_t) SB_FE_WORD(right, i) +
                       (sb_dword_t) carry;
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        carry = (sb_word_t) (d >> SB_WORD_BITS);
    });
    return carry;
}

// dest MAY alias left or right
static sb_word_t sb_fe_sub_borrow(sb_fe_t dest[static 1],
                                  const sb_fe_t left[static 1],
                                  const sb_fe_t right[static 1],
                                  sb_word_t borrow)
{
#if defined(__ARM_ARCH) && __ARM_ARCH >= 6 && SB_MUL_SIZE == 4

    // It seems to be difficult to get gcc to produce sbcs

#define SUB_ITER \
          "ldrd %0, %1, [%5], #8\n\t" \
          "ldrd %2, %3, [%6], #8\n\t" \
          "sbcs %0, %0, %2\n\t" \
          "sbcs %1, %1, %3\n\t" \
          "strd %0, %1, [%4], #8\n\t" \

    uint32_t l_0, l_1, r_0, r_1;
    __asm("mov  %0, #0\n\t"
          "subs %0, %0, %7\n\t" // set C based on borrow

          SUB_ITER // 0 and 1
          SUB_ITER // 2 and 3
          SUB_ITER // 4 and 5
          SUB_ITER // 6 and 7

          "mov  %7, #1\n\t"
          "sbc  %7, %7, #0\n\t" // borrow is now inverted
          "eor  %7, %7, #1\n\t"

          : "=r" (l_0), "=r" (l_1), "=r" (r_0), "=r" (r_1),
            "+r" (dest), "+r" (left), "+r" (right), "+r" (borrow),
            "=m" (*dest)
          : "m" (left), "m" (right));

#else
    SB_UNROLL_WORDS_2(i, 0, {
        sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) -
                       ((sb_dword_t) SB_FE_WORD(right, i) +
                        (sb_dword_t) borrow);
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
    return borrow;
}

sb_word_t sb_fe_sub(sb_fe_t dest[static const 1],
                    const sb_fe_t left[static const 1],
                    const sb_fe_t right[static const 1])
{
    return sb_fe_sub_borrow(dest, left, right, 0);
}

sb_word_t sb_fe_lt(const sb_fe_t left[static const 1],
                   const sb_fe_t right[static const 1])
{
    sb_word_t borrow = 0;
    SB_UNROLL_WORDS_2(i, 0, {
        sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) -
                       ((sb_dword_t) SB_FE_WORD(right, i) +
                        (sb_dword_t) borrow);
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });
    return borrow;
}

// As a ZVA countermeasure, modular operations work with "quasi-reduced" inputs
// and outputs:
// Rather than reducing to [0, M - 1], they reduce to [1, M].
// While 0 may appear as an intermediary due to the borrow/carry implementation,
// Z blinding (Coron's third countermeasure) should ensure that an attacker
// can't cause such an intermediary product deliberately.

// This applies to P-256; for secp256k1, there is no (0, Y) point on the curve.
// Similarly, for curve25519, zero values will only occur when dealing with
// a small-order subgroup of the curve. Fortuitously (or not?), P-256's prime
// has a Hamming weight very close to 256/2, which makes analyses more
// difficult, though the zero limbs might still be detectable. During
// Montgomery multiplication of a Hamming-weight-128 field element by P, most
// of the intermediaries have hamming weight close to the original, with P
// only emerging in the last iteration of the loop.

// This helper routine adds 1 or (p + 1), depending on c. Addition of 1 is done
// by adding -1 with a carry of 2; the underlying (and untested) assumption is
// that addition of a high Hamming-weight value is "closer" to adding p than
// adding zero.

static void sb_fe_cond_add_p_1(sb_fe_t dest[static 1], sb_word_t c,
                               const sb_prime_field_t p[static const 1])
{
    sb_word_t carry = sb_ctc_word(c, 2, 1);
    SB_UNROLL_WORDS_2(i, 0, {
        sb_dword_t d =
            (sb_dword_t) SB_FE_WORD(dest, i) +
            (sb_dword_t) sb_ctc_word(c, SB_FE_WORD(&SB_FE_MINUS_ONE, i),
                                        SB_FE_WORD(&p->p, i)) +
            (sb_dword_t) carry;
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        carry = (sb_word_t) (d >> SB_WORD_BITS);
    });
}

// Given quasi-reduced left and right, produce quasi-reduced left - right.
// left and right may differ by no more than the modulus, so the final addition
// of p+1 will produce output between 1 and p, inclusive.

void
sb_fe_mod_sub(sb_fe_t dest[static const 1], const sb_fe_t left[static const 1],
              const sb_fe_t right[static const 1],
              const sb_prime_field_t p[static const 1])
{
    sb_word_t b = sb_fe_sub_borrow(dest, left, right, 1);
    sb_fe_cond_add_p_1(dest, b, p);
    SB_ASSERT(sb_fe_equal(dest, &p->p) || sb_fe_lt(dest, &p->p),
              "modular subtraction must always produce quasi-reduced output");
    SB_ASSERT(!sb_fe_equal(dest, &SB_FE_ZERO),
              "modular subtraction must always produce quasi-reduced output");
}

// Given quasi-reduced left and right, produce quasi-reduced left + right.
// Consider adding (P - 1) and 1. The first addition will not overflow;
// the subtraction of P + 1 will overflow, and P + 1 will be added back
// to the result, producing P.

void
sb_fe_mod_add(sb_fe_t dest[static const 1], const sb_fe_t left[static const 1],
              const sb_fe_t right[static const 1],
              const sb_prime_field_t p[static const 1])
{
    sb_word_t c = sb_fe_add(dest, left, right);
    sb_word_t b = sb_fe_sub_borrow(dest, dest, &p->p, 1);
    // if c, add zero, since we already subtracted off the modulus
    // otherwise if b, add p
    sb_fe_cond_add_p_1(dest, b & (c ^ (sb_word_t) 1), p);
    SB_ASSERT(sb_fe_equal(dest, &p->p) || sb_fe_lt(dest, &p->p),
              "modular addition must always produce quasi-reduced output");
    SB_ASSERT(!sb_fe_equal(dest, &SB_FE_ZERO),
              "modular addition must always produce quasi-reduced output");
}

void sb_fe_mod_double(sb_fe_t dest[static const 1],
                      const sb_fe_t left[static const 1],
                      const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_add(dest, left, left, p);
}

#ifdef SB_TEST

void sb_test_fe(void)
{
    sb_fe_t res;
    assert(sb_fe_sub(&res, &SB_FE_ZERO, &SB_FE_ONE) == 1);
    for (size_t i = 0; i < SB_FE_WORDS; i++) {
        assert(SB_FE_WORD(&res, i) == (sb_word_t) -1);
    }
    assert(sb_fe_add(&res, &res, &SB_FE_ONE) == 1);
    assert(sb_fe_equal(&res, &SB_FE_ZERO));

    // all 0xFF
    assert(sb_fe_sub(&res, &SB_FE_ZERO, &SB_FE_ONE) == 1);
    sb_fe_rshift(&res, 1);
    // 0xFFFF.....FFFE
    assert(sb_fe_add(&res, &res, &res) == 0);
    // 0xFFFF.....FFFF
    assert(sb_fe_add(&res, &res, &SB_FE_ONE) == 0);
    // 0
    assert(sb_fe_add(&res, &res, &SB_FE_ONE) == 1);
    assert(sb_fe_equal(&res, &SB_FE_ZERO));
}

#endif

static inline void sb_mult_add_add(sb_word_t h[static const 1],
                                   sb_word_t l[static const 1],
                                   const sb_word_t a,
                                   const sb_word_t b,
                                   const sb_word_t c,
                                   const sb_word_t d)
{
#if defined(__ARM_FEATURE_DSP) && SB_MUL_SIZE == 4
    register int h_dest = c;
    register int l_dest = d;
    __asm("umaal %0, %1, %2, %3" : "+r" (l_dest), "+r" (h_dest) : "r" (a), "r" (b));
    *h = h_dest;
    *l = l_dest;
#else
    const sb_dword_t t =
        ((sb_dword_t) a * (sb_dword_t) b) + (sb_dword_t) c + (sb_dword_t) d;
    *h = (sb_word_t) (t >> (SB_WORD_BITS));
    *l = (sb_word_t) t;
#endif
}

static inline void sb_add_carry_2(sb_word_t h[static const 1],
                                  sb_word_t l[static const 1],
                                  const sb_word_t a,
                                  const sb_word_t b,
                                  const sb_word_t c)
{
    const sb_dword_t r = (sb_dword_t) a + (sb_dword_t) b + (sb_dword_t) c;
    *h = (sb_word_t) (r >> SB_WORD_BITS);
    *l = (sb_word_t) r;
}

void sb_fe_mont_mult(sb_fe_t A[static const restrict 1],
                     const sb_fe_t x[static const 1],
                     const sb_fe_t y[static const 1],
                     const sb_prime_field_t p[static const 1])
{
    *A = p->p; // 1. A = 0
    const sb_word_t y_0 = SB_FE_WORD(y, 0);
    sb_word_t hw = 0;

    SB_UNROLL_WORDS(i, 0, { // for i from 0 to (n - 1)
        // 2.1 u_i = (a_0 + x_i y_0) m' mod b
        const sb_word_t x_i = SB_FE_WORD(x, i);

        sb_word_t c, c2;
        sb_word_t A_0, tmp;
        sb_mult_add_add(&c, &A_0, x_i, y_0, SB_FE_WORD(A, 0), 0);

        const sb_word_t u_i =
            (sb_word_t)
                (A_0 *
                    ((sb_dword_t) p->p_mp));

        sb_mult_add_add(&c2, &tmp, u_i, SB_FE_WORD(&p->p, 0), A_0, 0);

        SB_UNROLL_WORDS(j, 1, {
            // A = A + x_i * y
            sb_mult_add_add(&c, &SB_FE_WORD(A, j),
                            x_i,
                            SB_FE_WORD(y, j),
                            SB_FE_WORD(A, j), c);

        });

        SB_UNROLL_WORDS(j, 1, {
            // A = A + u_i * m
            sb_mult_add_add(&c2, &SB_FE_WORD(A, j), u_i,
                            SB_FE_WORD(&p->p, j), SB_FE_WORD(A, j),
                            c2);
        });

        // A = A / b
        SB_UNROLL_WORDS(j, 1, { SB_FE_WORD(A, j - 1) = SB_FE_WORD(A, j); });

        sb_add_carry_2(&hw, &SB_FE_WORD(A, SB_FE_WORDS - 1), hw, c, c2);
        SB_ASSERT(hw < 2, "W + W * W + W * W overflows at most once");
    });

    // if A > m or the last iteration overflowed, subtract the modulus
    sb_word_t b = sb_fe_sub_borrow(A, A, &p->p, 1);
    // if hw, add zero, since we already subtracted off the modulus
    // otherwise if b, add p
    sb_fe_cond_add_p_1(A, b & (hw ^ (sb_word_t) 1), p);


    SB_ASSERT(sb_fe_equal(A, &p->p) || sb_fe_lt(A, &p->p),
              "Montgomery multiplication must always produce quasi-reduced output");
    SB_ASSERT(!sb_fe_equal(A, &SB_FE_ZERO),
              "Montgomery multiplication must always produce quasi-reduced output");
}

void sb_fe_mont_square(sb_fe_t dest[static const restrict 1],
                       const sb_fe_t left[static const 1],
                       const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(dest, left, left, p);
}

void sb_fe_mont_reduce(sb_fe_t dest[static const restrict 1],
                       const sb_fe_t left[static const 1],
                       const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(dest, left, &SB_FE_ONE, p);
}

#ifdef SB_TEST

void sb_test_mont_mult(void)
{
    static const sb_fe_t p256_r_inv =
        SB_FE_CONST(0xFFFFFFFE00000003, 0xFFFFFFFD00000002,
                    0x00000001FFFFFFFE, 0x0000000300000000);
    sb_fe_t t = SB_FE_ZERO;

    sb_fe_t r = SB_FE_ZERO;
    assert(sb_fe_sub(&r, &r, &SB_CURVE_P256_P.p) == 1); // r = R mod P

    sb_fe_mont_square(&t, &SB_FE_ONE, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &p256_r_inv));
    // aka R^-1 mod P

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &r));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p,
                    &p256_r_inv, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_t t2;
    sb_fe_mont_mult(&t2, &SB_CURVE_P256_N.p, &SB_CURVE_P256_P.r2_mod_p,
                    &SB_CURVE_P256_P);
    sb_fe_mont_reduce(&t, &t2, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_N.p));

    r = SB_FE_ZERO;
    assert(sb_fe_sub(&r, &r, &SB_CURVE_P256_N.p) == 1); // r = R mod N
    assert(sb_fe_equal(&r, &SB_CURVE_P256_N.r_mod_p));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_N.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_N);
    assert(sb_fe_equal(&t, &r));

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_N);
    assert(sb_fe_equal(&t, &SB_FE_ONE));

    static const sb_fe_t a5 = SB_FE_CONST(0xAA55AA55AA55AA55,
                                          0x55AA55AA55AA55AA,
                                          0xAA55AA55AA55AA55,
                                          0x55AA55AA55AA55AA);

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.p, &a5,
                    &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_P.p));
}

#endif

// Swap `b` and `c if `a` is true.
void sb_fe_ctswap(const sb_word_t a, sb_fe_t b[static const 1],
                  sb_fe_t c[static const 1])
{
    for (size_t i = 0; i < SB_FE_WORDS; i++) {
        const sb_word_t t = sb_ctc_word(a, SB_FE_WORD(b, i), SB_FE_WORD(c, i));
        SB_FE_WORD(c, i) = sb_ctc_word(a, SB_FE_WORD(c, i), SB_FE_WORD(b, i));
        SB_FE_WORD(b, i) = t;
    }
}

// x = x^e mod m

static void
sb_fe_mod_expt_r(sb_fe_t x[static const 1], const sb_fe_t e[static const 1],
                 sb_fe_t t2[static const 1], sb_fe_t t3[static const 1],
                 const sb_prime_field_t p[static const 1])
{
    _Bool by = 0;
    *t2 = p->r_mod_p;
    for (size_t i = p->bits - 1; i <= SB_FE_BITS; i--) {
        const sb_word_t b = sb_fe_test_bit(e, i);
        if (!by) {
            if (b) {
                by = 1;
            } else {
                continue;
            }
        }
        sb_fe_mont_square(t3, t2, p);
        if (b) {
            sb_fe_mont_mult(t2, t3, x, p);
        } else {
            *t2 = *t3;
        }
    }
    *x = *t2;
}

void sb_fe_mod_inv_r(sb_fe_t dest[static const 1], sb_fe_t t2[static const 1],
                     sb_fe_t t3[static const 1],
                     const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_expt_r(dest, &p->p_minus_two_f1, t2, t3, p);
    sb_fe_mod_expt_r(dest, &p->p_minus_two_f2, t2, t3, p);
}

#ifdef SB_TEST

static void
sb_fe_mod_expt(sb_fe_t x[static const 1], const sb_fe_t e[static const 1],
               sb_fe_t t2[static const 1], sb_fe_t t3[static const 1],
               const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(t2, x, &p->r2_mod_p, p);
    *x = *t2;
    sb_fe_mod_expt_r(x, e, t2, t3, p);
    sb_fe_mont_mult(t2, x, &SB_FE_ONE, p);
    *x = *t2;
}

void sb_fe_mod_inv(sb_fe_t dest[static const 1], sb_fe_t t2[static const 1],
                   sb_fe_t t3[static const 1],
                   const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_expt(dest, &p->p_minus_two_f1, t2, t3, p);
    sb_fe_mod_expt(dest, &p->p_minus_two_f2, t2, t3, p);
}

void sb_test_mod_expt_p(void)
{
    const sb_fe_t two = SB_FE_CONST(0, 0, 0, 2);
    const sb_fe_t thirtytwo = SB_FE_CONST(0, 0, 0, 32);
    const sb_fe_t two_expt_thirtytwo = SB_FE_CONST(0, 0, 0, 0x100000000);
    sb_fe_t t, t2, t3;
    t = two;
    sb_fe_mod_expt(&t, &thirtytwo, &t2, &t3, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &two_expt_thirtytwo));

    t = SB_CURVE_P256_N.p;
    sb_fe_mod_expt(&t, &SB_CURVE_P256_P.p, &t2, &t3, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^p == n

    t = SB_CURVE_P256_N.p;
    sb_fe_mod_expt(&t, &SB_FE_ONE, &t2, &t3, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^1 = n

    t = SB_CURVE_P256_P.p;
    sb_fe_sub(&t, &t, &SB_FE_ONE);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    sb_fe_add(&t, &t, &SB_FE_ONE);
    assert(sb_fe_equal(&t, &SB_CURVE_P256_P.p)); // (p-1)^-1 == (p-1)

    t = SB_FE_ONE;
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t, &SB_FE_ONE)); // 1^-1 == 1

    // t = B * R^-1
    sb_fe_mont_mult(&t, &SB_CURVE_P256.b, &SB_FE_ONE, &SB_CURVE_P256_P);

    // t = B^-1 * R
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);

    // t2 = B^-1 * R * B * R^-1 = 1
    sb_fe_mont_mult(&t2, &t, &SB_CURVE_P256.b, &SB_CURVE_P256_P);
    assert(sb_fe_equal(&t2, &SB_FE_ONE));

    // and again, mod N
    sb_fe_mont_mult(&t, &SB_CURVE_P256.b, &SB_FE_ONE, &SB_CURVE_P256_N);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_N);
    sb_fe_mont_mult(&t2, &t, &SB_CURVE_P256.b, &SB_CURVE_P256_N);
    assert(sb_fe_equal(&t2, &SB_FE_ONE));
}

#endif
