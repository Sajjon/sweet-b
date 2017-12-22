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

#include "sb_test.h"
#include "sb_fe.h"
#include "sb_sw_curves.h"

// ARM assembly is provided for Thumb-2 and 32-bit ARMv6 and later targets.
// If you have DSP extensions, the UMAAL instruction is used, which provides
// substantially better multiplication performance. The following bit of
// preprocessor crud tests whether you have a target for which the assembly
// is supported. If this does not work for you (you're not getting assembly
// on a target where you expect it or the assembly generated does not work
// for your target), you can define SB_USE_ARM_ASM explicitly, but please
// also file a GitHub issue!

#ifndef SB_USE_ARM_ASM
#if (defined(__thumb__) && defined(__ARM_ARCH_ISA_THUMB) && \
     __ARM_ARCH_ISA_THUMB >= 2) || \
    (!defined(__thumb__) && defined(__ARM_ARCH) && __ARM_ARCH >= 6 && \
     !defined(__aarch64__)) && \
    SB_MUL_SIZE == 4
#define SB_USE_ARM_ASM 1
#if defined(__ARM_FEATURE_DSP) && !defined(SB_USE_ARM_DSP_ASM)
#define SB_USE_ARM_DSP_ASM 1
#endif
#else
#define SB_USE_ARM_ASM 0
#endif
#endif

#if !defined(SB_USE_ARM_DSP_ASM)
#define SB_USE_ARM_DSP_ASM 0
#endif

#if SB_USE_ARM_DSP_ASM && !SB_USE_ARM_ASM
#error "Conflicting options: SB_USE_ARM_DSP_ASM implies SB_USE_ARM_ASM"
#endif

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
    SB_UNROLL_3(i, 0, {
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

#if SB_USE_ARM_ASM
    register sb_word_t l_0 __asm("r4");
    register sb_word_t l_1 __asm("r5");
    register sb_word_t r_0 __asm("r6");
    register sb_word_t r_1 __asm("r7");

#define ADD_ITER(add_0, i_0, i_1) \
          "ldrd %[l_0], %[l_1], [%[left], #" i_0 "]\n\t" \
          "ldrd %[r_0], %[r_1], [%[right], #" i_0 "]\n\t" \
          add_0 " %[l_0], %[l_0], %[r_0]\n\t" \
          "str  %[l_0], [%[dest], #" i_0 "]\n\t" \
          "adcs %[l_1], %[l_1], %[r_1]\n\t" \
          "str  %[l_1], [%[dest], #" i_1 "]\n\t" \

    __asm(ADD_ITER("adds", "0", "4") // 0 and 1
          ADD_ITER("adcs", "8", "12") // 2 and 3
          ADD_ITER("adcs", "16", "20") // 4 and 5
          ADD_ITER("adcs", "24", "28") // 6 and 7

          "adc  %[carry], %[carry], #0\n\t" // move C into carry

          : [l_0] "=&r" (l_0), [l_1] "=&r" (l_1),
            [r_0] "=&r" (r_0), [r_1] "=&r" (r_1),
            [carry] "+&r" (carry), "=m" (*dest)
          : [left] "r" (left), [right] "r" (right), [dest] "r" (dest),
            "m" (*left), "m" (*right)
          : "cc");

#else
    SB_UNROLL_2(i, 0, {
        sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) +
                       (sb_dword_t) SB_FE_WORD(right, i) +
                       (sb_dword_t) carry;
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        carry = (sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
    return carry;
}

// dest MAY alias left or right
static sb_word_t sb_fe_sub_borrow(sb_fe_t dest[static 1],
                                  const sb_fe_t left[static 1],
                                  const sb_fe_t right[static 1],
                                  sb_word_t borrow)
{

#if SB_USE_ARM_ASM
    register sb_word_t l_0 __asm("r4");
    register sb_word_t l_1 __asm("r5");
    register sb_word_t r_0 __asm("r6");
    register sb_word_t r_1 __asm("r7");

    // It seems to be difficult to get gcc to produce sbcs

#define SUB_ITER(sub, s_0, s_1, i) \
          "ldrd %[l_0], %[l_1], [%[left], # " i "]\n\t" \
          "ldrd %[r_0], %[r_1], [%[right], # " i "]\n\t" \
          sub " %[l_0], %[l_0], %[r_0]\n\t" \
          s_0 \
          "sbcs %[l_1], %[l_1], %[r_1]\n\t" \
          s_1

#define SUB_ITER_STORE(sub, i_0, i_1) \
          SUB_ITER(sub, "str %[l_0], [%[dest], #" i_0 "]\n\t", \
                        "str %[l_1], [%[dest], #" i_1 "]\n\t", i_0) \

    __asm("rsbs %[b], #0\n\t"
          SUB_ITER_STORE("sbcs", "0", "4") // 0 and 1
          SUB_ITER_STORE("sbcs", "8", "12") // 2 and 3
          SUB_ITER_STORE("sbcs", "16", "20") // 4 and 5
          SUB_ITER_STORE("sbcs", "24", "28") // 6 and 7

          "sbc  %[b], %[b], %[b]\n\t"
          "rsb  %[b], #0\n\t"

          : [l_0] "=&r" (l_0), [l_1] "=&r" (l_1),
            [r_0] "=&r" (r_0), [r_1] "=&r" (r_1),
            [b] "+&r" (borrow), "=m" (*dest)
          : [left] "r" (left), [right] "r" (right), [dest] "r" (dest),
            "m" (*left), "m" (*right) : "cc");

#else
    SB_UNROLL_2(i, 0, {
        sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) -
                       ((sb_dword_t) SB_FE_WORD(right, i) +
                        (sb_dword_t) borrow);
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
    return borrow;
}


sb_word_t sb_fe_sub(sb_fe_t dest[static 1],
                    const sb_fe_t left[static 1],
                    const sb_fe_t right[static 1])
{
    return sb_fe_sub_borrow(dest, left, right, 0);
}

sb_word_t sb_fe_lt(const sb_fe_t left[static 1],
                   const sb_fe_t right[static 1])
{
    sb_word_t borrow = 0;

#if SB_USE_ARM_ASM
    register sb_word_t l_0 __asm("r4");
    register sb_word_t l_1 __asm("r5");
    register sb_word_t r_0 __asm("r6");
    register sb_word_t r_1 __asm("r7");

    __asm(SUB_ITER("subs", "", "", "0") // 0 and 1
          SUB_ITER("sbcs", "", "", "8") // 2 and 3
          SUB_ITER("sbcs", "", "", "16") // 4 and 5
          SUB_ITER("sbcs", "", "", "24") // 6 and 7

          "sbc  %[b], %[b], %[b]\n\t"
          "rsb  %[b], #0\n\t"

          : [l_0] "=&r" (l_0), [l_1] "=&r" (l_1),
            [r_0] "=&r" (r_0),  [r_1] "=&r" (r_1),
            [b] "+&r" (borrow)
          : [left] "r" (left), [right] "r" (right),
            "m" (*left), "m" (*right) : "cc");
#else
    SB_UNROLL_3(i, 0, {
        sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) -
                       ((sb_dword_t) SB_FE_WORD(right, i) +
                        (sb_dword_t) borrow);
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
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

// This helper routine subtracts p if c is 1; the subtraction is done
// unconditionally, and the result is only written if c is 1
static void sb_fe_cond_sub_p(sb_fe_t dest[static 1], sb_word_t c,
                             const sb_fe_t p[static 1])
{
#if SB_USE_ARM_ASM
    register sb_word_t l_0 __asm("r4");
    register sb_word_t l_1 __asm("r5");
    register sb_word_t r_0 __asm("r6");
    register sb_word_t r_1 __asm("r7");
    c = sb_word_mask(c);

#if SB_USE_ARM_DSP_ASM

    // set GE bits
#define SB_COND_STORE_SET "uadd8 %[l_0], %[c], %[c]\n\t"
#define SB_COND_STORE_SEL(l, r, c) "sel %[" l "], %[" r "], %[" l "]\n\t"

#else

#define SB_COND_STORE_SET ""
#define SB_COND_STORE_SEL(l, r, c) \
          "eor  %[" r "], %[" l "], %[" r "]\n\t" \
          "and  %[" r "], %[" r "], %[" c "]\n\t" \
          "eor  %[" l "], %[" l "], %[" r "]\n\t" \

#endif

#define SB_ITER_COND_STORE(ops, opcs, i_0, i_1) \
          "ldrd  %[l_0], %[l_1], [%[dest], #" i_0 "]\n\t" \
          "ldrd  %[r_0], %[r_1], [%[p], #" i_0 "]\n\t" \
          ops  " %[r_0], %[l_0], %[r_0]\n\t" \
          opcs " %[r_1], %[l_1], %[r_1]\n\t" \
          SB_COND_STORE_SEL("l_0", "r_0", "c") \
          "str   %[l_0], [%[dest], #" i_0 "]\n\t" \
          SB_COND_STORE_SEL("l_1", "r_1", "c") \
          "str   %[l_1], [%[dest], #" i_1 "]\n\t" \

    __asm(SB_COND_STORE_SET

          SB_ITER_COND_STORE("subs", "sbcs", "0", "4") // 0 and 1
          SB_ITER_COND_STORE("sbcs", "sbcs", "8", "12") // 2 and 3
          SB_ITER_COND_STORE("sbcs", "sbcs", "16", "20") // 4 and 5
          SB_ITER_COND_STORE("sbcs", "sbcs", "24", "28") // 6 and 7

          : [l_0] "=&r" (l_0), [l_1] "=&r" (l_1),
            [r_0] "=&r" (r_0), [r_1] "=&r" (r_1),
            "=m" (*dest)
          : [dest] "r" (dest), [p] "r" (p), [c] "r" (c),
            "m" (*dest), "m" (*p) : "cc");

#else
    sb_word_t borrow = 0;

    SB_UNROLL_2(i, 0, {
        sb_dword_t d = (sb_dword_t) SB_FE_WORD(dest, i) -
                       ((sb_dword_t) SB_FE_WORD(p, i) +
                        (sb_dword_t) borrow);
        SB_FE_WORD(dest, i) = sb_ctc_word(c, SB_FE_WORD(dest, i),
                                          (sb_word_t) d);
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
}

// Quasi-reduce dest (with extra carry bit) by subtracting p iff dest is
// greater than p
void sb_fe_qr(sb_fe_t dest[static const 1], sb_word_t const carry,
              const sb_prime_field_t p[static const 1])
{
    sb_word_t b = sb_fe_lt(&p->p, dest);
    sb_fe_cond_sub_p(dest, carry | b, &p->p);
    SB_ASSERT(sb_fe_equal(dest, &p->p) || sb_fe_lt(dest, &p->p),
              "quasi-reduction must always produce quasi-reduced output");
    SB_ASSERT(!sb_fe_equal(dest, &SB_FE_ZERO),
              "quasi-reduction must always produce quasi-reduced output");
}

// This helper adds 1 or (p + 1), depending on c. On ARM, this is done by
// adding p then choosing to store either the original value or the result of
// the addition, followed by a second pass to add 1.
static void sb_fe_cond_add_p_1(sb_fe_t dest[static 1], sb_word_t c,
                               const sb_fe_t p[static 1])
{
#if SB_USE_ARM_ASM
    register sb_word_t l_0 __asm("r4");
    register sb_word_t l_1 __asm("r5");
    register sb_word_t r_0 __asm("r6");
    register sb_word_t r_1 __asm("r7");
    c = sb_word_mask(c);

#define ADD_1_ITER(add_0, add_0_v, i_0, i_1) \
          "ldrd %[l_0], %[l_1], [%[dest], #" i_0 "]\n\t" \
          add_0 " %[l_0], %[l_0], #" add_0_v "\n\t" \
          "str  %[l_0], [%[dest], #" i_0 "]\n\t" \
          "adcs %[l_1], %[l_1], #0\n\t" \
          "str  %[l_1], [%[dest], #" i_1 "]\n\t" \

    __asm(SB_COND_STORE_SET

          SB_ITER_COND_STORE("adds", "adcs", "0", "4") // 0 and 1
          SB_ITER_COND_STORE("adcs", "adcs", "8", "12") // 2 and 3
          SB_ITER_COND_STORE("adcs", "adcs", "16", "20") // 4 and 5
          SB_ITER_COND_STORE("adcs", "adcs", "24", "28") // 6 and 7

          ADD_1_ITER("adds", "1", "0", "4")
          ADD_1_ITER("adcs", "0", "8", "12")
          ADD_1_ITER("adcs", "0", "16", "20")
          ADD_1_ITER("adcs", "0", "24", "28")

          : [l_0] "=&r" (l_0), [l_1] "=&r" (l_1),
            [r_0] "=&r" (r_0), [r_1] "=&r" (r_1),
            "=m" (*dest)
          : [dest] "r" (dest), [p] "r" (p), [c] "r" (c),
            "m" (*dest), "m" (*p) : "cc");

#else
    sb_word_t carry = 1;

    SB_UNROLL_2(i, 0, {
        sb_dword_t d = (sb_dword_t) SB_FE_WORD(dest, i) +
                       (sb_dword_t) sb_ctc_word(c, 0, SB_FE_WORD(p, i)) +
                       (sb_dword_t) carry;
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        carry = (sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
}


// Given quasi-reduced left and right, produce quasi-reduced left - right.
// This is done as a subtraction of (right - 1) followed by addition of
// 1 or (p + 1), which means that a result of all zeros is never written back
// to memory.
void
sb_fe_mod_sub(sb_fe_t dest[static const 1], const sb_fe_t left[static const 1],
              const sb_fe_t right[static const 1],
              const sb_prime_field_t p[static const 1])
{
    sb_word_t b = sb_fe_sub_borrow(dest, left, right, 1);
    sb_fe_cond_add_p_1(dest, b, &p->p);
    SB_ASSERT(sb_fe_equal(dest, &p->p) || sb_fe_lt(dest, &p->p),
              "modular subtraction must always produce quasi-reduced output");
    SB_ASSERT(!sb_fe_equal(dest, &SB_FE_ZERO),
              "modular subtraction must always produce quasi-reduced output");
}

// Given quasi-reduced left and right, produce quasi-reduced left + right.

void
sb_fe_mod_add(sb_fe_t dest[static const 1], const sb_fe_t left[static const 1],
              const sb_fe_t right[static const 1],
              const sb_prime_field_t p[static const 1])
{
    sb_word_t carry = sb_fe_add(dest, left, right);
    sb_fe_qr(dest, carry, p);
}

void sb_fe_mod_double(sb_fe_t dest[static const 1],
                      const sb_fe_t left[static const 1],
                      const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_add(dest, left, left, p);
}

#ifdef SB_TEST

_Bool sb_test_fe(void)
{
    sb_fe_t res;
    SB_TEST_ASSERT(sb_fe_sub(&res, &SB_FE_ZERO, &SB_FE_ONE) == 1);
    for (size_t i = 0; i < SB_FE_WORDS; i++) {
        SB_TEST_ASSERT(SB_FE_WORD(&res, i) == (sb_word_t) -1);
    }
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &SB_FE_ONE) == 1);
    SB_TEST_ASSERT(sb_fe_equal(&res, &SB_FE_ZERO));

    // all 0xFF
    SB_TEST_ASSERT(sb_fe_sub(&res, &SB_FE_ZERO, &SB_FE_ONE) == 1);
    sb_fe_rshift(&res, 1);
    // 0xFFFF.....FFFE
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &res) == 0);
    // 0xFFFF.....FFFF
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &SB_FE_ONE) == 0);
    // 0
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &SB_FE_ONE) == 1);
    SB_TEST_ASSERT(sb_fe_equal(&res, &SB_FE_ZERO));
    return 1;
}

#endif

static inline void sb_mult_add_add(sb_word_t h[static const 1],
                                   sb_word_t l[static const 1],
                                   const sb_word_t a,
                                   const sb_word_t b,
                                   const sb_word_t c,
                                   const sb_word_t d)
{
#if SB_USE_ARM_DSP_ASM
    register sb_word_t h_dest = c;
    register sb_word_t l_dest = d;
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
#if SB_USE_ARM_DSP_ASM && SB_UNROLL > 0

    sb_word_t hw, c, c2, x_i, u_i;
    // Is there some arcane constraint syntax to force v_0 and v_1 to be in
    // adjacent registers?
    register sb_word_t A_j_0 __asm("r4");
    register sb_word_t A_j_1 __asm("r5");
    register sb_word_t y_j_0 __asm("r6");
    register sb_word_t y_j_1 __asm("r7");
#if SB_UNROLL < 3
    sb_word_t i;
#endif

#define MM_ITER_MUL(A_0, A_1, j, e, s_0, s_1) \
        "ldrd  %[y_j_0], %[y_j_1], [%[y], #" j "]\n\t" \
        A_0 \
        "umaal %[A_j_0], %[c], %[x_i], %[y_j_0]\n\t" \
        A_1 \
        "umaal %[A_j_1], %[c], %[x_i], %[y_j_1]\n\t" \
        e \
        "ldrd  %[y_j_0], %[y_j_1], [%[p], #" j "]\n\t" \
        "umaal %[A_j_0], %[c2], %[u_i], %[y_j_0]\n\t" \
        s_0 \
        "umaal %[A_j_1], %[c2], %[u_i], %[y_j_1]\n\t" \
        s_1

#define MM_ITER_1_I(j, e, s_0, s_1) \
        MM_ITER_MUL("mov %[A_j_0], #0\n\t", "mov %[A_j_1], #0\n\t", \
                   j, e, s_0, s_1)

#define MM_ITER_2_I(j, e, s_0, s_1) \
        MM_ITER_MUL("ldrd %[A_j_0], %[A_j_1], [%[A], #" j "]\n\t", "", \
                    j, e, s_0, s_1)

#define MM_ITER(M, add, i) \
    "mov   %[c], #0\n\t" \
    "mov   %[c2], #0\n\t" \
    "ldr   %[x_i], [%[x], " i "]\n\t" \
    M("0", "mul %[u_i], %[A_j_0], %[hw]\n\t", "", "str %[A_j_1], [%[A]]\n\t") \
    M("8", "", "str %[A_j_0], [%[A], #4]\n\t", \
               "str %[A_j_1], [%[A], #8]\n\t") \
    M("16", "", "str %[A_j_0], [%[A], #12]\n\t", \
                "str %[A_j_1], [%[A], #16]\n\t") \
    M("24", "", "str %[A_j_0], [%[A], #20]\n\t", \
                "str %[A_j_1], [%[A], #24]\n\t") \
    add "  %[A_j_0], %[c], %[c2]\n\t" \
    "str   %[A_j_0], [%[A], #28]\n\t" \

    __asm(
    "ldr  %[hw], [%[p], #32]\n\t" // use hw as p->mp
    MM_ITER(MM_ITER_1_I, "adds", "#0")
#if SB_UNROLL < 3
    "mov %[i], #4\n\t"
    ".L_mont_mul_loop: "
    MM_ITER(MM_ITER_2_I, "adcs", "%[i]")
    "add %[i], #4\n\t"
    "tst %[i], #32\n\t"
    "beq .L_mont_mul_loop\n\t"
#else
    MM_ITER(MM_ITER_2_I, "adcs", "#4")
    MM_ITER(MM_ITER_2_I, "adcs", "#8")
    MM_ITER(MM_ITER_2_I, "adcs", "#12")
    MM_ITER(MM_ITER_2_I, "adcs", "#16")
    MM_ITER(MM_ITER_2_I, "adcs", "#20")
    MM_ITER(MM_ITER_2_I, "adcs", "#24")
    MM_ITER(MM_ITER_2_I, "adcs", "#28")
#endif
    "mov %[hw], #0\n\t"
    "adc %[hw], %[hw], #0\n\t"
    : [A_j_0] "=&r" (A_j_0), [A_j_1] "=&r" (A_j_1),
      [y_j_0] "=&r" (y_j_0), [y_j_1] "=&r" (y_j_1),
      [c] "=&r" (c), [c2] "=&r" (c2),
      [u_i] "=&r" (u_i), [hw] "=&r" (hw),
#if SB_UNROLL < 3
      [i] "=&r" (i),
#endif
      [x_i] "=&r" (x_i), "=m" (*A)
    : [A] "r" (A), [y] "r" (y), [p] "r" (p), [x] "r" (x),
      "m" (*x), "m" (*y), "m" (*p) :
      "cc");

#else

    sb_word_t hw = 0;

    SB_UNROLL_2(i, 0, { // for i from 0 to (n - 1)
        const sb_word_t x_i = SB_FE_WORD(x, i);

        sb_word_t c = 0, c2 = 0;

        SB_UNROLL_1(j, 0, {
            const sb_word_t A_j = (i == 0) ? 0 : SB_FE_WORD(A, j);
            // A = A + x_i * y
            sb_mult_add_add(&c, &SB_FE_WORD(A, j),
            x_i,
            SB_FE_WORD(y, j),
            A_j, c);

        });

        // u_i = (a_0 + x_i y_0) m' mod b
        const sb_word_t u_i =
            (sb_word_t)
                (SB_FE_WORD(A, 0) *
                 ((sb_dword_t) p->p_mp));

        SB_UNROLL_1(j, 0, {
            // A = A + u_i * m
            sb_mult_add_add(&c2, &SB_FE_WORD(A, j), u_i,
                            SB_FE_WORD(&p->p, j), SB_FE_WORD(A, j),
                            c2);
        });

        // A = A / b
        SB_UNROLL_1(j, 1, { SB_FE_WORD(A, j - 1) = SB_FE_WORD(A, j); });

        sb_add_carry_2(&hw, &SB_FE_WORD(A, SB_FE_WORDS - 1), hw, c, c2);
        SB_ASSERT(hw < 2, "W + W * W + W * W overflows at most once");
    });

#endif

    sb_fe_qr(A, hw, p);
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

_Bool sb_test_mont_mult(void)
{
    static const sb_fe_t p256_r_inv =
        SB_FE_CONST(0xFFFFFFFE00000003, 0xFFFFFFFD00000002,
                    0x00000001FFFFFFFE, 0x0000000300000000);
    sb_fe_t t = SB_FE_ZERO;

    sb_fe_t r = SB_FE_ZERO;
    SB_TEST_ASSERT(sb_fe_sub(&r, &r, &SB_CURVE_P256_P.p) == 1); // r = R mod P

    sb_fe_mont_square(&t, &SB_FE_ONE, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &p256_r_inv));
    // aka R^-1 mod P

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &r));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p,
                    &p256_r_inv, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_t t2;
    sb_fe_mont_mult(&t2, &SB_CURVE_P256_N.p, &SB_CURVE_P256_P.r2_mod_p,
                    &SB_CURVE_P256_P);
    sb_fe_mont_reduce(&t, &t2, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_N.p));

    r = SB_FE_ZERO;
    SB_TEST_ASSERT(sb_fe_sub(&r, &r, &SB_CURVE_P256_N.p) == 1); // r = R mod N
    SB_TEST_ASSERT(sb_fe_equal(&r, &SB_CURVE_P256_N.r_mod_p));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_N.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_N);
    SB_TEST_ASSERT(sb_fe_equal(&t, &r));

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_N);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE));

    static const sb_fe_t a5 = SB_FE_CONST(0xAA55AA55AA55AA55,
                                          0x55AA55AA55AA55AA,
                                          0xAA55AA55AA55AA55,
                                          0x55AA55AA55AA55AA);

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.p, &a5,
                    &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_P.p));
    return 1;
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

static void sb_fe_mod_inv(sb_fe_t dest[static const 1],
                          sb_fe_t t2[static const 1],
                          sb_fe_t t3[static const 1],
                          const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_expt(dest, &p->p_minus_two_f1, t2, t3, p);
    sb_fe_mod_expt(dest, &p->p_minus_two_f2, t2, t3, p);
}

_Bool sb_test_mod_expt_p(void)
{
    const sb_fe_t two = SB_FE_CONST(0, 0, 0, 2);
    const sb_fe_t thirtytwo = SB_FE_CONST(0, 0, 0, 32);
    const sb_fe_t two_expt_thirtytwo = SB_FE_CONST(0, 0, 0, 0x100000000);
    sb_fe_t t, t2, t3;
    t = two;
    sb_fe_mod_expt(&t, &thirtytwo, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &two_expt_thirtytwo));

    t = SB_CURVE_P256_N.p;
    sb_fe_mod_expt(&t, &SB_CURVE_P256_P.p, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^p == n

    t = SB_CURVE_P256_N.p;
    sb_fe_mod_expt(&t, &SB_FE_ONE, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^1 = n

    t = SB_CURVE_P256_P.p;
    sb_fe_sub(&t, &t, &SB_FE_ONE);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    sb_fe_add(&t, &t, &SB_FE_ONE);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_P.p)); // (p-1)^-1 == (p-1)

    t = SB_FE_ONE;
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE)); // 1^-1 == 1

    // t = B * R^-1
    sb_fe_mont_mult(&t, &SB_CURVE_P256.b, &SB_FE_ONE, &SB_CURVE_P256_P);

    // t = B^-1 * R
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);

    // t2 = B^-1 * R * B * R^-1 = 1
    sb_fe_mont_mult(&t2, &t, &SB_CURVE_P256.b, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t2, &SB_FE_ONE));

    // and again, mod N
    sb_fe_mont_mult(&t, &SB_CURVE_P256.b, &SB_FE_ONE, &SB_CURVE_P256_N);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_N);
    sb_fe_mont_mult(&t2, &t, &SB_CURVE_P256.b, &SB_CURVE_P256_N);
    SB_TEST_ASSERT(sb_fe_equal(&t2, &SB_FE_ONE));
    return 1;
}

#endif
