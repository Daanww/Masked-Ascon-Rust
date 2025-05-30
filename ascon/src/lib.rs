// Copyright 2021-2022 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo.svg"
)]
// #![forbid(unsafe_code)]
// #![warn(missing_docs)]

#[cfg(target_arch = "riscv32")]
use core::arch::asm;

use core::mem::size_of;
use core::ops::{BitXor, BitXorAssign, Not};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Produce mask for padding.
#[inline(always)]
pub const fn pad(n: usize) -> u64 {
    0x80_u64 << (56 - 8 * n)
}

/// Compute round constant
#[inline(always)]
const fn round_constant(round: u64) -> u64 {
    ((0xfu64 - round) << 4) | round
}

/// The state of Ascon's permutation.
///
/// The permutation operates on a state of 320 bits represented as 5 64 bit words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub x: [u64; 5],
}

// c data system: State = word_t x[6], word_t = share_t s[NUM_SHARES_KEY], share_t = uint32_t w[2]
// rust data system: Masked_State = x [Shares; 5], Shares = s [Word; NUM_SHARES], Word = (u32,u32)

pub const NUM_SHARES: usize = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Word(pub u32, pub u32);

impl Word {
    pub fn rotate_right(self, n: usize) -> Self {
        if n < 32 {
            Word(
                (self.1 << (32 - n)) | (self.0 >> n),
                (self.0 << (32 - n)) | (self.1 >> n),
            )
        } else {
            Word(self.1, self.0).rotate_right(n - 32)
        }
    }
}

impl From<u64> for Word {
    fn from(value: u64) -> Self {
        Word((value >> 32) as u32, value as u32)
    }
}

impl From<Word> for u64 {
    fn from(value: Word) -> Self {
        (value.0 as u64) << 32 | (value.1 as u64)
    }
}

impl BitXor for Word {
    type Output = Word;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Word(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl BitXorAssign for Word {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
        self.1 ^= rhs.1;
    }
}

impl Not for Word {
    type Output = Word;

    fn not(self) -> Self::Output {
        Word(!self.0, !self.1)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Shares {
    pub s: [Word; NUM_SHARES],
}

impl Shares {
    pub fn new() -> Self {
        Shares {
            s: [Word::default(); NUM_SHARES],
        }
    }

    pub fn combine_shares(self) -> u64 {
        // Both ideas are equivalent, the folding is just a bit cooler.

        // let mut x = 0;
        // for i in 0..NUM_SHARES {
        //     x ^= self.s[i];
        // }
        // x
        self.s
            .into_iter()
            .fold(0, |acc, x| acc ^ Into::<u64>::into(x))
    }
}

impl BitXorAssign for Shares {
    fn bitxor_assign(&mut self, rhs: Self) {
        for i in 0..NUM_SHARES {
            self.s[i] ^= rhs.s[i];
        }
    }
}

impl BitXor for Shares {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut w = Shares::default();
        for i in 0..NUM_SHARES {
            w.s[i] = self.s[i] ^ rhs.s[i];
        }
        w
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaskedState {
    pub x: [Shares; 5],
}

/*#define EOR_AND_ROR(ce, ae, be, imm, tmp) \
77   │     do {                                  \
78   │         ROR(tmp, be, ROT(imm));                \
79   │         __asm__ volatile(                       \
80   │             "and %[tmp_], %[ae_], %[tmp_] \n\t"  \
81   │             "xor %[ce_], %[tmp_], %[ce_] \n\t"    \
82   │             : [ce_] "+r"(ce), [tmp_] "+r"(tmp) : [ae_] "r"(ae));\
83   │     } while (0) */
// #[cfg(target_arch = "riscv32")]
// #[inline(always)]
// fn eor_and(c: &mut u64, a: u64, b: u64) {
//     // This is extremely inefficient but I do not care atm

//     let Word(mut cw0, mut cw1) = (*c).into();
//     let Word(aw0, aw1) = a.into();
//     let Word(bw0, bw1) = b.into();
//     unsafe {
//         asm!(
//             "and {tmp}, {a0}, {b0}",
//             "xor {c0}, {tmp}, {c0}",
//             tmp = out(reg) _,
//             a0 = in(reg) aw0,
//             b0 = in(reg) bw0,
//             c0 = inout(reg) cw0,
//         );
//         asm!(
//             "and {tmp}, {a1}, {b1}",
//             "xor {c1}, {tmp}, {c1}",
//             tmp = out(reg) _,
//             a1 = in(reg) aw1,
//             b1 = in(reg) bw1,
//             c1 = inout(reg) cw1,
//         );
//     }
//     *c = Word(cw0, cw1).into();
// }

// #[cfg(not(target_arch = "riscv32"))]
// #[inline(always)]
// fn eor_and(c: &mut u64, a: u64, b: u64) {
//     *c ^= a & b
// }

// #[inline(always)]
// fn eor_and(c: &mut u32, a: u32, b: u32) {
//     *c ^= a & b
// }

#[cfg(not(target_arch = "riscv32"))]
#[inline(always)]
fn eor_and(c: &mut Word, a: Word, b: Word) {
    c.0 ^= a.0 & b.0;
    c.1 ^= a.1 & b.1;
}

#[cfg(target_arch = "riscv32")]
#[inline(always)]
fn eor_and(c: &mut Word, a: Word, b: Word) {
    unsafe {
        asm!(
            "and {tmp}, {a0}, {b0}",
            "xor {c0}, {tmp}, {c0}",
            tmp = out(reg) _,
            a0 = in(reg) a.0,
            b0 = in(reg) b.0,
            c0 = inout(reg) c.0,
        );
        asm!(
            "and {tmp}, {a1}, {b1}",
            "xor {c1}, {tmp}, {c1}",
            tmp = out(reg) _,
            a1 = in(reg) a.1,
            b1 = in(reg) b.1,
            c1 = inout(reg) c.1,
        );
    }
}

/*#define EOR_BIC_ROR(ce, ae, be, imm, tmp) \
86   │     do {                                  \
87   │         ROR(tmp, be, ROT(imm));                \
88   │         __asm__ volatile(                 \
89   │             "xori %[tmp_], %[tmp_], -1 \n\t"     \
90   │             "and %[tmp_], %[ae_], %[tmp_] \n\t"  \
91   │             "xor %[ce_], %[tmp_], %[ce_] \n\t"    \
92   │             : [ce_] "+r"(ce), [tmp_] "+r"(tmp) : [ae_] "r"(ae));\
93   │     } while (0) */
// #[cfg(target_arch = "riscv32")]
// #[inline(always)]
// fn eor_bic(c: &mut u64, a: u64, b: u64) {
//     // This is extremely inefficient but I do not care atm

//     let Word(mut cw0, mut cw1) = (*c).into();
//     let Word(aw0, aw1) = a.into();
//     let Word(bw0, bw1) = b.into();
//     unsafe {
//         asm!(
//             "xori {tmp}, {b0}, -1",
//             "and {tmp}, {a0}, {tmp}",
//             "xor {c0}, {tmp}, {c0}",
//             tmp = out(reg) _,
//             a0 = in(reg) aw0,
//             b0 = in(reg) bw0,
//             c0 = inout(reg) cw0,
//         );
//         asm!(
//             "xori {tmp}, {b1}, -1",
//             "and {tmp}, {a1}, {tmp}",
//             "xor {c1}, {tmp}, {c1}",
//             tmp = out(reg) _,
//             a1 = in(reg) aw1,
//             b1 = in(reg) bw1,
//             c1 = inout(reg) cw1,
//         );
//     }
//     *c = Word(cw0, cw1).into();
// }

// #[cfg(not(target_arch = "riscv32"))]
// #[inline(always)]
// fn eor_bic(c: &mut u64, a: u64, b: u64) {
//     *c ^= a & !b
// }

// #[inline(always)]
// fn eor_bic(c: &mut u32, a: u32, b: u32) {
//     *c ^= a & !b
// }

#[cfg(not(target_arch = "riscv32"))]
#[inline(always)]
fn eor_bic(c: &mut Word, a: Word, b: Word) {
    c.0 ^= a.0 & !b.0;
    c.1 ^= a.1 & !b.1;
}

#[cfg(target_arch = "riscv32")]
#[inline(always)]
fn eor_bic(c: &mut Word, a: Word, b: Word) {
    unsafe {
        asm!(
            "xori {tmp}, {b0}, -1",
            "and {tmp}, {a0}, {tmp}",
            "xor {c0}, {tmp}, {c0}",
            tmp = out(reg) _,
            a0 = in(reg) a.0,
            b0 = in(reg) b.0,
            c0 = inout(reg) c.0,
        );
        asm!(
            "xori {tmp}, {b1}, -1",
            "and {tmp}, {a1}, {tmp}",
            "xor {c1}, {tmp}, {c1}",
            tmp = out(reg) _,
            a1 = in(reg) a.1,
            b1 = in(reg) b.1,
            c1 = inout(reg) c.1,
        );
    }
}

/*#define EOR_ORR_ROR(ce, ae, be, imm, tmp) \
 96   │     do {                                  \
 97   │         ROR(tmp, be, ROT(imm));                \
 98   │         __asm__ volatile(                       \
 99   │             "or  %[tmp_], %[ae_], %[tmp_] \n\t"  \
100   │             "xor %[ce_], %[tmp_], %[ce_] \n\t"    \
101   │             : [ce_] "+r"(ce), [tmp_] "+r"(tmp) : [ae_] "r"(ae));\
102   │     } while (0) */
// #[cfg(target_arch = "riscv32")]
// #[inline(always)]
// fn eor_orr(c: &mut u64, a: u64, b: u64) {
//     // This is extremely inefficient but I do not care atm

//     let Word(mut cw0, mut cw1) = (*c).into();
//     let Word(aw0, aw1) = a.into();
//     let Word(bw0, bw1) = b.into();
//     unsafe {
//         asm!(
//             "or {tmp}, {a0}, {b0}",
//             "xor {c0}, {tmp}, {c0}",
//             tmp = out(reg) _,
//             a0 = in(reg) aw0,
//             b0 = in(reg) bw0,
//             c0 = inout(reg) cw0,
//         );
//         asm!(
//             "or {tmp}, {a1}, {b1}",
//             "xor {c1}, {tmp}, {c1}",
//             tmp = out(reg) _,
//             a1 = in(reg) aw1,
//             b1 = in(reg) bw1,
//             c1 = inout(reg) cw1,
//         );
//     }
//     *c = Word(cw0, cw1).into();
// }

// #[cfg(not(target_arch = "riscv32"))]
// #[inline(always)]
// fn eor_orr(c: &mut u64, a: u64, b: u64) {
//     *c ^= a | b
// }

// #[inline(always)]
// fn eor_orr(c: &mut u32, a: u32, b: u32) {
//     *c ^= a | b
// }

#[cfg(not(target_arch = "riscv32"))]
#[inline(always)]
fn eor_orr(c: &mut Word, a: Word, b: Word) {
    c.0 ^= a.0 | b.0;
    c.1 ^= a.1 | b.1;
}

#[cfg(target_arch = "riscv32")]
#[inline(always)]
fn eor_orr(c: &mut Word, a: Word, b: Word) {
    unsafe {
        asm!(
            "or {tmp}, {a0}, {b0}",
            "xor {c0}, {tmp}, {c0}",
            tmp = out(reg) _,
            a0 = in(reg) a.0,
            b0 = in(reg) b.0,
            c0 = inout(reg) c.0,
        );
        asm!(
            "or {tmp}, {a1}, {b1}",
            "xor {c1}, {tmp}, {c1}",
            tmp = out(reg) _,
            a1 = in(reg) a.1,
            b1 = in(reg) b.1,
            c1 = inout(reg) c.1,
        );
    }
}

fn mxorbic(c: Shares, a: Shares, b: Shares) -> Shares {
    let mut c_mut: Shares = c;
    if NUM_SHARES == 1 {
        eor_bic(&mut c_mut.s[0], a.s[0], b.s[0]);
    } else if NUM_SHARES == 2 {
        eor_bic(&mut c_mut.s[0], a.s[0], b.s[0]);
        eor_bic(&mut c_mut.s[1], a.s[1], b.s[0]);
        eor_and(&mut c_mut.s[1], a.s[1], b.s[1]);
        eor_and(&mut c_mut.s[0], a.s[0], b.s[1]);
    } else if NUM_SHARES == 3 {
        eor_and(&mut c_mut.s[0], b.s[0], a.s[1]);
        eor_bic(&mut c_mut.s[0], a.s[0], b.s[0]);
        eor_and(&mut c_mut.s[0], b.s[0], a.s[2]);
        eor_and(&mut c_mut.s[1], b.s[1], a.s[2]);
        eor_bic(&mut c_mut.s[1], a.s[1], b.s[1]);
        eor_and(&mut c_mut.s[1], b.s[1], a.s[0]);
        eor_bic(&mut c_mut.s[2], b.s[2], a.s[0]);
        eor_orr(&mut c_mut.s[2], a.s[2], b.s[2]);
        eor_and(&mut c_mut.s[2], b.s[2], a.s[1]);
    } else if NUM_SHARES == 4 {
        eor_bic(&mut c_mut.s[0], a.s[0], b.s[0]);
        eor_bic(&mut c_mut.s[1], a.s[1], b.s[0]);
        eor_bic(&mut c_mut.s[2], a.s[2], b.s[0]);
        eor_bic(&mut c_mut.s[3], a.s[3], b.s[0]);
        eor_and(&mut c_mut.s[1], a.s[1], b.s[1]);
        eor_and(&mut c_mut.s[2], a.s[2], b.s[1]);
        eor_and(&mut c_mut.s[3], a.s[3], b.s[1]);
        eor_and(&mut c_mut.s[0], a.s[0], b.s[1]);
        eor_and(&mut c_mut.s[2], a.s[2], b.s[2]);
        eor_and(&mut c_mut.s[3], a.s[3], b.s[2]);
        eor_and(&mut c_mut.s[0], a.s[0], b.s[2]);
        eor_and(&mut c_mut.s[1], a.s[1], b.s[2]);
        eor_and(&mut c_mut.s[3], a.s[3], b.s[3]);
        eor_and(&mut c_mut.s[0], a.s[0], b.s[3]);
        eor_and(&mut c_mut.s[1], a.s[1], b.s[3]);
        eor_and(&mut c_mut.s[2], a.s[2], b.s[3]);
    }
    c_mut
}

fn mxorbic_unlimited(c: Shares, a: Shares, b: Shares) -> Shares {
    let mut c_mut: Shares = c;
    for n in 0..NUM_SHARES {
        // First doing the eor_bic()
        if n == 0 {
            for i in 0..NUM_SHARES {
                eor_bic(&mut c_mut.s[i], a.s[i], b.s[n])
            }
        } else {
            for i in 0..NUM_SHARES {
                eor_and(&mut c_mut.s[i], a.s[i], b.s[n])
            }
        }
    }
    c_mut
}

#[inline(always)]
fn masked_sbox(x: [Shares; 5], c: u64) -> [Shares; 5] {
    let mut x = x;

    // addition of the round constant
    x[2].s[0] ^= c.into();

    // affine1
    x[0] ^= x[4];
    x[4] ^= x[3];
    x[2] ^= x[1];

    let mut t = x;

    // keccak sbox
    t[0] = mxorbic(x[0], x[2], x[1]);
    t[1] = mxorbic(x[1], x[3], x[2]);
    t[2] = mxorbic(x[2], x[4], x[3]);
    t[3] = mxorbic(x[3], x[0], x[4]);
    t[4] = mxorbic(x[4], x[1], x[0]);

    // affine2
    t[1] ^= t[0];
    t[0] ^= t[4];
    t[3] ^= t[2];

    t[2].s[0] = !t[2].s[0];

    t
}

#[inline(always)]
fn masked_sbox_unlimited(x: [Shares; 5], c: u64) -> [Shares; 5] {
    let mut x = x;

    // addition of the round constant
    x[2].s[0] ^= c.into();

    // affine1
    // for share in 0..NUM_SHARES {
    //     s.x[0].s[share] ^= s.x[4].s[share];
    //     s.x[4].s[share] ^= s.x[3].s[share];
    //     s.x[2].s[share] ^= s.x[1].s[share];
    // }
    x[0] ^= x[4];
    x[4] ^= x[3];
    x[2] ^= x[1];

    let mut t = x;

    // keccak sbox
    t[0] = mxorbic_unlimited(x[0], x[2], x[1]);
    t[1] = mxorbic_unlimited(x[1], x[3], x[2]);
    t[2] = mxorbic_unlimited(x[2], x[4], x[3]);
    t[3] = mxorbic_unlimited(x[3], x[0], x[4]);
    t[4] = mxorbic_unlimited(x[4], x[1], x[0]);

    // affine2
    // for share in 0..NUM_SHARES {
    //     t.x[1].s[share] ^= t.x[0].s[share];
    //     t.x[0].s[share] ^= t.x[4].s[share];
    //     t.x[3].s[share] ^= t.x[2].s[share];
    // }
    t[1] ^= t[0];
    t[0] ^= t[4];
    t[3] ^= t[2];

    t[2].s[0] = !t[2].s[0];

    t
}

pub fn masked_round(s: [Shares; 5], c: u64) -> [Shares; 5] {
    let mut t = masked_sbox(s, c);

    for i in 0..NUM_SHARES {
        t[0].s[i] = t[0].s[i] ^ t[0].s[i].rotate_right(19) ^ t[0].s[i].rotate_right(28);
        t[1].s[i] = t[1].s[i] ^ t[1].s[i].rotate_right(61) ^ t[1].s[i].rotate_right(39);
        t[2].s[i] = t[2].s[i] ^ t[2].s[i].rotate_right(1) ^ t[2].s[i].rotate_right(6);
        t[3].s[i] = t[3].s[i] ^ t[3].s[i].rotate_right(10) ^ t[3].s[i].rotate_right(17);
        t[4].s[i] = t[4].s[i] ^ t[4].s[i].rotate_right(7) ^ t[4].s[i].rotate_right(41);
    }

    t
}

pub fn masked_round_unlimited(s: [Shares; 5], c: u64) -> [Shares; 5] {
    let mut t = masked_sbox_unlimited(s, c);

    for i in 0..NUM_SHARES {
        t[0].s[i] = t[0].s[i] ^ t[0].s[i].rotate_right(19) ^ t[0].s[i].rotate_right(28);
        t[1].s[i] = t[1].s[i] ^ t[1].s[i].rotate_right(61) ^ t[1].s[i].rotate_right(39);
        t[2].s[i] = t[2].s[i] ^ t[2].s[i].rotate_right(1) ^ t[2].s[i].rotate_right(6);
        t[3].s[i] = t[3].s[i] ^ t[3].s[i].rotate_right(10) ^ t[3].s[i].rotate_right(17);
        t[4].s[i] = t[4].s[i] ^ t[4].s[i].rotate_right(7) ^ t[4].s[i].rotate_right(41);
    }

    t
}

impl MaskedState {
    pub fn new(x0: Shares, x1: Shares, x2: Shares, x3: Shares, x4: Shares) -> Self {
        MaskedState {
            x: [x0, x1, x2, x3, x4],
        }
    }

    pub fn combine_shares(self) -> State {
        State {
            x: [
                self.x[0].combine_shares(),
                self.x[1].combine_shares(),
                self.x[2].combine_shares(),
                self.x[3].combine_shares(),
                self.x[4].combine_shares(),
            ],
        }
    }

    #[cfg(not(feature = "no_unroll"))]
    /// Perform permutation with 12 rounds.
    pub fn permute_12(&mut self) {
        // We could in theory iter().fold() over an array of round constants,
        // but the compiler produces better results when optimizing this chain
        // of round function calls.
        self.x = masked_round(
            masked_round(
                masked_round(
                    masked_round(
                        masked_round(
                            masked_round(
                                masked_round(
                                    masked_round(
                                        masked_round(
                                            masked_round(
                                                masked_round(masked_round(self.x, 0xf0), 0xe1),
                                                0xd2,
                                            ),
                                            0xc3,
                                        ),
                                        0xb4,
                                    ),
                                    0xa5,
                                ),
                                0x96,
                            ),
                            0x87,
                        ),
                        0x78,
                    ),
                    0x69,
                ),
                0x5a,
            ),
            0x4b,
        )
    }

    #[cfg(feature = "no_unroll")]
    /// Perform permutation with 12 rounds.
    pub fn permute_12(self) -> Self {
        [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
        ]
        .into_iter()
        .fold(self, masked_round)
    }

    #[cfg(not(feature = "no_unroll"))]
    /// Perform permutation with 8 rounds.
    pub fn permute_8(&mut self) {
        self.x = masked_round(
            masked_round(
                masked_round(
                    masked_round(
                        masked_round(
                            masked_round(masked_round(masked_round(self.x, 0xb4), 0xa5), 0x96),
                            0x87,
                        ),
                        0x78,
                    ),
                    0x69,
                ),
                0x5a,
            ),
            0x4b,
        )
    }

    #[cfg(feature = "no_unroll")]
    /// Perform permutation with 8 rounds.
    pub fn permute_8(self) -> Self {
        [0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
            .into_iter()
            .fold(self, masked_round)
    }

    #[cfg(not(feature = "no_unroll"))]
    /// Perform permutation with 6 rounds.
    pub fn permute_6(&mut self) {
        self.x = masked_round(
            masked_round(
                masked_round(
                    masked_round(masked_round(masked_round(self.x, 0x96), 0x87), 0x78),
                    0x69,
                ),
                0x5a,
            ),
            0x4b,
        )
    }

    #[cfg(feature = "no_unroll")]
    /// Perform permutation with 6 rounds.
    pub fn permute_6(self) -> Self {
        [0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
            .into_iter()
            .fold(self, masked_round)
    }

    /// Perform a given number (up to 12) of permutations
    ///
    /// Panics (in debug mode) if `rounds` is larger than 12.
    pub fn permute_n(&mut self, rounds: usize) {
        debug_assert!(rounds <= 12);

        let start = 12 - rounds;
        self.x = (start..12).fold(self.x, |x, round_index| {
            masked_round(x, round_constant(round_index as u64))
        })
    }
}

/// Ascon's round function
pub const fn round(x: [u64; 5], c: u64) -> [u64; 5] {
    // S-box layer
    let x0 = x[0] ^ x[4];
    let x2 = x[2] ^ x[1] ^ c; // with round constant
    let x4 = x[4] ^ x[3];

    let tx0 = x0 ^ (!x[1] & x2);
    let tx1 = x[1] ^ (!x2 & x[3]);
    let tx2 = x2 ^ (!x[3] & x4);
    let tx3 = x[3] ^ (!x4 & x0);
    let tx4 = x4 ^ (!x0 & x[1]);
    let tx1 = tx1 ^ tx0;
    let tx3 = tx3 ^ tx2;
    let tx0 = tx0 ^ tx4;

    // linear layer
    let x0 = tx0 ^ tx0.rotate_right(9);
    let x1 = tx1 ^ tx1.rotate_right(22);
    let x2 = tx2 ^ tx2.rotate_right(5);
    let x3 = tx3 ^ tx3.rotate_right(7);
    let x4 = tx4 ^ tx4.rotate_right(34);
    [
        tx0 ^ x0.rotate_right(19),
        tx1 ^ x1.rotate_right(39),
        !(tx2 ^ x2.rotate_right(1)),
        tx3 ^ x3.rotate_right(10),
        tx4 ^ x4.rotate_right(7),
    ]
}

impl State {
    /// Instantiate new state from the given values.
    pub fn new(x0: u64, x1: u64, x2: u64, x3: u64, x4: u64) -> Self {
        State {
            x: [x0, x1, x2, x3, x4],
        }
    }

    #[cfg(not(feature = "no_unroll"))]
    /// Perform permutation with 12 rounds.
    pub fn permute_12(&mut self) {
        // We could in theory iter().fold() over an array of round constants,
        // but the compiler produces better results when optimizing this chain
        // of round function calls.
        self.x = round(
            round(
                round(
                    round(
                        round(
                            round(
                                round(
                                    round(
                                        round(round(round(round(self.x, 0xf0), 0xe1), 0xd2), 0xc3),
                                        0xb4,
                                    ),
                                    0xa5,
                                ),
                                0x96,
                            ),
                            0x87,
                        ),
                        0x78,
                    ),
                    0x69,
                ),
                0x5a,
            ),
            0x4b,
        );
    }

    #[cfg(feature = "no_unroll")]
    /// Perform permutation with 12 rounds.
    pub fn permute_12(&mut self) {
        self.x = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
        ]
        .into_iter()
        .fold(self.x, round);
    }

    #[cfg(not(feature = "no_unroll"))]
    /// Perform permutation with 8 rounds.
    pub fn permute_8(&mut self) {
        self.x = round(
            round(
                round(
                    round(
                        round(round(round(round(self.x, 0xb4), 0xa5), 0x96), 0x87),
                        0x78,
                    ),
                    0x69,
                ),
                0x5a,
            ),
            0x4b,
        );
    }

    #[cfg(feature = "no_unroll")]
    /// Perform permutation with 8 rounds.
    pub fn permute_8(&mut self) {
        self.x = [0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
            .into_iter()
            .fold(self.x, round);
    }

    #[cfg(not(feature = "no_unroll"))]
    /// Perform permutation with 6 rounds.
    pub fn permute_6(&mut self) {
        self.x = round(
            round(
                round(round(round(round(self.x, 0x96), 0x87), 0x78), 0x69),
                0x5a,
            ),
            0x4b,
        );
    }

    #[cfg(feature = "no_unroll")]
    /// Perform permutation with 6 rounds.
    pub fn permute_6(&mut self) {
        self.x = [0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
            .into_iter()
            .fold(self.x, round);
    }

    /// Perform permutation with 1 round
    pub fn permute_1(&mut self) {
        self.x = round(self.x, 0x4b);
    }

    /// Perform a given number (up to 12) of permutations
    ///
    /// Panics (in debug mode) if `rounds` is larger than 12.
    pub fn permute_n(&mut self, rounds: usize) {
        debug_assert!(rounds <= 12);

        let start = 12 - rounds;
        self.x = (start..12).fold(self.x, |x, round_index| {
            round(x, round_constant(round_index as u64))
        });
    }

    /// Convert state to bytes.
    pub fn as_bytes(&self) -> [u8; 40] {
        let mut bytes = [0u8; size_of::<u64>() * 5];
        for (dst, src) in bytes.chunks_exact_mut(size_of::<u64>()).zip(self.x) {
            dst.copy_from_slice(&u64::to_be_bytes(src));
        }
        bytes
    }
}

impl core::ops::Index<usize> for State {
    type Output = u64;

    #[inline(always)]
    fn index(&self, index: usize) -> &Self::Output {
        &self.x[index]
    }
}

impl core::ops::IndexMut<usize> for State {
    #[inline(always)]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.x[index]
    }
}

impl TryFrom<&[u64]> for State {
    type Error = ();

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        match value.len() {
            5 => Ok(Self::new(value[0], value[1], value[2], value[3], value[4])),
            _ => Err(()),
        }
    }
}

impl From<&[u64; 5]> for State {
    fn from(value: &[u64; 5]) -> Self {
        Self { x: *value }
    }
}

impl TryFrom<&[u8]> for State {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != core::mem::size_of::<u64>() * 5 {
            return Err(());
        }

        let mut state = Self::default();
        for (src, dst) in value
            .chunks_exact(core::mem::size_of::<u64>())
            .zip(state.x.iter_mut())
        {
            *dst = u64::from_be_bytes(src.try_into().unwrap());
        }
        Ok(state)
    }
}

impl From<&[u8; size_of::<u64>() * 5]> for State {
    fn from(value: &[u8; size_of::<u64>() * 5]) -> Self {
        let mut state = Self::default();
        for (src, dst) in value
            .chunks_exact(core::mem::size_of::<u64>())
            .zip(state.x.iter_mut())
        {
            *dst = u64::from_be_bytes(src.try_into().unwrap());
        }
        state
    }
}

impl AsRef<[u64]> for State {
    fn as_ref(&self) -> &[u64] {
        &self.x
    }
}

#[cfg(feature = "zeroize")]
impl Drop for State {
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for State {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_0to7() {
        assert_eq!(pad(0), 0x8000000000000000);
        assert_eq!(pad(1), 0x80000000000000);
        assert_eq!(pad(2), 0x800000000000);
        assert_eq!(pad(3), 0x8000000000);
        assert_eq!(pad(4), 0x80000000);
        assert_eq!(pad(5), 0x800000);
        assert_eq!(pad(6), 0x8000);
        assert_eq!(pad(7), 0x80);
    }

    #[test]
    fn round_constants() {
        assert_eq!(round_constant(0), 0xf0);
        assert_eq!(round_constant(1), 0xe1);
        assert_eq!(round_constant(2), 0xd2);
        assert_eq!(round_constant(3), 0xc3);
        assert_eq!(round_constant(4), 0xb4);
        assert_eq!(round_constant(5), 0xa5);
        assert_eq!(round_constant(6), 0x96);
        assert_eq!(round_constant(7), 0x87);
        assert_eq!(round_constant(8), 0x78);
        assert_eq!(round_constant(9), 0x69);
        assert_eq!(round_constant(10), 0x5a);
        assert_eq!(round_constant(11), 0x4b);
    }

    #[test]
    fn combining_shares() {
        let masked_state = MaskedState {
            x: [
                Shares {
                    s: [0x1a7cdba7740c82bc.into(), 0x7e6932bbfbfa5a67.into()],
                },
                Shares {
                    s: [0xe112073424f921e6.into(), 0x9be65fc79cbfb8f6.into()],
                },
                Shares {
                    s: [0x8a9e09b8ae7eb2f.into(), 0xc93be817c6cb4daf.into()],
                },
                Shares {
                    s: [0x2b1e58fcdedf3ee9.into(), 0xbd3d1231300e1998.into()],
                },
                Shares {
                    s: [0xbc67dd558ba054db.into(), 0x543b01a5c5f0bc26.into()],
                },
            ],
        };

        let combined_state = masked_state.combine_shares();
        let state = State {
            x: [
                0x6415e91c8ff6d8db,
                0x7af458f3b8469910,
                0xc192088c4c2ca680,
                0x96234acdeed12771,
                0xe85cdcf04e50e8fd,
            ],
        };
        assert_eq!(state, combined_state);
    }

    #[test]
    fn one_round() {
        let state = round(
            [
                0x0123456789abcdef,
                0x23456789abcdef01,
                0x456789abcdef0123,
                0x6789abcdef012345,
                0x89abcde01234567f,
            ],
            0x1f,
        );
        assert_eq!(
            state,
            [
                0x3c1748c9be2892ce,
                0x5eafb305cd26164f,
                0xf9470254bb3a4213,
                0xf0428daf0c5d3948,
                0x281375af0b294899
            ]
        );
    }

    #[test]
    fn one_round_masked() {
        let masked_state = MaskedState {
            x: [
                Shares {
                    s: [0x27ae2dc5c90be280.into(), 0xaa30f98a37074ef2.into()],
                },
                Shares {
                    s: [0xf2baaf1857e449bf.into(), 0x82a4fc8ed9affef.into()],
                },
                Shares {
                    s: [0x16c368c10c7bd104.into(), 0x756bb602ceb37c5a.into()],
                },
                Shares {
                    s: [0x84bae4600195a6c.into(), 0xde6789e2796feec.into()],
                },
                Shares {
                    s: [0xeccb93549a56b060.into(), 0xa09b54d4c22a87d.into()],
                },
            ],
        };
        let masked_result = MaskedState {
            x: masked_round(masked_state.x, 0x1f),
        }
        .combine_shares();
        let state = masked_state.combine_shares();
        let state = State {
            x: round(state.x, 0x1f),
        };
        assert_eq!(masked_result, state);
    }

    #[test]
    fn one_round_masked_unlimited() {
        let masked_state = MaskedState {
            x: [
                Shares {
                    s: [0x27ae2dc5c90be280.into(), 0xaa30f98a37074ef2.into()],
                },
                Shares {
                    s: [0xf2baaf1857e449bf.into(), 0x82a4fc8ed9affef.into()],
                },
                Shares {
                    s: [0x16c368c10c7bd104.into(), 0x756bb602ceb37c5a.into()],
                },
                Shares {
                    s: [0x84bae4600195a6c.into(), 0xde6789e2796feec.into()],
                },
                Shares {
                    s: [0xeccb93549a56b060.into(), 0xa09b54d4c22a87d.into()],
                },
            ],
        };
        let masked_result = MaskedState {
            x: masked_round_unlimited(masked_state.x, 0x1f),
        }
        .combine_shares();
        let state = masked_state.combine_shares();
        let state = State {
            x: round(state.x, 0x1f),
        };
        assert_eq!(masked_result, state);
    }

    #[test]
    fn state_permute_12() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_12();
        assert_eq!(state[0], 0x206416dfc624bb14);
        assert_eq!(state[1], 0x1b0c47a601058aab);
        assert_eq!(state[2], 0x8934cfc93814cddd);
        assert_eq!(state[3], 0xa9738d287a748e4b);
        assert_eq!(state[4], 0xddd934f058afc7e1);
    }

    #[test]
    fn state_permute_12_masked() {
        let mut masked_state = MaskedState {
            x: [
                Shares {
                    s: [0x1a7cdba7740c82bc.into(), 0x7e6932bbfbfa5a67.into()],
                },
                Shares {
                    s: [0xe112073424f921e6.into(), 0x9be65fc79cbfb8f6.into()],
                },
                Shares {
                    s: [0x8a9e09b8ae7eb2f.into(), 0xc93be817c6cb4daf.into()],
                },
                Shares {
                    s: [0x2b1e58fcdedf3ee9.into(), 0xbd3d1231300e1998.into()],
                },
                Shares {
                    s: [0xbc67dd558ba054db.into(), 0x543b01a5c5f0bc26.into()],
                },
            ],
        };
        let mut state = masked_state.combine_shares();
        masked_state.permute_12();
        state.permute_12();
        let masked_result = masked_state.combine_shares();
        assert_eq!(masked_result, state);
    }

    #[test]
    fn state_permute_6() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_6();
        assert_eq!(state[0], 0xc27b505c635eb07f);
        assert_eq!(state[1], 0xd388f5d2a72046fa);
        assert_eq!(state[2], 0x9e415c204d7b15e7);
        assert_eq!(state[3], 0xce0d71450fe44581);
        assert_eq!(state[4], 0xdd7c5fef57befe48);
    }

    #[test]
    fn state_permute_6_masked() {
        let mut masked_state = MaskedState {
            x: [
                Shares {
                    s: [0x96a4b081f6b776c0.into(), 0x974d52e7a919604e.into()],
                },
                Shares {
                    s: [0x46e63318728f10f5.into(), 0xb201f5988d95bce9.into()],
                },
                Shares {
                    s: [0x430be614c071065d.into(), 0x64565a244f759990.into()],
                },
                Shares {
                    s: [0x1518cdd7d61e53be.into(), 0xf7f4582108ac6806.into()],
                },
                Shares {
                    s: [0x55f72bd931613b93.into(), 0x10fa1b04a165fcb4.into()],
                },
            ],
        };
        let mut state = masked_state.combine_shares();
        masked_state.permute_6();
        state.permute_6();
        let masked_result = masked_state.combine_shares();
        assert_eq!(masked_result, state);
    }

    #[test]
    fn state_permute_8() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        state.permute_8();
        assert_eq!(state[0], 0x67ed228272f46eee);
        assert_eq!(state[1], 0x80bc0b097aad7944);
        assert_eq!(state[2], 0x2fa599382c6db215);
        assert_eq!(state[3], 0x368133fae2f7667a);
        assert_eq!(state[4], 0x28cefb195a7c651c);
    }

    #[test]
    fn state_permute_8_masked() {
        let mut masked_state = MaskedState {
            x: [
                Shares {
                    s: [0x747d8fa934720165.into(), 0x50b4a34682887e2b.into()],
                },
                Shares {
                    s: [0x9af770356afa951.into(), 0xb6c8532e069673c6.into()],
                },
                Shares {
                    s: [0xdf5aea65e44bfe94.into(), 0xa8d2e782e076b7c4.into()],
                },
                Shares {
                    s: [0x2c69acc6232637f3.into(), 0x3e01e69fe836551c.into()],
                },
                Shares {
                    s: [0x8684ef23b3233e4d.into(), 0x36114fa19c3b0b00.into()],
                },
            ],
        };
        let mut state = masked_state.combine_shares();
        masked_state.permute_8();
        state.permute_8();
        let masked_result = masked_state.combine_shares();
        assert_eq!(masked_result, state);
    }

    #[test]
    fn state_permute_n() {
        let mut state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        let mut state2 = state.clone();

        state.permute_6();
        state2.permute_n(6);
        assert_eq!(state.x, state2.x);

        state.permute_8();
        state2.permute_n(8);
        assert_eq!(state.x, state2.x);

        state.permute_12();
        state2.permute_n(12);
        assert_eq!(state.x, state2.x);
    }

    #[test]
    fn state_permute_n_masked() {
        let mut masked_state = MaskedState {
            x: [
                Shares {
                    s: [0x9f53a79fdaa0e184.into(), 0xe0f2e3032e25c68a.into()],
                },
                Shares {
                    s: [0xeb8a77981f8f0dea.into(), 0xe9737b9b75285275.into()],
                },
                Shares {
                    s: [0x20a673b7f3319398.into(), 0xfd25a6c6bd5acc5.into()],
                },
                Shares {
                    s: [0xac350163bcbc0992.into(), 0xc18d5cd492e43556.into()],
                },
                Shares {
                    s: [0xbdb77ca54cd6a306.into(), 0x2dacc5871b5d60a1.into()],
                },
            ],
        };
        let mut masked_state_2 = masked_state.clone();

        masked_state.permute_6();
        masked_state_2.permute_n(6);
        assert_eq!(masked_state, masked_state_2);

        masked_state.permute_8();
        masked_state_2.permute_n(8);
        assert_eq!(masked_state, masked_state_2);

        masked_state.permute_12();
        masked_state_2.permute_n(12);
        assert_eq!(masked_state, masked_state_2);
    }

    #[test]
    fn state_convert_bytes() {
        let state = State::new(
            0x0123456789abcdef,
            0xef0123456789abcd,
            0xcdef0123456789ab,
            0xabcdef0123456789,
            0x89abcdef01234567,
        );
        let bytes = state.as_bytes();

        // test TryFrom<&[u8]>
        let state2 = State::try_from(&bytes[..]);
        assert_eq!(state2.expect("try_from bytes").x, state.x);

        let state2 = State::from(&bytes);
        assert_eq!(state2.x, state.x);
    }

    #[test]
    fn word_u64_conversion() {
        let x: u64 = 0xDEADBEEFCAFEF00D;
        let x2: Word = x.into();
        let x3: u64 = x2.into();
        assert_eq!(x, x3);

        let x: Word = Word(0xDEADBEEF, 0xCAFEF00D);
        let x2: u64 = x.into();
        let x3: Word = x2.into();
        assert_eq!(x, x3);
    }

    #[test]
    fn word_rotation() {
        let x: u64 = 0xDEADBEEFCAFEF00D;
        let x2: Word = x.into();
        let x3 = x.rotate_right(5);
        let x4 = x2.rotate_right(5);
        assert_eq!(x3, x4.into());
    }
}
