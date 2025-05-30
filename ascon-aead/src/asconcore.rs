// Copyright 2021-2023 Sebastian Ramacher
// SPDX-License-Identifier: Apache-2.0 OR MIT

use aead::{
    array::{typenum::Unsigned, Array, ArraySize},
    consts::{U16, U20},
    rand_core::CryptoRngCore,
    Error,
};
use ascon::{pad, MaskedState, Shares, State, Word, NUM_SHARES};
use subtle::ConstantTimeEq;

/// Clear bytes from a 64 bit word.
#[inline(always)]
const fn clear(word: u64, n: usize) -> u64 {
    word & (0x00ffffffffffffff >> (n * 8 - 8))
}

/// Clear bytes from a 32 bit Word tuple.
#[inline(always)]
fn clear_word(word: Word, n: usize) -> Word {
    clear(word.into(), n).into()
}

/// Clear bytes from a masked Word.
#[inline(always)]
fn clear_masked(word: Shares, n: usize) -> Shares {
    let mut new_word = word;
    for i in 0..NUM_SHARES {
        new_word.s[i] = clear_word(new_word.s[i], n);
    }
    new_word
}

#[inline(always)]
const fn keyrot(lo2hi: u64, hi2lo: u64) -> u64 {
    lo2hi << 32 | hi2lo >> 32
}

// Helper functions to convert &[u8] to u64/u32. Once the `processing_*`
// functions are rewritten with `as_chunks`, they can be dropped.

#[inline]
fn u64_from_be_bytes(input: &[u8]) -> u64 {
    // Soundness: function is always called with slices of the correct size
    u64::from_be_bytes(input.try_into().unwrap())
}

#[inline]
fn u64_from_be_bytes_partial(input: &[u8]) -> u64 {
    let mut tmp = [0u8; 8];
    tmp[0..input.len()].copy_from_slice(input);
    u64::from_be_bytes(tmp)
}

#[inline]
fn u32_from_be_bytes(input: &[u8]) -> u32 {
    // Soundness: function is always called with slices of the correct size
    u32::from_be_bytes(input.try_into().unwrap())
}

/// Helper trait for handling differences in key usage of Ascon-128* and Ascon-80*
///
/// For internal use-only.
pub(crate) trait InternalKey<KS: ArraySize>:
    Sized + Clone + for<'a> From<&'a Array<u8, KS>>
{
    /// Return K0.
    fn get_k0(&self) -> u64;
    /// Return K1.
    fn get_k1(&self) -> u64;
    /// Return K2.
    fn get_k2(&self) -> u64;
}

#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub(crate) struct InternalKey16(u64, u64);

impl InternalKey<U16> for InternalKey16 {
    #[inline(always)]
    fn get_k0(&self) -> u64 {
        0
    }

    #[inline(always)]
    fn get_k1(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn get_k2(&self) -> u64 {
        self.1
    }
}

impl From<&Array<u8, U16>> for InternalKey16 {
    fn from(key: &Array<u8, U16>) -> Self {
        Self(u64_from_be_bytes(&key[..8]), u64_from_be_bytes(&key[8..]))
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "zeroize", derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop))]
pub(crate) struct InternalKey20(u64, u64, u32);

impl InternalKey<U20> for InternalKey20 {
    #[inline(always)]
    fn get_k0(&self) -> u64 {
        self.2 as u64
    }

    #[inline(always)]
    fn get_k1(&self) -> u64 {
        self.0
    }

    #[inline(always)]
    fn get_k2(&self) -> u64 {
        self.1
    }
}

impl From<&Array<u8, U20>> for InternalKey20 {
    fn from(key: &Array<u8, U20>) -> Self {
        Self(
            u64_from_be_bytes(&key[4..12]),
            u64_from_be_bytes(&key[12..]),
            u32_from_be_bytes(&key[..4]),
        )
    }
}

/// Parameters of an Ascon instance
pub(crate) trait Parameters {
    /// Size of the secret key
    ///
    /// For internal use-only.
    type KeySize: ArraySize;
    /// Internal storage for secret keys
    ///
    /// For internal use-only.
    type InternalKey: InternalKey<Self::KeySize>;

    /// Number of bytes to process per round
    const COUNT: usize;
    /// Initialization vector used to initialize Ascon's state
    ///
    /// For internal use-only
    const IV: u64;
}

/// Parameters for Ascon-128
pub(crate) struct Parameters128;

impl Parameters for Parameters128 {
    type KeySize = U16;
    type InternalKey = InternalKey16;

    const COUNT: usize = 8;
    const IV: u64 = 0x80400c0600000000;
}

/// Parameters for Ascon-128a
pub(crate) struct Parameters128a;

impl Parameters for Parameters128a {
    type KeySize = U16;
    type InternalKey = InternalKey16;

    const COUNT: usize = 16;
    const IV: u64 = 0x80800c0800000000;
}

/// Parameters for Ascon-80pq
pub(crate) struct Parameters80pq;

impl Parameters for Parameters80pq {
    type KeySize = U20;
    type InternalKey = InternalKey20;

    const COUNT: usize = 8;
    const IV: u64 = 0xa0400c0600000000;
}

pub(crate) struct MaskedAsconCore<'a, P: Parameters, R: CryptoRngCore> {
    pub(crate) state: MaskedState,
    key: &'a P::InternalKey,
    rng: R,
}

impl<'a, P: Parameters, R: CryptoRngCore> MaskedAsconCore<'a, P, R> {
    pub(crate) fn new(
        internal_key: &'a P::InternalKey,
        nonce: &Array<u8, U16>,
        mut rng: R,
    ) -> Self {
        // let mut state = State::new(
        //     if P::KeySize::USIZE == 20 {
        //         P::IV ^ internal_key.get_k0()
        //     } else {
        //         P::IV
        //     },
        //     internal_key.get_k1(),
        //     internal_key.get_k2(),
        //     u64_from_be_bytes(&nonce[..8]),
        //     u64_from_be_bytes(&nonce[8..]),
        // );

        if P::KeySize::USIZE != 16 || P::COUNT != 8 {
            panic!("ERROR: ONLY Ascon128 is supported.");
        }

        // generating key masks
        let mut masked_k1 = Shares::default();
        for i in 1..NUM_SHARES {
            masked_k1.s[i] = rng.as_rngcore().next_u64().into();
            masked_k1.s[0] ^= masked_k1.s[i];
        }
        masked_k1.s[0] ^= internal_key.get_k1().into();

        let mut masked_k2 = Shares::default();
        for i in 1..NUM_SHARES {
            masked_k2.s[i] = rng.as_rngcore().next_u64().into();
            masked_k2.s[0] ^= masked_k2.s[i];
        }
        masked_k2.s[0] ^= internal_key.get_k2().into();

        // generating nonce masks
        let mut masked_n1 = Shares::default();
        for i in 1..NUM_SHARES {
            masked_n1.s[i] = rng.as_rngcore().next_u64().into();
            masked_n1.s[0] ^= masked_n1.s[i];
        }
        masked_n1.s[0] ^= u64_from_be_bytes(&nonce[..8]).into();

        let mut masked_n2 = Shares::default();
        for i in 1..NUM_SHARES {
            masked_n2.s[i] = rng.as_rngcore().next_u64().into();
            masked_n2.s[0] ^= masked_n2.s[i];
        }
        masked_n2.s[0] ^= u64_from_be_bytes(&nonce[8..]).into();

        // initializing state
        let mut state = MaskedState::default();

        // randomizing intial state and setting the initial value
        for i in 1..NUM_SHARES {
            state.x[0].s[i] = rng.as_rngcore().next_u64().into();
            state.x[0].s[0] ^= state.x[0].s[i];
        }
        state.x[0].s[0] ^= P::IV.into();

        state.x[1] = masked_k1;
        state.x[2] = masked_k2;
        state.x[3] = masked_n1;
        state.x[4] = masked_n2;

        state.permute_12();

        state.x[3] ^= masked_k1;
        state.x[4] ^= masked_k2;
        // state.permute_12();
        // if P::KeySize::USIZE == 20 {
        //     state[2] ^= internal_key.get_k0();
        // }
        // state[3] ^= internal_key.get_k1();
        // state[4] ^= internal_key.get_k2();

        Self {
            state,
            key: internal_key,
            rng,
        }
    }

    /// Generates a Word which contains the shares for a u64
    /// Uses the rng inside self
    #[inline(always)]
    fn generate_shares(&mut self, data: u64) -> Shares {
        let mut masked_data = Shares::default();
        for i in 1..NUM_SHARES {
            masked_data.s[i] = self.rng.as_rngcore().next_u64().into();
            masked_data.s[0] ^= masked_data.s[i];
        }
        masked_data.s[0] ^= data.into();
        masked_data
    }

    /// Permutation with 12 rounds and application of the key at the end
    fn permute_12_and_apply_key(&mut self) {
        // self.state.permute_12();
        // self.state[3] ^= self.key.get_k1();
        // self.state[4] ^= self.key.get_k2();
        self.state.permute_12();

        // This is really inefficient, because the key shares used in initialization can just be reused here
        // However I do not feel like adding the key shares to the state and just want it to work.
        // generating key masks
        let masked_k1 = self.generate_shares(self.key.get_k1());

        let masked_k2 = self.generate_shares(self.key.get_k2());
        self.state.x[3] ^= masked_k1;
        self.state.x[4] ^= masked_k2;
    }

    /// Permutation with 6 or 8 rounds based on the parameters
    #[inline(always)]
    fn permute_state(&mut self) {
        if P::COUNT == 8 {
            self.state.permute_6();
        } else {
            self.state.permute_8();
        }
    }

    fn process_associated_data(&mut self, associated_data: &[u8]) {
        // if !associated_data.is_empty() {
        //     // TODO: replace with as_chunks once stabilized
        //     // https://github.com/rust-lang/rust/issues/74985

        //     let mut blocks = associated_data.chunks_exact(P::COUNT);
        //     for block in blocks.by_ref() {
        //         // process full block of associated data
        //         self.state[0] ^= u64_from_be_bytes(&block[..8]);
        //         if P::COUNT == 16 {
        //             self.state[1] ^= u64_from_be_bytes(&block[8..16]);
        //         }
        //         self.permute_state();
        //     }

        //     // process partial block if it exists
        //     let mut last_block = blocks.remainder();
        //     let sidx = if P::COUNT == 16 && last_block.len() >= 8 {
        //         self.state[0] ^= u64_from_be_bytes(&last_block[..8]);
        //         last_block = &last_block[8..];
        //         1
        //     } else {
        //         0
        //     };
        //     self.state[sidx] ^= pad(last_block.len());
        //     if !last_block.is_empty() {
        //         self.state[sidx] ^= u64_from_be_bytes_partial(last_block);
        //     }
        //     self.permute_state();
        // }

        // // domain separation
        // self.state[4] ^= 1;

        if !associated_data.is_empty() {
            // TODO: replace with as_chunks once stabilized
            // https://github.com/rust-lang/rust/issues/74985

            let mut blocks = associated_data.chunks_exact(P::COUNT);
            for block in blocks.by_ref() {
                // process full block of associated data
                // self.state[0] ^= u64_from_be_bytes(&block[..8]);
                // if P::COUNT == 16 {
                //     self.state[1] ^= u64_from_be_bytes(&block[8..16]);
                // }
                let masked_block = self.generate_shares(u64_from_be_bytes(&block[..8]));
                self.state.x[0] ^= masked_block;
                self.permute_state();
            }

            // process partial block if it exists
            let mut last_block = blocks.remainder();
            let sidx = if P::COUNT == 16 && last_block.len() >= 8 {
                let masked_block = self.generate_shares(u64_from_be_bytes(&last_block[..8]));
                self.state.x[0] ^= masked_block;
                last_block = &last_block[8..];
                1
            } else {
                0
            };
            self.state.x[sidx].s[0] ^= pad(last_block.len()).into();
            if !last_block.is_empty() {
                let masked_block = self.generate_shares(u64_from_be_bytes_partial(last_block));
                self.state.x[sidx] ^= masked_block;
            }
            self.permute_state();
        }

        // domain separation
        self.state.x[4].s[0] ^= 1.into();
    }

    fn process_encrypt_inplace(&mut self, message: &mut [u8]) {
        // let mut blocks = message.chunks_exact_mut(P::COUNT);
        // for block in blocks.by_ref() {
        //     // process full block of message
        //     self.state[0] ^= u64_from_be_bytes(&block[..8]);
        //     block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
        //     if P::COUNT == 16 {
        //         self.state[1] ^= u64_from_be_bytes(&block[8..16]);
        //         block[8..16].copy_from_slice(&u64::to_be_bytes(self.state[1]));
        //     }
        //     self.permute_state();
        // }

        // // process partial block if it exists
        // let mut last_block = blocks.into_remainder();
        // let sidx = if P::COUNT == 16 && last_block.len() >= 8 {
        //     self.state[0] ^= u64_from_be_bytes(&last_block[..8]);
        //     last_block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
        //     last_block = &mut last_block[8..];
        //     1
        // } else {
        //     0
        // };
        // self.state[sidx] ^= pad(last_block.len());
        // if !last_block.is_empty() {
        //     self.state[sidx] ^= u64_from_be_bytes_partial(last_block);
        //     last_block.copy_from_slice(&u64::to_be_bytes(self.state[sidx])[0..last_block.len()]);
        // }

        let mut blocks = message.chunks_exact_mut(P::COUNT);
        for block in blocks.by_ref() {
            // process full block of message
            let masked_block = self.generate_shares(u64_from_be_bytes(&block[..8]));
            self.state.x[0] ^= masked_block;
            block[..8].copy_from_slice(&u64::to_be_bytes(self.state.x[0].combine_shares()));
            if P::COUNT == 16 {
                let masked_block = self.generate_shares(u64_from_be_bytes(&block[8..16]));
                self.state.x[1] ^= masked_block;
                block[8..16].copy_from_slice(&u64::to_be_bytes(self.state.x[1].combine_shares()));
            }
            self.permute_state();
        }

        // process partial block if it exists
        let mut last_block = blocks.into_remainder();
        let sidx = if P::COUNT == 16 && last_block.len() >= 8 {
            let masked_block = self.generate_shares(u64_from_be_bytes(&last_block[..8]));
            self.state.x[0] ^= masked_block;
            last_block[..8].copy_from_slice(&u64::to_be_bytes(self.state.x[0].combine_shares()));
            last_block = &mut last_block[8..];
            1
        } else {
            0
        };
        self.state.x[sidx].s[0] ^= pad(last_block.len()).into();
        if !last_block.is_empty() {
            let masked_block = self.generate_shares(u64_from_be_bytes_partial(last_block));
            self.state.x[sidx] ^= masked_block;
            last_block.copy_from_slice(
                &u64::to_be_bytes(self.state.x[sidx].combine_shares())[0..last_block.len()],
            );
        }
    }

    fn process_decrypt_inplace(&mut self, ciphertext: &mut [u8]) {
        // let mut blocks = ciphertext.chunks_exact_mut(P::COUNT);
        // for block in blocks.by_ref() {
        //     // process full block of ciphertext
        //     let cx = u64_from_be_bytes(&block[..8]);
        //     block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0] ^ cx));
        //     self.state[0] = cx;
        //     if P::COUNT == 16 {
        //         let cx = u64_from_be_bytes(&block[8..16]);
        //         block[8..16].copy_from_slice(&u64::to_be_bytes(self.state[1] ^ cx));
        //         self.state[1] = cx;
        //     }
        //     self.permute_state();
        // }

        // // process partial block if it exists
        // let mut last_block = blocks.into_remainder();
        // let sidx = if P::COUNT == 16 && last_block.len() >= 8 {
        //     let cx = u64_from_be_bytes(&last_block[..8]);
        //     last_block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0] ^ cx));
        //     self.state[0] = cx;
        //     last_block = &mut last_block[8..];
        //     1
        // } else {
        //     0
        // };
        // self.state[sidx] ^= pad(last_block.len());
        // if !last_block.is_empty() {
        //     let cx = u64_from_be_bytes_partial(last_block);
        //     self.state[sidx] ^= cx;
        //     last_block.copy_from_slice(&u64::to_be_bytes(self.state[sidx])[0..last_block.len()]);
        //     self.state[sidx] = clear(self.state[sidx], last_block.len()) ^ cx;
        // }

        let mut blocks = ciphertext.chunks_exact_mut(P::COUNT);
        for block in blocks.by_ref() {
            // process full block of ciphertext
            let cx = self.generate_shares(u64_from_be_bytes(&block[..8]));
            block[..8].copy_from_slice(&u64::to_be_bytes((self.state.x[0] ^ cx).combine_shares()));
            self.state.x[0] = cx;
            if P::COUNT == 16 {
                let cx = self.generate_shares(u64_from_be_bytes(&block[8..16]));
                block[8..16]
                    .copy_from_slice(&u64::to_be_bytes((self.state.x[1] ^ cx).combine_shares()));
                self.state.x[1] = cx;
            }
            self.permute_state();
        }

        // process partial block if it exists
        let mut last_block = blocks.into_remainder();
        let sidx: usize = if P::COUNT == 16 && last_block.len() >= 8 {
            let cx: Shares = self.generate_shares(u64_from_be_bytes(&last_block[..8]));
            let plaintext_shares: Shares = self.state.x[0] ^ cx;
            last_block[..8].copy_from_slice(&u64::to_be_bytes(plaintext_shares.combine_shares()));
            self.state.x[0] = cx;
            last_block = &mut last_block[8..];
            1
        } else {
            0
        };
        self.state.x[sidx].s[0] ^= pad(last_block.len()).into();
        if !last_block.is_empty() {
            let cx: Shares = self.generate_shares(u64_from_be_bytes_partial(last_block));
            self.state.x[sidx] ^= cx;
            last_block.copy_from_slice(
                &u64::to_be_bytes(self.state.x[sidx].combine_shares())[0..last_block.len()],
            );
            self.state.x[sidx] = clear_masked(self.state.x[sidx], last_block.len()) ^ cx;
        }
    }

    fn process_final(&mut self) -> [u8; 16] {
        // if P::KeySize::USIZE == 16 && P::COUNT == 8 {
        //     self.state[1] ^= self.key.get_k1();
        //     self.state[2] ^= self.key.get_k2();
        // } else if P::KeySize::USIZE == 16 && P::COUNT == 16 {
        //     self.state[2] ^= self.key.get_k1();
        //     self.state[3] ^= self.key.get_k2();
        // } else if P::KeySize::USIZE == 20 {
        //     self.state[1] ^= keyrot(self.key.get_k0(), self.key.get_k1());
        //     self.state[2] ^= keyrot(self.key.get_k1(), self.key.get_k2());
        //     self.state[3] ^= keyrot(self.key.get_k2(), 0);
        // }

        // self.permute_12_and_apply_key();

        // let mut tag = [0u8; 16];
        // tag[..8].copy_from_slice(&u64::to_be_bytes(self.state[3]));
        // tag[8..].copy_from_slice(&u64::to_be_bytes(self.state[4]));
        // tag

        if P::KeySize::USIZE == 16 && P::COUNT == 8 {
            let tmp = self.generate_shares(self.key.get_k1());
            self.state.x[1] ^= tmp;
            let tmp = self.generate_shares(self.key.get_k2());
            self.state.x[2] ^= tmp;
        } else if P::KeySize::USIZE == 16 && P::COUNT == 16 {
            let tmp = self.generate_shares(self.key.get_k1());
            self.state.x[2] ^= tmp;
            let tmp = self.generate_shares(self.key.get_k2());
            self.state.x[3] ^= tmp;
        } else if P::KeySize::USIZE == 20 {
            let tmp = self.generate_shares(keyrot(self.key.get_k0(), self.key.get_k1()));
            self.state.x[1] ^= tmp;
            let tmp = self.generate_shares(keyrot(self.key.get_k1(), self.key.get_k2()));
            self.state.x[2] ^= tmp;
            let tmp = self.generate_shares(keyrot(self.key.get_k2(), 0));
            self.state.x[3] ^= tmp;
        }

        self.permute_12_and_apply_key();

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&u64::to_be_bytes(self.state.x[3].combine_shares()));
        tag[8..].copy_from_slice(&u64::to_be_bytes(self.state.x[4].combine_shares()));
        tag
    }

    pub(crate) fn encrypt_inplace(
        &mut self,
        message: &mut [u8],
        associated_data: &[u8],
    ) -> Array<u8, U16> {
        self.process_associated_data(associated_data);
        self.process_encrypt_inplace(message);
        Array::from(self.process_final())
    }

    pub(crate) fn decrypt_inplace(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        expected_tag: &Array<u8, U16>,
    ) -> Result<(), Error> {
        self.process_associated_data(associated_data);
        self.process_decrypt_inplace(ciphertext);

        let tag = self.process_final();
        if bool::from(tag.ct_eq(expected_tag)) {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

/// Core implementation of Ascon for one encryption/decryption operation
pub(crate) struct AsconCore<'a, P: Parameters> {
    pub(crate) state: State,
    key: &'a P::InternalKey,
}

impl<'a, P: Parameters> AsconCore<'a, P> {
    pub(crate) fn new(internal_key: &'a P::InternalKey, nonce: &Array<u8, U16>) -> Self {
        let mut state = State::new(
            if P::KeySize::USIZE == 20 {
                P::IV ^ internal_key.get_k0()
            } else {
                P::IV
            },
            internal_key.get_k1(),
            internal_key.get_k2(),
            u64_from_be_bytes(&nonce[..8]),
            u64_from_be_bytes(&nonce[8..]),
        );

        state.permute_12();
        if P::KeySize::USIZE == 20 {
            state[2] ^= internal_key.get_k0();
        }
        state[3] ^= internal_key.get_k1();
        state[4] ^= internal_key.get_k2();

        Self {
            state,
            key: internal_key,
        }
    }

    /// Permutation with 12 rounds and application of the key at the end
    fn permute_12_and_apply_key(&mut self) {
        self.state.permute_12();
        self.state[3] ^= self.key.get_k1();
        self.state[4] ^= self.key.get_k2();
    }

    /// Permutation with 6 or 8 rounds based on the parameters
    #[inline(always)]
    fn permute_state(&mut self) {
        if P::COUNT == 8 {
            self.state.permute_6();
        } else {
            self.state.permute_8();
        }
    }

    fn process_associated_data(&mut self, associated_data: &[u8]) {
        if !associated_data.is_empty() {
            // TODO: replace with as_chunks once stabilized
            // https://github.com/rust-lang/rust/issues/74985

            let mut blocks = associated_data.chunks_exact(P::COUNT);
            for block in blocks.by_ref() {
                // process full block of associated data
                self.state[0] ^= u64_from_be_bytes(&block[..8]);
                if P::COUNT == 16 {
                    self.state[1] ^= u64_from_be_bytes(&block[8..16]);
                }
                self.permute_state();
            }

            // process partial block if it exists
            let mut last_block = blocks.remainder();
            let sidx = if P::COUNT == 16 && last_block.len() >= 8 {
                self.state[0] ^= u64_from_be_bytes(&last_block[..8]);
                last_block = &last_block[8..];
                1
            } else {
                0
            };
            self.state[sidx] ^= pad(last_block.len());
            if !last_block.is_empty() {
                self.state[sidx] ^= u64_from_be_bytes_partial(last_block);
            }
            self.permute_state();
        }

        // domain separation
        self.state[4] ^= 1;
    }

    fn process_encrypt_inplace(&mut self, message: &mut [u8]) {
        let mut blocks = message.chunks_exact_mut(P::COUNT);
        for block in blocks.by_ref() {
            // process full block of message
            self.state[0] ^= u64_from_be_bytes(&block[..8]);
            block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
            if P::COUNT == 16 {
                self.state[1] ^= u64_from_be_bytes(&block[8..16]);
                block[8..16].copy_from_slice(&u64::to_be_bytes(self.state[1]));
            }
            self.permute_state();
        }

        // process partial block if it exists
        let mut last_block = blocks.into_remainder();
        let sidx = if P::COUNT == 16 && last_block.len() >= 8 {
            self.state[0] ^= u64_from_be_bytes(&last_block[..8]);
            last_block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0]));
            last_block = &mut last_block[8..];
            1
        } else {
            0
        };
        self.state[sidx] ^= pad(last_block.len());
        if !last_block.is_empty() {
            self.state[sidx] ^= u64_from_be_bytes_partial(last_block);
            last_block.copy_from_slice(&u64::to_be_bytes(self.state[sidx])[0..last_block.len()]);
        }
    }

    fn process_decrypt_inplace(&mut self, ciphertext: &mut [u8]) {
        let mut blocks = ciphertext.chunks_exact_mut(P::COUNT);
        for block in blocks.by_ref() {
            // process full block of ciphertext
            let cx = u64_from_be_bytes(&block[..8]);
            block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0] ^ cx));
            self.state[0] = cx;
            if P::COUNT == 16 {
                let cx = u64_from_be_bytes(&block[8..16]);
                block[8..16].copy_from_slice(&u64::to_be_bytes(self.state[1] ^ cx));
                self.state[1] = cx;
            }
            self.permute_state();
        }

        // process partial block if it exists
        let mut last_block = blocks.into_remainder();
        let sidx = if P::COUNT == 16 && last_block.len() >= 8 {
            let cx = u64_from_be_bytes(&last_block[..8]);
            last_block[..8].copy_from_slice(&u64::to_be_bytes(self.state[0] ^ cx));
            self.state[0] = cx;
            last_block = &mut last_block[8..];
            1
        } else {
            0
        };
        self.state[sidx] ^= pad(last_block.len());
        if !last_block.is_empty() {
            let cx = u64_from_be_bytes_partial(last_block);
            self.state[sidx] ^= cx;
            last_block.copy_from_slice(&u64::to_be_bytes(self.state[sidx])[0..last_block.len()]);
            self.state[sidx] = clear(self.state[sidx], last_block.len()) ^ cx;
        }
    }

    fn process_final(&mut self) -> [u8; 16] {
        if P::KeySize::USIZE == 16 && P::COUNT == 8 {
            self.state[1] ^= self.key.get_k1();
            self.state[2] ^= self.key.get_k2();
        } else if P::KeySize::USIZE == 16 && P::COUNT == 16 {
            self.state[2] ^= self.key.get_k1();
            self.state[3] ^= self.key.get_k2();
        } else if P::KeySize::USIZE == 20 {
            self.state[1] ^= keyrot(self.key.get_k0(), self.key.get_k1());
            self.state[2] ^= keyrot(self.key.get_k1(), self.key.get_k2());
            self.state[3] ^= keyrot(self.key.get_k2(), 0);
        }

        self.permute_12_and_apply_key();

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&u64::to_be_bytes(self.state[3]));
        tag[8..].copy_from_slice(&u64::to_be_bytes(self.state[4]));
        tag
    }

    pub(crate) fn encrypt_inplace(
        &mut self,
        message: &mut [u8],
        associated_data: &[u8],
    ) -> Array<u8, U16> {
        self.process_associated_data(associated_data);
        self.process_encrypt_inplace(message);
        Array::from(self.process_final())
    }

    pub(crate) fn decrypt_inplace(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        expected_tag: &Array<u8, U16>,
    ) -> Result<(), Error> {
        self.process_associated_data(associated_data);
        self.process_decrypt_inplace(ciphertext);

        let tag = self.process_final();
        if bool::from(tag.ct_eq(expected_tag)) {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use aead::{array::Array, consts::U16};

    use ascon::Word;
    use hex_literal::hex;

    use aead::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn clear_0to7() {
        assert_eq!(clear(0x0123456789abcdef, 1), 0x23456789abcdef);
        assert_eq!(clear(0x0123456789abcdef, 2), 0x456789abcdef);
        assert_eq!(clear(0x0123456789abcdef, 3), 0x6789abcdef);
        assert_eq!(clear(0x0123456789abcdef, 4), 0x89abcdef);
        assert_eq!(clear(0x0123456789abcdef, 5), 0xabcdef);
        assert_eq!(clear(0x0123456789abcdef, 6), 0xcdef);
        assert_eq!(clear(0x0123456789abcdef, 7), 0xef);
    }

    #[test]
    fn init_masked() {
        let key = <Parameters128 as Parameters>::InternalKey::from(&Into::<Array<u8, U16>>::into(
            hex!("000102030405060708090A0B0C0D0E0F"),
        ));
        let nonce: Array<u8, U16> = Into::into(hex!("000102030405060708090A0B0C0D0E0F"));
        let rng = ChaCha20Rng::seed_from_u64(0xDEADBEEFCAFEF00D);

        let masked_core: MaskedAsconCore<Parameters128, ChaCha20Rng> =
            MaskedAsconCore::new(&key, &nonce, rng);
        let core: AsconCore<Parameters128> = AsconCore::new(&key, &nonce);

        let masked_state = masked_core.state;
        let state = core.state;

        assert_eq!(masked_state.combine_shares(), state);
    }

    #[test]
    fn permute_12_and_apply_key_masked() {
        let key = <Parameters128 as Parameters>::InternalKey::from(&Into::<Array<u8, U16>>::into(
            hex!("000102030405060708090A0B0C0D0E0F"),
        ));
        let nonce: Array<u8, U16> = Into::into(hex!("000102030405060708090A0B0C0D0E0F"));
        let rng = ChaCha20Rng::seed_from_u64(0xDEADBEEFCAFEF00D);

        let mut masked_core: MaskedAsconCore<Parameters128, ChaCha20Rng> =
            MaskedAsconCore::new(&key, &nonce, rng);
        let mut core: AsconCore<Parameters128> = AsconCore::new(&key, &nonce);

        masked_core.permute_12_and_apply_key();
        core.permute_12_and_apply_key();

        let masked_state = masked_core.state;
        let state = core.state;

        assert_eq!(masked_state.combine_shares(), state);
    }

    #[test]
    fn permute_state_masked() {
        let key = <Parameters128 as Parameters>::InternalKey::from(&Into::<Array<u8, U16>>::into(
            hex!("000102030405060708090A0B0C0D0E0F"),
        ));
        let nonce: Array<u8, U16> = Into::into(hex!("000102030405060708090A0B0C0D0E0F"));
        let rng = ChaCha20Rng::seed_from_u64(0xDEADBEEFCAFEF00D);

        let mut masked_core: MaskedAsconCore<Parameters128, ChaCha20Rng> =
            MaskedAsconCore::new(&key, &nonce, rng);
        let mut core: AsconCore<Parameters128> = AsconCore::new(&key, &nonce);

        masked_core.permute_state();
        core.permute_state();

        let masked_state = masked_core.state;
        let state = core.state;

        assert_eq!(masked_state.combine_shares(), state);
    }

    #[test]
    fn process_associated_data_masked() {
        let key = <Parameters128 as Parameters>::InternalKey::from(&Into::<Array<u8, U16>>::into(
            hex!("000102030405060708090A0B0C0D0E0F"),
        ));
        let nonce: Array<u8, U16> = Into::into(hex!("000102030405060708090A0B0C0D0E0F"));
        let rng = ChaCha20Rng::seed_from_u64(0xDEADBEEFCAFEF00D);

        let mut masked_core: MaskedAsconCore<Parameters128, ChaCha20Rng> =
            MaskedAsconCore::new(&key, &nonce, rng);
        let mut core: AsconCore<Parameters128> = AsconCore::new(&key, &nonce);

        let associated_data = &hex!("0102030405060708090A0B0C0D0E0F");
        masked_core.process_associated_data(associated_data);
        core.process_associated_data(associated_data);

        let masked_state = masked_core.state;
        let state = core.state;

        assert_eq!(masked_state.combine_shares(), state);
    }

    #[test]
    fn process_encrypt_inplace_masked() {
        let key = <Parameters128 as Parameters>::InternalKey::from(&Into::<Array<u8, U16>>::into(
            hex!("000102030405060708090A0B0C0D0E0F"),
        ));
        let nonce: Array<u8, U16> = Into::into(hex!("000102030405060708090A0B0C0D0E0F"));
        let rng = ChaCha20Rng::seed_from_u64(0xDEADBEEFCAFEF00D);

        let mut masked_core: MaskedAsconCore<Parameters128, ChaCha20Rng> =
            MaskedAsconCore::new(&key, &nonce, rng);
        let mut core: AsconCore<Parameters128> = AsconCore::new(&key, &nonce);

        let mut message_1 = hex!("0102030405060708090A0B0C0D0E0F");
        let mut message_2 = message_1;
        masked_core.process_encrypt_inplace(message_1.as_mut_slice());
        core.process_encrypt_inplace(message_2.as_mut_slice());

        let masked_state = masked_core.state;
        let state = core.state;

        assert_eq!(masked_state.combine_shares(), state);
    }

    #[test]
    fn process_decrypt_inplace_masked() {
        let key = <Parameters128 as Parameters>::InternalKey::from(&Into::<Array<u8, U16>>::into(
            hex!("000102030405060708090A0B0C0D0E0F"),
        ));
        let nonce: Array<u8, U16> = Into::into(hex!("000102030405060708090A0B0C0D0E0F"));
        let rng = ChaCha20Rng::seed_from_u64(0xDEADBEEFCAFEF00D);

        let mut masked_core: MaskedAsconCore<Parameters128, ChaCha20Rng> =
            MaskedAsconCore::new(&key, &nonce, rng);
        let mut core: AsconCore<Parameters128> = AsconCore::new(&key, &nonce);

        let mut message_1 = hex!("0102030405060708090A0B0C0D0E0F");
        let mut message_2 = message_1;
        masked_core.process_decrypt_inplace(message_1.as_mut_slice());
        core.process_decrypt_inplace(message_2.as_mut_slice());

        let masked_state = masked_core.state;
        let state = core.state;

        assert_eq!(masked_state.combine_shares(), state);
    }

    #[test]
    fn process_final_masked() {
        let key = <Parameters128 as Parameters>::InternalKey::from(&Into::<Array<u8, U16>>::into(
            hex!("000102030405060708090A0B0C0D0E0F"),
        ));
        let nonce: Array<u8, U16> = Into::into(hex!("000102030405060708090A0B0C0D0E0F"));
        let rng = ChaCha20Rng::seed_from_u64(0xDEADBEEFCAFEF00D);

        let mut masked_core: MaskedAsconCore<Parameters128, ChaCha20Rng> =
            MaskedAsconCore::new(&key, &nonce, rng);
        let mut core: AsconCore<Parameters128> = AsconCore::new(&key, &nonce);

        let mut message_1 = hex!("000102030405060708090A0B0C0D0E0F");
        let mut message_2 = message_1;
        masked_core.process_decrypt_inplace(message_1.as_mut_slice());
        core.process_decrypt_inplace(message_2.as_mut_slice());

        let masked_tag = masked_core.process_final();
        let tag = core.process_final();
        let masked_state = masked_core.state;
        let state = core.state;

        assert_eq!(masked_state.combine_shares(), state);
        assert_eq!(masked_tag, tag);
    }

    #[test]
    fn clear_clear_word() {
        let w = Word(0xDEADBEEF, 0xCAFEF00D);
        let w_u: u64 = w.into();
        let w = clear_word(w, 4);
        let w_u = clear(w_u, 4);
        assert_eq!(w, w_u.into());
    }
}
