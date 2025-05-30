// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#![no_main]
#![no_std]

extern crate panic_halt as _;

pub(crate) mod capture_to_target;
pub(crate) mod heap;
pub(crate) mod simpleserial;
pub(crate) mod target_to_capture;
pub(crate) mod uart;
pub(crate) mod util;

use ibex_demo_system_pac::{gpioa::out::OUT_SPEC, Peripherals, Reg};
use riscv_rt::entry;

use simpleserial::{CmdError, CmdResponse, SimpleSerial, MAX_SS_LEN};


static mut KEY: [u8; 16] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
static mut NONCE: [u8; 16] = [0x85, 0xac, 0x04, 0xcb, 0x2d, 0xfa, 0x40, 0xf1, 0x9c, 0x1b, 0x16, 0xb7, 0x3d, 0x56, 0xc8, 0xb8];
static mut AD: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
static mut SEED: [u8; 8] = [0x00; 8];




#[entry]
fn main() -> ! {
    let p = Peripherals::take().unwrap();

    let mut uart = uart::Uart::new(p.UART0);
    let pins = &p.GPIOA.out;
    pins.write(|w| unsafe { w.bits(0x00) });

    // let _ = writeln!(uart, "Hello Rusty Ibex System!!\r");

    // UNSAFE: Called exactly once, right here.
    unsafe { heap::init() };

    // Now we're free to use dynamic allocation!

    let mut cmds: SimpleSerial<8> = SimpleSerial::new(pins);
    let _ = cmds.push(b'p', 16, &encrypt_ascon);
    let _ = cmds.push(b'k', 16, &get_key);
    let _ = cmds.push(b'n', 16, &get_nonce);
    let _ = cmds.push(b'a', 8, &get_ad); 
    let _ = cmds.push(b's', 8, &get_seed);
    loop {
        let _ = cmds.simpleserial_get(&mut uart, pins);
    }

}

fn get_key(dlen: u8, data: [u8; MAX_SS_LEN], _: &Reg<OUT_SPEC>) -> Result<Option<CmdResponse>, CmdError> {
    if dlen as usize != 16 {
        return Err(CmdError::InvalidLength);
    }
    unsafe {KEY.copy_from_slice(&data[..dlen as usize]);}
    Ok(None)
}

fn get_nonce(dlen: u8, data: [u8; MAX_SS_LEN], _: &Reg<OUT_SPEC>) -> Result<Option<CmdResponse>, CmdError> {
    if dlen as usize != 16 {
        return Err(CmdError::InvalidLength);
    }
    unsafe {NONCE.copy_from_slice(&data[..dlen as usize]);}
    Ok(None)
}

fn get_ad(dlen: u8, data: [u8; MAX_SS_LEN], _: &Reg<OUT_SPEC>) -> Result<Option<CmdResponse>, CmdError> {
    if dlen as usize != 8 {
        return Err(CmdError::InvalidLength);
    }
    unsafe {AD.copy_from_slice(&data[..dlen as usize]);}
    Ok(None)
}

fn get_seed(dlen: u8, data: [u8; MAX_SS_LEN], _: &Reg<OUT_SPEC>) -> Result<Option<CmdResponse>, CmdError> {
    if dlen as usize != 8 {
        return Err(CmdError::InvalidLength);
    }
    unsafe {SEED.copy_from_slice(&data[..dlen as usize]);}
    Ok(None)
}

fn encrypt_ascon(dlen: u8, data: [u8; MAX_SS_LEN], pins: &Reg<OUT_SPEC>) -> Result<Option<CmdResponse>, CmdError> {
    if dlen as usize != 16 {
        return Err(CmdError::InvalidLength);
    }
    if MAX_SS_LEN < 16 {
        return Err(CmdError::InvalidCommand);
    }
    
    let mut PT: [u8; 16] = [0x00; 16];
    PT[..dlen as usize].copy_from_slice(&data[..dlen as usize]);



    use ascon_aead::aead::{Payload, Aead};
    use ascon_aead::{Ascon128, Key, MaskedAscon128, Nonce};
    

    use ::rand::prelude::SeedableRng;
    use rand_chacha::ChaCha20Rng;


    let mut seed_as_u64 = 0;
    unsafe {seed_as_u64 = u64::from_le_bytes(SEED)};
    let mut rng = ChaCha20Rng::seed_from_u64(seed_as_u64);

    let input_plaintext: &[u8] = PT.as_ref();
    let input_ad = unsafe{AD.as_ref()};
    let payload = Payload{ msg: input_plaintext, aad: input_ad };

    let key = Key::<Ascon128>::from_slice(unsafe { &KEY });
    let cipher = MaskedAscon128::new(key, rng);

    let nonce = Nonce::<Ascon128>::from_slice(unsafe { &NONCE }); // 128-bits; unique per message

    SimpleSerial::<8>::trigger_high(pins);

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .expect("encryption failure!"); // NOTE: handle this error to avoid panics!

    SimpleSerial::<8>::trigger_low(pins);


    let mut ciphertext_array: [u8; MAX_SS_LEN] = [0x00; MAX_SS_LEN];
    ciphertext_array.copy_from_slice(&ciphertext[..MAX_SS_LEN]); 


    Ok(Some(CmdResponse {
        char: b'r',
        len: MAX_SS_LEN as u8,
        data: ciphertext_array,
    }))
}