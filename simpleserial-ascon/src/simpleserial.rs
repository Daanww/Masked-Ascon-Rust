//! The ChipWhisperer Simple Serial Protocol
//!
#![warn(missing_docs)]
#![deny(macro_use_extern_crate)]
#![feature(generic_const_exprs)]


use crate::uart::Uart;

use embedded_hal::blocking::delay::DelayMs;
use ibex_demo_system_pac::{gpioa::out::OUT_SPEC, Reg};

use core::fmt::Write;

pub(crate) const MAX_SS_LEN: usize = 32;

/// Errors
#[cfg_attr(test, derive(Debug, PartialEq, Clone))]
pub enum PktError {
    /// There were insufficient bytes in the BUS
    InsufficientBytes {
        /// Length of BUS buffer
        buffer_length: usize,
    },
    /// The DLEN didn't match the actual data
    IncorrectDataLength {
        /// Length of BUS buffer
        buffer_length: usize,
        /// DLEN
        data_length: usize,
    },
    /// There was an invalid CRC
    CrcInvalid,
    InvalidHexCharacter,

}

pub enum CmdError {
    OK,
    InvalidCommand,
    BadCRC,
    Timeout,
    InvalidLength,
    UnexpectedFrameByte,
    Custom(u8),
}


pub enum SSError {
    PktError,
    CmdError
}

pub struct CmdResponse { pub char: u8, pub len: u8, pub data: [u8; MAX_SS_LEN]}
type CmdFn = &'static dyn Fn(u8, [u8; MAX_SS_LEN], &Reg<OUT_SPEC>) -> Result<Option<CmdResponse>, CmdError>;

#[derive(Clone, Copy)]
pub struct CmdSpecification {
    cmd: u8,
    len: u8,
    handler: CmdFn,
}

/// Container for SimpleSerial commands
pub struct SimpleSerial<const MAX_CMDS: usize> {
    cmds: [Option<CmdSpecification>; MAX_CMDS],
    current_size: u8,
}

impl<const MAX_CMDS: usize> SimpleSerial<MAX_CMDS> {
    /// Create a new SimpleSerial Instance
    pub fn new(a: &Reg<OUT_SPEC>) -> Self {
        Self::trigger_setup(a);
        Self::new_no_init()
    }

    pub fn trigger_high(a: &Reg<OUT_SPEC>) {
        a.write(|w| unsafe { w.bits(0x01) });
    }

    pub fn trigger_low(a: &Reg<OUT_SPEC>) {
        a.write(|w| unsafe { w.bits(0x00) });
    }

    fn trigger_setup(a: &Reg<OUT_SPEC>) {
        Self::trigger_low(a)
    }

    /// Create a new SimpleSerial Instance without initializing the platform, uart and trigger.
    pub fn new_no_init() -> Self {
        SimpleSerial {
            cmds: [None; MAX_CMDS],
            current_size: 0,
        }
    }

    /// Add an extra command handler
    pub fn push(&mut self, cmd: u8, len: u8, handler: CmdFn) -> Result<(), ()> {
        let cur_size = usize::from(self.current_size);

        // Check that we are not exceeding the command limit
        if MAX_CMDS - cur_size <= 1 {
            return Err(());
        }

        self.cmds[cur_size] = Some(CmdSpecification { cmd, len, handler });
        self.current_size += 1;

        Ok(())
    }


    pub fn simpleserial_get(&self, uart: &mut Uart, pins: &Reg<OUT_SPEC>) -> Result<(), SSError> {
        let mut ascii_buf: [u8; 2 * MAX_SS_LEN] = [0; 2 * MAX_SS_LEN];

        //get command character
        let mut c: u8 = getch(uart);

        //find the specific command in the command list
        let cmd = {
            let mut maybe_cmd = None;
            for maybe_spec in self.cmds {
                match maybe_spec {
                    Some(cmd_spec) if cmd_spec.cmd == c => {
                        maybe_cmd = Some(cmd_spec);
                    }
                    _ => (),
                }
            }

            match maybe_cmd {
                Some(inner) => inner,
                None => {
                    return Err(SSError::CmdError);
                }
            }
        };

        //receive data characters for this command
        for i in 0..2 * cmd.len as usize {
            c = getch(uart);

            //check for early \n or \r which implies faulty data for the command
            if c == b'\n' || c == b'\r' {
                return Err(SSError::CmdError);
            }

            ascii_buf[i] = c;
        }

        //assert that the last character is \n or \r
        c = getch(uart);
        if c != b'\n' && c != b'\r' {
            return Err(SSError::CmdError);

        }
        //decode the ascii input
        let data_buff: [u8; MAX_SS_LEN] = match ascii_to_binary(ascii_buf, cmd.len) {
            Ok(data) => data,
            _ => {return Err(SSError::PktError);},
        };
        match (cmd.handler)(cmd.len, data_buff, pins) {
            Ok(Some(CmdResponse { char, len, data })) => {
                let _ = Self::simpleserial_put(char, len, data, uart);
                let _ = Self::simpleserial_put(b'z', 1, [0x00u8; MAX_SS_LEN], uart);
                Ok(())
            },
            Ok(None) => {
                let _ = Self::simpleserial_put(b'z', 1, [0x00u8; MAX_SS_LEN], uart);
                Ok(())
            },
            _ => Err(SSError::PktError)
        }

    }

    pub fn simpleserial_put(c: u8, len:u8, data: [u8; MAX_SS_LEN], uart: &mut Uart) -> Result<(), SSError> {
        if len as usize > MAX_SS_LEN {
            return Err(SSError::PktError);
        }
        let ascii: [u8; 2 * MAX_SS_LEN] = binary_to_ascii(data, len);
        
        //write the first character
        putch(uart, c);
        //Write each byte as 2 nibbles
        for i in 0 .. 2 * len as usize {
            putch(uart, ascii[i]);
        }

        //write trailing '\n'
        putch(uart, b'\n');

        Ok(())
    }
}

pub(crate) fn putch(uart: &mut Uart, c: u8) {
    let _ = write!(uart, "{}", c as char);
}

pub(crate) fn getch(uart: &Uart) -> u8 {
    loop {
        match uart.get_data() {
            Some(byte) => {
                return byte;
            }
            None => (),
        }
    }
}

pub fn binary_to_ascii(hex_data: [u8; MAX_SS_LEN], len: u8) -> [u8; 2* MAX_SS_LEN] {
    let hexmap = [
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E',
        b'F',
    ];
    let mut buffer = [0; 2 * MAX_SS_LEN];
    for (i, byte) in hex_data
        .iter()
        .flat_map(|&byte| {
            let high = hexmap[(byte >> 4) as usize];
            let low = hexmap[(byte & 0x0F) as usize];
            [high, low]
        })
        .enumerate()
    {
        if i > 2 * len as usize {
            break;
        }
        buffer[i] = byte;
    }
    buffer
}

pub fn ascii_to_binary(hex_bytes: [u8; 2* MAX_SS_LEN], len: u8) -> Result<[u8; MAX_SS_LEN], PktError> {
    if len as usize > MAX_SS_LEN {
        return Err(PktError::IncorrectDataLength { buffer_length: MAX_SS_LEN, data_length: len as usize });
    }
    

    let mut binary_data: [u8; MAX_SS_LEN] = [0u8; MAX_SS_LEN];


    for i in 0..len as usize {
        let high = hex_to_digit(hex_bytes[2 * i])?;
        let low = hex_to_digit(hex_bytes[2 * i + 1])?;
        binary_data[i] = (high << 4) | low;
    }

    Ok(binary_data)
}

fn hex_to_digit(byte: u8) -> Result<u8, PktError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PktError::InvalidHexCharacter),
    }
}
