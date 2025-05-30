// use array_utils::{drift_to_begin, drift_to_end};

// use riscv::delay::McycleDelay;
// use crate::uart::Uart;
// use crate::simpleserial::{getch, putch, CRC_GEN_POLY, PKT_SIZE};

// use core::fmt::Write;


// /// Write a buffer away to the shared BUS
// /// If it comes across a null byte, it will write it away and then stop writing
// pub fn write_away<const BUFFER_SIZE: usize>(uart: &mut Uart, buffer: [u8; BUFFER_SIZE]) {
//     // let _ = writeln!(uart, "Write_away, {}\r", BUFFER_SIZE);

//     for i in 0..BUFFER_SIZE {
//         let token = buffer[i];
//         // unsafe { crate::firmware::putch(token) };
//         putch(uart, token);
//         if token == 0x00 {
//             break;
//         }
//     }
//     // write trailing \n
//     let _ = write!(uart, "\n");
//     let _ = writeln!(uart, "\r");
// }

// /// Read from the shared BUS until we find a null byte
// pub fn read_away<const BUFFER_SIZE: usize>(uart: &mut Uart, delay: &mut McycleDelay) -> ([u8; BUFFER_SIZE], usize) {
//     let mut byte_array = [0; BUFFER_SIZE];
//     let mut size = BUFFER_SIZE;

//     for i in 0..BUFFER_SIZE {
//         // match unsafe { crate::firmware::getch() } {
//         match getch(uart, delay) {
//             0x00 => {
//                 size = i + 1;
//                 break;
//             }
//             token => byte_array[i] = token,
//         }
//     }

//     (byte_array, size)
// }

// pub fn pkt_insert_crc8(buffer: [u8; 254], len: usize) -> [u8; 254] {
//     // Move everything back to the front of the buffer
//     drift_to_begin(
//         // Insert the CRC at the end of the buffer
//         crc8_rs::insert_crc8(
//             // Move the buffer content to the end of a new buffer
//             // leaving one byte for the CRC byte
//             drift_to_end(buffer, len, 1, 0),
//             CRC_GEN_POLY,
//         ),
//         254 - len - 1,
//         0,
//         0,
//     )
// }

// /// Perform CRC injection than stuff the buffer
// pub fn pkt_stuff(buffer: [u8; 254], len: usize) -> [u8; PKT_SIZE] {
//     // Stuff the crced buffer
//     let mut stuffed = cobs_rs::stuff(buffer, 0x00);

//     // Append a zero byte at the proper location
//     stuffed[len + 2] = 0x00;
//     stuffed
// }
