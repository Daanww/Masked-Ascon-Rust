// sim_test/src/uart.rs

use core::fmt::{self, Write};
pub struct Uart {
    uart: ibex_demo_system_pac::UART0,
}

impl Uart {
    pub fn new(uart: ibex_demo_system_pac::UART0) -> Self {
        Uart { uart }
    }

    fn uart_log(&self, msg: &str) {
        for c in msg.bytes() {
            self.uart_putc(c);
        }
    }

    fn uart_putc(&self, c: u8) {
        self.uart.tx.write(|w| {
            w.data().variant(c);
            w
        });
    }

    fn rx_buf_empty(&self) -> bool {
        self.uart.status.read().rx_empty().bit_is_set()
    }

    fn read_byte(&self) -> u8 {
        self.uart.rx.read().data().bits()
    }

    pub fn get_data(&self) -> Option<u8> {
        if self.rx_buf_empty() {
            None
        } else {
            Some(self.read_byte())
        }
    }
}

// Implementing this trait will allow us to use the `writeln!` macro to format log messages.
impl Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.uart_log(s);
        Ok(())
    }
}
