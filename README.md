# Masked Ascon Implementation in Rust

This repository contains a masked implementation of Ascon written in Rust.

- `simpleserial-ascon`: Main implementation.
- `ascon`: Fork of the original Ascon library with masked functionality added.
- `ascon-aead`: Fork of the original Ascon AEAD library with masked functionality added.

## Setup Instructions (Clean Ubuntu Install)

1. Install dependencies:
   ```bash
   sudo apt update
   sudo apt install -y build-essential libelf1 curl
   ```

2. Install Rust:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

3. Add target:
   ```bash
   rustup target add riscv32imc-unknown-none-elf
   ```

4. Set up the Ibex demo system:  
   Follow the instructions at [Ibex Demo System](https://github.com/lowRISC/ibex-demo-system/tree/main)

5. Run:
   ```bash
   ./simpleserial-ascon.sh
   ```
