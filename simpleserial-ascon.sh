#!/bin/bash

pushd simpleserial-ascon
cargo build --release
popd
pushd ibex-demo-system
./build/lowrisc_ibex_demo_system_0/sim-verilator/Vtop_verilator \
  -t --meminit=ram,../target/riscv32imc-unknown-none-elf/release/simpleserial-ascon
echo -e "sim_test UART log:\n"
cat uart0.log
echo -e "\n"
popd > /dev/null
