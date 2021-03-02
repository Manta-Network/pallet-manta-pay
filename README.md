# pallet-manta-dap

This is a pallet that enables decentialized anynonymous payment (DAP) protocol.
This code is a proof-of-concept; is not properly reviewed or audited and it likely to have 
severe bugs or security pitfalls.
Use at your own risk!

## Pre-computed tokens

``` sh
cargo run --bin pre_comp --release
```

## Test coverage
* install [grcov](https://github.com/mozilla/grcov):
```
cargo install grcov
```
* build and run test
``` sh
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
export RUSTDOCFLAGS="-Cpanic=abort"
cargo +nightly build
cargo +nightly test 
```
* generate the report 
``` sh
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/
open target/debug/coverage/index.html
```

* The report is also available within `coverage` folder. Our coverage is way above the status shown here.
The `grcov` tool mis-labled many lines of the code as not-covered.

![Result](https://github.com/Manta-Network/pallet-manta-dap/blob/master/coverage/coverage.png)

## Benchmark

``` sh
cargo bench
```

* benchmark enviroment

MBP 13inch 2021,  CPU:  2.3 GHz Quad-Core Intel Core i7, Memory 32 GB 3733 MHz LPDDR4X.

  * with `criterion` (take some time)
``` sh
manta_bench/ZKP verification                        
                        time:   [15.308 ms 15.386 ms 15.465 ms]
```
  * with `frame-benchmarking`: within `manta-node` repo, run 
```
cargo +nightly build --release -p manta-node -Z package-features --package manta-runtime --features runtime-benchmarks
target/release/manta-node benchmark --pallet pallet_manta_dap --extrinsic init --repeat 100 --wasm-execution 
target/release/manta-node benchmark --pallet pallet_manta_dap --extrinsic transfer --repeat 100 --wasm-execution 
target/release/manta-node benchmark --pallet pallet_manta_dap --extrinsic mint --repeat 100 --wasm-execution 
target/release/manta-node benchmark --pallet pallet_manta_dap --extrinsic manta_transfer --repeat 100 --wasm-execution 
target/release/manta-node benchmark --pallet pallet_manta_dap --extrinsic forfeit --repeat 100 --wasm-execution 
```

| Function      | init |  trasfer | mint | manta_transfer | forfeit |
| ----------- |:-----------:|:-----------:|:-----------:|:-----------:|:-----------:|
| Time       |    26 \mu s    |  29 \mu s | 25.3 ms | 29.2 ms | 26.8 ms |
