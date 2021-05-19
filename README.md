# pallet-manta-pay

This is a pallet that enables decentralized anonymous payment (pay) protocol.
The best way to use this repo is to invoke it with a `manta-runtime`,
available from either [manta-node](https://github.com/Manta-Network/manta-node) or [cumulus](https://github.com/Manta-Network/cumulus).

__Disclaimer__: This code is a proof-of-concept; is not properly reviewed or audited and is likely to have 
severe bugs or security pitfalls.
Use at your own risk!

## Documentations

``` sh
cargo doc --open
```


## Pre-computed tokens

``` sh
cargo run --bin pre_comp --release
```

## Test coverage
* install [grcov](https://github.com/mozilla/grcov):
```
cargo install grcov
```
* build and run test (extremely slow)
``` sh
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
export RUSTDOCFLAGS="-Cpanic=abort"
cargo +nightly-2021-01-29 test
```
* generate the report 
``` sh
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/
open target/debug/coverage/index.html
```

* The report is also available within `coverage` folder. 

![Result](https://github.com/Manta-Network/pallet-manta-pay/blob/master/coverage/coverage.png)

## Benchmark
* benchmark environment

AMD Ryzen 9 5900X 12-Core Processor; Ubuntu 20.04; rustc 1.50.0 (cb75ad5db 2021-02-10)
Crucial SSD P2 M.2 NVME PCIEx4; Crucial Ballistix 2x16GB

  * with `criterion` (take some time)

``` sh
cargo bench
```
sample output
``` sh
deserialization/hash param                        
                        time:   [113.15 us 113.18 us 113.23 us]
deserialization/commit param                        
                        time:   [132.49 us 132.51 us 132.53 us]
perdersen/hash param gen                        
                        time:   [7.0316 ms 7.0321 ms 7.0326 ms]
perdersen/commit open   time:   [59.471 us 59.490 us 59.511 us]
merkle_tree/with 1 leaf time:   [1.1660 ms 1.1664 ms 1.1669 ms]
merkle_tree/with 2 leaf time:   [1.3025 ms 1.3030 ms 1.3035 ms]
merkle_tree/with 3 leaf time:   [1.5725 ms 1.5730 ms 1.5735 ms]
transfer/ZKP verification                        
                        time:   [8.8006 ms 8.8016 ms 8.8028 ms]                   
```
  * with `frame-benchmarking`: within `manta-node` repo, run 
```
cargo +nightly build --release -p manta-node -Z package-features --package manta-runtime --features runtime-benchmarks --wasm-execution compiled
target/release/manta-node benchmark --pallet pallet_manta_pay --extrinsic init --repeat 100 --execution=wasm --wasm-execution compiled
target/release/manta-node benchmark --pallet pallet_manta_pay --extrinsic transfer --repeat 100 --execution=wasm --wasm-execution compiled
target/release/manta-node benchmark --pallet pallet_manta_pay --extrinsic mint --repeat 100 --execution=wasm --wasm-execution compiled
target/release/manta-node benchmark --pallet pallet_manta_pay --extrinsic manta_transfer --repeat 100 --execution=wasm --wasm-execution compiled
target/release/manta-node benchmark --pallet pallet_manta_pay --extrinsic reclaim --repeat 100 --execution=wasm --wasm-execution compiled
```
sample output
| Function      | init |  transfer | mint | manta_transfer | reclaim |
| ----------- |:-----------:|:-----------:|:-----------:|:-----------:|:-----------:|
| Rust       |    640 us   |  13 us | 1.9 ms | 10.1 ms | 8.8 ms |
| Wasm |    2.8 ms    |  111  us | 13.1 ms | 130 ms | 107 ms |
