# pallet-manta-dap

## todos:

* write an instruction 
* update test coverage
* end-to-end benchmarks


## Howto check test coverage
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
The `grcov` tool mis-labled many lines of the code as not tested.

![Result](https://github.com/Manta-Network/pallet-manta-dap/blob/master/coverage/coverage.png)
