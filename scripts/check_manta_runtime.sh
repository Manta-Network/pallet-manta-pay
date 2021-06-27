#!/usr/bin/env bash

########################## Check Manta-Node ##########################

git clone https://github.com/Manta-Network/Manta.git

cd Manta/

sed -i "s@pallet-manta-pay = { git='https://github.com/Manta-Network/pallet-manta-pay', branch='calamari', default-features = false }@pallet-manta-pay = {path= '../../../../', default-features = false }@g" ./runtimes/manta/runtime/Cargo.toml
         
cargo build
cargo build --all-features

# Check Wasm benchmarking 
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic init_asset --execution=Wasm --wasm-execution Compiled --repeat 100 
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic transfer_asset --execution=Wasm --wasm-execution Compiled --repeat 100
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic mint_private_asset --execution=Wasm --wasm-execution Compiled --repeat 10
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic private_transfer --execution=Wasm --wasm-execution Compiled --repeat 10
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic reclaim --execution=Wasm --wasm-execution Compiled --repeat 10 