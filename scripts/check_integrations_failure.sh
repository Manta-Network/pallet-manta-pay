#!/usr/bin/env bash

########################## Check Manta-Node ##########################

git clone https://github.com/Manta-Network/Manta.git

cd Manta/

# Update pallet-manta-pay upstream dependencies, in case we are integrating a change in one of them.
cargo update -p manta-error
cargo update -p manta-crypto
cargo update -p manta-asset
cargo update -p manta-data
cargo update -p manta-ledger
cargo update -p manta-api

# When integrating a change in pallet-manta-pay only, using the local code will be enough for the check.
sed -i "/pallet-manta-pay =/c\pallet-manta-pay = { path= '../../../../', default-features = false }" ./runtimes/manta/runtime/Cargo.toml

cargo build
cargo build --all-features

# Check Wasm benchmarking 
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic init_asset --execution=Wasm --wasm-execution Compiled --repeat 100 
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic transfer_asset --execution=Wasm --wasm-execution Compiled --repeat 100
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic mint_private_asset --execution=Wasm --wasm-execution Compiled --repeat 10
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic private_transfer --execution=Wasm --wasm-execution Compiled --repeat 10
target/debug/manta benchmark --pallet pallet_manta_pay --extrinsic reclaim --execution=Wasm --wasm-execution Compiled --repeat 10 