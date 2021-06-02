#!/usr/bin/env bash

git clone https://github.com/Manta-Network/Manta.git

cd Manta/

pwd

sed -i "s@pallet-manta-pay = {git='https://github.com/Manta-Network/pallet-manta-pay', branch='calamari', default-features = false }@pallet-manta-pay = {path= '../../../../', default-features = false }@g" ./runtimes/manta/runtime/Cargo.toml

cat Cargo.toml
         
cargo build --release --all-features
