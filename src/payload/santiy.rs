// Copyright 2019-2021 Manta Network.
// This file is part of pallet-manta-pay.
//
// pallet-manta-pay is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// pallet-manta-pay is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with pallet-manta-pay.  If not, see <http://www.gnu.org/licenses/>.

use super::*;
use crate::zkp::*;
use pallet_manta_asset::SanityCheck;

impl SanityCheck for MintData {
	type Param = CommitmentParam;

	fn sanity(&self, param: &Self::Param) -> bool {
		let payload = [self.amount.to_le_bytes().as_ref(), self.k.as_ref()].concat();
		<MantaCrypto as Commitment>::check_commitment(&param, &payload, &self.s, &self.cm)
	}
}

impl SanityCheck for PrivateTransferData {
	type Param = VerificationKey;

	/// the sanity check for the private transfer data is
	/// to check the validity of the ZKP proof
	fn sanity(&self, param: &Self::Param) -> bool {
		manta_verify_transfer_zkp(param, self)
	}
}

impl SanityCheck for ReclaimData {
	type Param = VerificationKey;

	/// the sanity check for the reclaim data is
	/// to check the validity of the ZKP proof
	fn sanity(&self, param: &Self::Param) -> bool {
		manta_verify_reclaim_zkp(param, self)
	}
}
