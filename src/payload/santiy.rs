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
use manta_asset::SanityCheck;
use manta_error::MantaError;

impl SanityCheck for MintData {
	type Param = CommitmentParam;

	fn sanity(&self, param: &Self::Param) -> Result<bool, MantaError> {
		// check that
		// cm = com( asset_id | v||k, s )
		let payload = [
			(self.asset_id as u64).to_le_bytes().as_ref(),
			self.amount.to_le_bytes().as_ref(),
			self.k.as_ref(),
		]
		.concat();
		<MantaCrypto as Commitment>::check_commitment(&param, &payload, &self.s, &self.cm)
	}
}
