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

impl Default for PrivateTransferData {
	fn default() -> Self {
		Self {
			sender_1: SenderData::default(),
			sender_2: SenderData::default(),
			receiver_1: ReceiverData::default(),
			receiver_2: ReceiverData::default(),
			proof: [0u8; 192],
		}
	}
}

impl Default for ReclaimData {
	fn default() -> Self {
		Self {
			reclaim_amount: 0,
			sender_1: SenderData::default(),
			sender_2: SenderData::default(),
			receiver: ReceiverData::default(),
			proof: [0u8; 192],
		}
	}
}
