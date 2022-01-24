// Copyright 2019-2022 Manta Network.
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

//! Precomputed Coins
//!
//! THIS FILE IS AUTOMATICALLY GENERATED by `src/bin/precompute_coins.rs`. DO NOT EDIT.

pub(crate) const MINT: &[u8] = &[
	1, 0, 0, 0, 0, 4, 160, 134, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 134, 27, 19, 222,
	31, 11, 82, 76, 171, 50, 122, 73, 7, 80, 180, 154, 135, 40, 142, 66, 125, 210, 71, 233, 52, 44,
	41, 225, 126, 158, 212, 0, 101, 165, 223, 130, 254, 206, 187, 98, 53, 235, 89, 168, 231, 58,
	40, 206, 188, 9, 105, 228, 163, 53, 247, 4, 154, 140, 221, 31, 6, 166, 22, 69, 137, 125, 228,
	57, 171, 232, 130, 92, 232, 131, 228, 57, 17, 135, 106, 57, 10, 44, 172, 22, 107, 65, 231, 114,
	39, 182, 176, 198, 104, 136, 237, 230, 12, 187, 212, 219, 0, 67, 200, 252, 33, 96, 174, 76, 43,
	67, 41, 119, 2, 203, 66, 76, 27, 223, 207, 91, 91, 163, 162, 100, 250, 97, 233, 235, 67, 215,
	42, 220, 135, 93, 15, 81, 180, 172, 57, 220, 56, 29, 142, 251, 114, 147, 11, 140, 5, 70, 101,
	136, 202, 14, 13, 83, 154, 57, 203, 123, 153, 105, 72, 232, 166, 171, 55, 170, 191, 7, 245, 81,
	109, 21, 66, 192, 115, 156, 80, 193, 111, 251, 65, 150, 48, 14, 3, 56, 171, 116, 97, 157, 126,
	5, 98, 165, 15, 228, 143, 187, 34, 155, 224, 152, 215, 140, 241, 39, 86, 144, 46, 83, 51, 47,
	112, 149, 186, 143, 35, 235, 216, 62, 12, 137, 133, 153, 174, 235, 150, 184, 183, 175, 184,
	215, 220, 101, 34, 40, 13, 70, 18, 246, 127, 174, 152, 64, 67, 224, 124, 145, 74, 68, 87, 173,
	99, 253, 154, 152, 79, 241, 78, 145, 10, 0, 166, 255, 36, 151, 213, 120, 76, 5, 253, 155, 93,
	51, 48, 223, 34, 168, 166, 101, 137, 10, 171, 216, 1, 241, 26, 14, 75, 131, 138,
];

pub(crate) const PRIVATE_TRANSFER_INPUT_0: &[u8] = &[
	1, 0, 0, 0, 0, 4, 16, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 110, 53, 223, 119,
	114, 19, 186, 115, 12, 123, 84, 248, 44, 45, 207, 121, 102, 189, 109, 25, 205, 175, 146, 168,
	226, 165, 179, 220, 58, 70, 161, 101, 43, 106, 30, 181, 94, 119, 225, 117, 85, 130, 236, 183,
	4, 153, 94, 172, 123, 206, 175, 78, 122, 7, 122, 195, 217, 60, 241, 161, 53, 173, 10, 162, 43,
	52, 157, 220, 6, 57, 32, 154, 196, 225, 122, 52, 48, 41, 148, 140, 158, 239, 238, 86, 126, 221,
	243, 60, 34, 14, 140, 175, 69, 160, 22, 142, 161, 47, 48, 32, 0, 203, 244, 154, 193, 116, 254,
	56, 164, 119, 183, 220, 121, 138, 128, 238, 162, 210, 83, 216, 137, 95, 165, 104, 146, 67, 149,
	58, 71, 149, 98, 234, 33, 158, 184, 186, 5, 63, 214, 222, 122, 232, 44, 59, 114, 175, 68, 247,
	150, 235, 9, 191, 39, 146, 166, 148, 119, 63, 89, 204, 120, 20, 69, 240, 214, 52, 179, 230, 77,
	63, 178, 230, 164, 183, 202, 105, 85, 26, 131, 199, 150, 181, 75, 226, 150, 121, 34, 93, 165,
	125, 227, 231, 127, 88, 91, 173, 1, 126, 130, 111, 178, 205, 212, 186, 66, 200, 43, 240, 149,
	4, 250, 160, 248, 16, 119, 113, 111, 62, 14, 45, 158, 28, 207, 124, 250, 97, 32, 202, 188, 59,
	217, 57, 13, 177, 146, 65, 84, 169, 164, 53, 50, 8, 191, 156, 2, 27, 208, 103, 77, 90, 77, 164,
	115, 209, 228, 33, 101, 96, 86, 158, 62, 249, 8, 201, 18, 226, 252, 81, 153, 75, 151, 64, 220,
	207, 244, 143, 209, 182, 153, 12, 95, 23, 201, 124, 165, 114, 43, 213, 13, 136, 150, 80, 136,
];

pub(crate) const PRIVATE_TRANSFER_INPUT_1: &[u8] = &[
	1, 0, 0, 0, 0, 4, 32, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 75, 99, 52, 155, 249,
	28, 2, 231, 47, 24, 66, 132, 67, 57, 54, 59, 246, 140, 125, 218, 200, 65, 119, 123, 247, 213,
	128, 15, 28, 209, 161, 72, 95, 127, 13, 203, 151, 3, 122, 159, 40, 113, 90, 210, 207, 232, 200,
	231, 46, 175, 47, 204, 9, 36, 212, 75, 53, 245, 176, 111, 61, 179, 105, 218, 113, 107, 192,
	178, 209, 39, 236, 182, 28, 193, 133, 106, 220, 189, 198, 75, 221, 101, 163, 211, 171, 151, 98,
	165, 107, 96, 13, 51, 188, 47, 223, 189, 49, 232, 2, 232, 0, 203, 50, 251, 198, 133, 233, 128,
	7, 221, 143, 228, 59, 123, 109, 223, 242, 239, 22, 219, 0, 178, 111, 222, 190, 148, 247, 116,
	209, 197, 118, 106, 122, 35, 188, 76, 20, 61, 145, 138, 242, 40, 123, 138, 40, 64, 10, 84, 0,
	75, 25, 229, 82, 147, 2, 143, 108, 134, 207, 177, 209, 172, 98, 106, 196, 149, 126, 204, 165,
	61, 123, 74, 96, 167, 140, 253, 146, 13, 197, 210, 239, 226, 91, 191, 100, 45, 123, 141, 143,
	155, 34, 140, 72, 204, 1, 181, 16, 112, 123, 59, 71, 133, 180, 196, 17, 212, 227, 42, 108, 255,
	180, 14, 23, 61, 226, 97, 198, 3, 126, 139, 250, 253, 232, 241, 49, 61, 238, 247, 254, 220, 72,
	181, 44, 103, 53, 178, 212, 118, 169, 21, 252, 241, 48, 71, 21, 101, 217, 78, 198, 248, 44,
	106, 138, 199, 0, 152, 69, 145, 35, 2, 147, 157, 139, 242, 200, 124, 241, 132, 153, 124, 102,
	115, 85, 70, 111, 19, 125, 30, 161, 107, 63, 255, 175, 86, 240, 80, 23, 37, 198, 42, 90, 126,
	10,
];

pub(crate) const PRIVATE_TRANSFER: &[u8] = &[
	0, 0, 8, 149, 48, 185, 86, 16, 241, 213, 134, 17, 43, 239, 169, 173, 227, 144, 139, 104, 111,
	171, 170, 160, 153, 164, 105, 105, 64, 203, 29, 167, 223, 142, 48, 112, 245, 188, 240, 98, 103,
	196, 86, 28, 96, 123, 211, 134, 229, 59, 221, 222, 11, 174, 6, 113, 105, 55, 62, 221, 247, 176,
	62, 224, 157, 133, 77, 99, 205, 130, 255, 236, 50, 34, 123, 65, 2, 126, 135, 118, 208, 26, 8,
	12, 70, 32, 45, 234, 212, 225, 80, 118, 252, 108, 134, 57, 39, 203, 108, 81, 5, 120, 62, 111,
	163, 131, 68, 34, 9, 63, 90, 137, 97, 83, 216, 28, 242, 27, 255, 246, 96, 126, 12, 150, 110,
	59, 241, 158, 221, 167, 7, 8, 46, 137, 16, 109, 57, 207, 16, 84, 109, 17, 237, 186, 250, 65,
	42, 242, 130, 107, 243, 82, 10, 188, 220, 154, 150, 196, 27, 175, 99, 169, 39, 4, 214, 108,
	188, 212, 51, 19, 107, 149, 151, 89, 130, 164, 36, 233, 109, 18, 188, 62, 163, 232, 93, 49, 98,
	107, 92, 160, 144, 179, 189, 68, 156, 175, 87, 179, 50, 198, 133, 216, 27, 13, 25, 123, 73,
	207, 31, 93, 42, 246, 25, 177, 129, 91, 41, 116, 83, 28, 28, 3, 20, 190, 131, 222, 91, 123,
	138, 172, 221, 182, 172, 135, 249, 173, 207, 149, 144, 133, 12, 140, 223, 227, 96, 47, 43, 99,
	142, 234, 72, 187, 244, 94, 239, 228, 151, 74, 235, 126, 143, 208, 151, 56, 34, 230, 54, 111,
	107, 66, 9, 50, 4, 27, 26, 253, 12, 187, 27, 80, 194, 108, 240, 173, 124, 243, 195, 150, 125,
	110, 161, 238, 65, 63, 217, 254, 2, 30, 190, 227, 241, 216, 90, 148, 162, 20, 22, 214, 44, 31,
	238, 148, 235, 65, 106, 215, 138, 201, 121, 131, 203, 92, 118, 46, 110, 135, 163, 193, 30, 0,
	137, 151, 0, 62, 176, 184, 76, 90, 67, 35, 62, 46, 170, 220, 149, 166, 227, 81, 136, 61, 5,
	222, 119, 186, 72, 224, 175, 149, 12, 17, 139, 27, 228, 127, 29, 68, 193, 107, 72, 220, 244,
	228, 175, 60, 141, 178, 243, 97, 188, 178, 138, 7, 157, 68, 66, 168, 65, 223, 85, 231, 131, 47,
	243, 196, 178, 191, 154, 2, 74, 49, 155, 60, 51, 69, 214, 208, 200, 200, 31, 60, 10, 94, 114,
	64, 157, 136, 254, 220, 170, 174, 131, 161, 52, 147, 115, 106, 28, 148, 18, 154, 242, 48, 17,
	155, 239, 159, 183, 192, 95, 149, 88, 143, 100, 171, 117, 250, 20, 70, 216, 249, 17, 229, 154,
	177, 26, 206, 55, 88, 90, 33, 172, 230, 159, 84, 218, 254, 24, 240, 175, 154, 68, 183, 2, 137,
	16, 226, 9, 193, 7, 74, 229, 233, 11, 201, 82, 20, 28, 155, 99, 179, 127, 163, 16, 239, 163,
	237, 176, 1, 149, 66, 85, 242, 28, 74, 132, 15, 110, 26, 45, 186, 186, 156, 169, 167, 182, 213,
	67, 154, 155, 20, 222, 205, 206, 91, 21,
];

pub(crate) const RECLAIM_INPUT_0: &[u8] = &[
	1, 0, 0, 0, 0, 4, 16, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 161, 35, 209, 88,
	179, 58, 151, 235, 180, 188, 175, 69, 71, 135, 188, 40, 108, 232, 45, 92, 221, 161, 252, 168,
	36, 109, 181, 66, 80, 171, 187, 35, 190, 237, 67, 79, 80, 228, 122, 121, 249, 90, 252, 78, 37,
	117, 13, 142, 178, 139, 185, 16, 141, 211, 241, 149, 11, 197, 48, 174, 137, 120, 22, 2, 99, 69,
	62, 235, 160, 93, 41, 57, 84, 151, 217, 69, 176, 208, 88, 117, 190, 95, 142, 16, 96, 7, 126,
	25, 231, 222, 189, 240, 32, 139, 188, 156, 182, 166, 211, 93, 0, 20, 199, 204, 129, 27, 228,
	161, 196, 103, 183, 106, 101, 160, 217, 47, 58, 114, 222, 61, 140, 59, 34, 27, 23, 109, 192,
	61, 168, 187, 155, 235, 79, 16, 15, 66, 20, 96, 0, 94, 236, 87, 134, 100, 40, 23, 175, 97, 24,
	253, 192, 153, 214, 85, 147, 22, 231, 204, 155, 2, 54, 103, 28, 244, 243, 151, 111, 41, 10,
	165, 205, 157, 23, 61, 149, 52, 45, 16, 147, 79, 114, 29, 47, 164, 98, 24, 198, 173, 68, 85,
	15, 210, 169, 182, 74, 91, 12, 60, 170, 5, 126, 193, 203, 60, 130, 213, 150, 100, 114, 149,
	174, 233, 222, 86, 210, 216, 197, 34, 96, 143, 79, 191, 88, 226, 87, 19, 52, 117, 164, 175, 49,
	199, 195, 158, 0, 54, 99, 145, 89, 83, 108, 255, 212, 135, 137, 220, 245, 117, 84, 134, 153,
	26, 98, 46, 211, 188, 12, 191, 115, 69, 233, 203, 56, 122, 63, 10, 253, 240, 74, 32, 152, 241,
	71, 248, 162, 69, 99, 173, 162, 92, 210, 117, 167, 70, 178, 22, 77, 212, 71, 225, 92, 158, 130,
];

pub(crate) const RECLAIM_INPUT_1: &[u8] = &[
	1, 0, 0, 0, 0, 4, 32, 78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 68, 31, 247, 87, 136,
	209, 103, 124, 193, 86, 226, 63, 65, 223, 214, 139, 253, 145, 239, 152, 238, 13, 15, 176, 48,
	83, 115, 85, 141, 164, 20, 23, 220, 160, 212, 217, 40, 134, 187, 186, 114, 101, 172, 213, 251,
	75, 129, 239, 150, 228, 216, 62, 76, 8, 190, 229, 244, 175, 28, 33, 58, 170, 98, 153, 128, 206,
	35, 205, 29, 24, 44, 14, 94, 177, 242, 28, 117, 31, 207, 241, 202, 3, 187, 234, 48, 95, 69,
	107, 34, 194, 132, 43, 97, 240, 42, 90, 147, 187, 71, 31, 0, 76, 238, 105, 183, 234, 221, 51,
	250, 198, 26, 155, 243, 103, 5, 128, 42, 59, 9, 207, 177, 188, 166, 187, 183, 6, 211, 178, 59,
	214, 53, 191, 31, 142, 144, 40, 208, 80, 246, 53, 185, 187, 144, 196, 12, 119, 231, 70, 25,
	112, 192, 48, 217, 12, 77, 231, 128, 92, 170, 85, 235, 203, 197, 10, 144, 214, 234, 26, 103, 8,
	177, 169, 190, 179, 188, 148, 60, 230, 182, 253, 164, 168, 228, 228, 186, 122, 226, 9, 120,
	247, 12, 201, 227, 21, 150, 207, 25, 36, 69, 54, 246, 203, 22, 25, 220, 65, 121, 18, 194, 225,
	6, 42, 194, 127, 254, 67, 19, 91, 10, 79, 111, 88, 220, 148, 243, 2, 102, 59, 87, 36, 226, 168,
	208, 7, 69, 143, 76, 131, 119, 90, 10, 181, 237, 150, 8, 109, 108, 155, 248, 82, 187, 27, 158,
	215, 36, 107, 70, 95, 122, 130, 104, 43, 28, 64, 172, 148, 154, 219, 245, 9, 47, 53, 155, 48,
	30, 251, 151, 202, 117, 81, 7, 91, 140, 202, 129, 152, 179, 131, 50, 204, 159, 97, 135,
];

pub(crate) const RECLAIM: &[u8] = &[
	1, 0, 0, 0, 0, 0, 8, 130, 20, 75, 175, 207, 152, 240, 165, 209, 177, 173, 121, 75, 185, 156,
	230, 238, 35, 13, 29, 34, 78, 75, 217, 199, 134, 81, 19, 201, 169, 255, 22, 37, 224, 167, 254,
	165, 185, 207, 238, 110, 151, 241, 155, 174, 40, 31, 242, 135, 222, 199, 11, 40, 219, 36, 108,
	31, 160, 225, 220, 52, 72, 85, 97, 224, 217, 244, 178, 62, 164, 77, 141, 137, 214, 167, 224,
	181, 86, 54, 242, 202, 80, 184, 255, 197, 102, 26, 184, 121, 46, 181, 58, 36, 51, 107, 44, 98,
	191, 211, 4, 193, 193, 184, 176, 139, 132, 56, 118, 187, 63, 19, 201, 107, 70, 157, 210, 74,
	21, 184, 254, 184, 252, 152, 67, 21, 146, 1, 37, 4, 251, 11, 69, 231, 167, 188, 157, 251, 209,
	138, 196, 196, 11, 239, 240, 140, 64, 237, 247, 21, 162, 35, 99, 149, 7, 72, 141, 152, 75, 43,
	184, 114, 63, 21, 213, 75, 203, 243, 247, 54, 247, 208, 100, 44, 46, 187, 254, 35, 249, 57,
	112, 218, 234, 176, 198, 21, 152, 64, 68, 21, 16, 170, 4, 181, 70, 126, 82, 213, 165, 227, 129,
	184, 95, 123, 136, 240, 18, 109, 255, 197, 27, 236, 25, 24, 139, 222, 37, 10, 147, 5, 168, 227,
	127, 162, 28, 87, 110, 2, 232, 227, 4, 16, 39, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 86,
	168, 73, 236, 236, 28, 184, 19, 57, 104, 154, 10, 132, 45, 255, 114, 231, 229, 77, 188, 193, 9,
	105, 20, 120, 49, 224, 26, 45, 146, 230, 111, 122, 39, 42, 254, 221, 188, 127, 57, 155, 153,
	189, 21, 212, 55, 187, 141, 94, 49, 182, 177, 214, 94, 255, 198, 210, 225, 94, 254, 16, 50,
	104, 97, 1, 212, 153, 172, 62, 165, 112, 104, 128, 74, 142, 219, 185, 239, 213, 87, 76, 27,
	125, 143, 156, 82, 188, 238, 208, 165, 90, 48, 155, 32, 220, 23, 197, 65, 70, 199, 240, 166,
	225, 107, 68, 45, 110, 142, 82, 197, 9, 7, 203, 215, 53, 77, 161, 89, 146, 123, 205, 106, 83,
	36, 156, 50, 102, 16, 1, 88, 237, 85, 4, 112, 144, 118, 24, 59, 72, 210, 73, 50, 2, 149, 128,
	165, 11, 248, 155, 178, 215, 30, 236, 58, 156, 186, 254, 85, 23, 74, 46, 83, 228, 222, 229,
	197, 32, 181, 156, 138, 224, 226, 136, 189, 149, 22, 152, 66, 101, 84, 4, 13, 133, 224, 23,
	106, 168, 154, 39, 87, 184, 145,
];
