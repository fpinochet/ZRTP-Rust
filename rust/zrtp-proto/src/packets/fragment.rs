/*
 * Copyright 2026 - Francisco F. Pinochet
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use nom::{
    number::complete::{be_u8, be_u16},
    IResult,
};

/// Header for a fragmented ZRTP message (RFC 6189 Section 5.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentHeader {
    /// Total number of fragments.
    pub frag_count: u8,
    /// Sequence number of this fragment (0-indexed).
    pub frag_seq: u8,
}

impl FragmentHeader {
    /// Size of the fragment header in bytes (Marker 0xFFFF + count + seq).
    pub const SIZE: usize = 4;

    /// Parses the fragment header from the given input.
    pub fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, marker) = be_u16(input)?;
        if marker != 0xFFFF {
            return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Tag)));
        }
        let (input, frag_count) = be_u8(input)?;
        let (input, frag_seq) = be_u8(input)?;
        Ok((input, Self { frag_count, frag_seq }))
    }

    /// Serializes the fragment header into bytes.
    pub fn to_bytes(&self) -> [u8; 4] {
        [0xFF, 0xFF, self.frag_count, self.frag_seq]
    }
}

/// Helper for splitting a large payload into ZRTP fragments.
pub fn fragment_payload(payload: &[u8], max_size: usize) -> Vec<Vec<u8>> {
    if payload.len() <= max_size {
        return vec![payload.to_vec()];
    }

    let frag_count = payload.len().div_ceil(max_size);
    let mut fragments = Vec::with_capacity(frag_count);

    for i in 0..frag_count {
        let start = i * max_size;
        let end = std::cmp::min(start + max_size, payload.len());
        
        let mut fragment = Vec::with_capacity(FragmentHeader::SIZE + (end - start));
        let header = FragmentHeader {
            frag_count: frag_count as u8,
            frag_seq: i as u8,
        };
        fragment.extend_from_slice(&header.to_bytes());
        fragment.extend_from_slice(&payload[start..end]);
        fragments.push(fragment);
    }

    fragments
}
