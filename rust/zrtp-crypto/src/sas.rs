/*
 * Copyright 2006 - 2018, Werner Dittmann
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

//! SAS (Short Authentication String) rendering.

/// Renders the first 20 bits of the SAS hash as a 4-character Base32 string.
/// 
/// Defined in RFC 6189 Section 5.1.
pub fn render_sas_base32(sas_hash: &[u8]) -> String {
    if sas_hash.len() < 4 {
        return String::new();
    }
    
    // Take the first 20 bits
    let b1 = sas_hash[0];
    let b2 = sas_hash[1];
    let b3 = sas_hash[2];
    
    let val = ((b1 as u32) << 12) | ((b2 as u32) << 4) | ((b3 as u32) >> 4);
    
    let base32_chars = b"ybndrfg8ejkmcpqxot1uwisza345h769";
    
    let mut result = String::with_capacity(4);
    result.push(base32_chars[((val >> 15) & 0x1F) as usize] as char);
    result.push(base32_chars[((val >> 10) & 0x1F) as usize] as char);
    result.push(base32_chars[((val >> 5) & 0x1F) as usize] as char);
    result.push(base32_chars[(val & 0x1F) as usize] as char);
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sas_rendering() {
        // Just a smoke test
        let hash = [0xFF; 32];
        let sas = render_sas_base32(&hash);
        assert_eq!(sas.len(), 4);
    }
}
