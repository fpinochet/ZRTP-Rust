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
    if sas_hash.len() < 3 {
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

/// The PGP "Even" word list (for even-index bytes).
const PGP_WORDS_EVEN: &[&str] = &[
    "aardvark", "absurd", "accrue", "acme", "adrift", "adult", "afflict", "ahead", "aimless", "Algol",
    "allow", "alone", "ammo", "ancient", "apple", "artist", "assume", "Athens", "atlas", "Aztec",
    "baboon", "backfield", "backward", "basalt", "beaming", "bedlamp", "beehive", "beeswax", "befriend", "Belfast",
    "berserk", "billiard", "bison", "blackjack", "blockade", "blowtorch", "bluebird", "bombast", "bookshelf", "brackish",
    "breadline", "breakup", "brickyard", "briefcase", "Burbank", "button", "buzzard", "cement", "chairlift", "chatter",
    "checkup", "chisel", "choking", "chopper", "Christmas", "clamshell", "classic", "classroom", "cleanup", "clockwork",
    "cobra", "commence", "concert", "cowbell", "crackdown", "cranky", "crowfoot", "crucial", "crumpled", "crusade",
    "cubic", "deadbolt", "deckhand", "dogsled", "dosage", "dragnet", "drainage", "dreadful", "drifter", "dropper",
    "drumbeat", "drunken", "Dupont", "dwelling", "eating", "edict", "egghead", "eightball", "endorse", "endow",
    "enlist", "erase", "escape", "exceed", "eyeglass", "eyetooth", "facial", "fallout", "flagpole", "flatfoot",
    "flytrap", "fracture", "fragile", "framework", "freedom", "frighten", "gazelle", "Geiger", "Glasgow", "glitter",
    "glucose", "goggles", "goldfish", "gremlin", "guidance", "hamlet", "highchair", "hockey", "hotdog", "indoors",
    "indulge", "inverse", "involve", "island", "Janus", "jawbone", "keyboard", "kickoff", "kiwi", "klaxon",
    "lockup", "merit", "minnow", "miser", "Mohawk", "mural", "music", "Neptune", "newborn", "nightbird",
    "obtuse", "offload", "oilfield", "optic", "orca", "payday", "peachy", "pheasant", "physique", "playhouse",
    "Pluto", "preclude", "prefer", "preshrunk", "printer", "profile", "prowler", "pupil", "puppy", "python",
    "quadrant", "quiver", "quota", "ragtime", "ratchet", "rebirth", "reform", "regain", "reindeer", "rematch",
    "repay", "retouch", "revenge", "reward", "rhythm", "ringbolt", "robust", "rocker", "ruffled", "sawdust",
    "scallion", "scenic", "scorecard", "Scotland", "seabird", "select", "sentence", "shadow", "showgirl", "skullcap",
    "skydive", "slingshot", "slothful", "slowdown", "snapline", "snapshot", "snowcap", "snowslide", "solo", "spaniel",
    "spearhead", "spellbind", "spheroid", "spigot", "spindle", "spoilage", "spyglass", "stagehand", "stagnate", "stairway",
    "standard", "stapler", "steamship", "stepchild", "sterling", "stockman", "stopwatch", "stormy", "sugar", "surmount",
    "suspense", "swelter", "tactics", "talon", "tapeworm", "tempest", "tiger", "tissue", "tonic", "tracker",
    "transit", "trauma", "treadmill", "Trojan", "trouble", "tumor", "tunnel", "tycoon", "umpire", "uncut",
    "unearth", "unwind", "uproot", "upset", "upshot", "vapor", "village", "virus", "Vulcan", "waffle",
    "wallet", "watchword", "wayside", "willow", "woodlark", "Zulu",
];

/// The PGP "Odd" word list (for odd-index bytes).
const PGP_WORDS_ODD: &[&str] = &[
    "adroitness", "adviser", "aggregate", "alkali", "almighty", "amulet", "amusement", "antenna", "applicant", "Apollo",
    "armistice", "article", "asteroid", "Atlantic", "atmosphere", "autopsy", "Babylon", "backwater", "barbecue", "belowground",
    "bifocals", "bodyguard", "borderline", "bottomless", "Bradbury", "Brazilian", "breakaway", "Burlington", "businessman", "butterfat",
    "Camelot", "candidate", "cannonball", "Capricorn", "caravan", "caretaker", "celebrate", "cellulose", "certify", "chambermaid",
    "Cherokee", "Chicago", "clergyman", "coherence", "combustion", "commando", "company", "component", "concurrent", "confidence",
    "conformist", "congregate", "consensus", "consulting", "corporate", "corrosion", "councilman", "crossover", "cumbersome", "customer",
    "Dakota", "decadence", "December", "decimal", "designing", "detector", "detergent", "determine", "dictator", "dinosaur",
    "direction", "disable", "disbelief", "disruptive", "distortion", "divisive", "document", "embezzle", "enchanting", "enrollment",
    "enterprise", "equation", "equipment", "escapade", "Eskimo", "everyday", "examine", "existence", "exodus", "fascinate",
    "filament", "finicky", "forever", "fortitude", "frequency", "gadgetry", "Galveston", "getaway", "glossary", "gossamer",
    "graduate", "gravity", "guitarist", "hamburger", "Hamilton", "handiwork", "hazardous", "headwaters", "hemisphere", "hesitate",
    "hideaway", "holiness", "hurricane", "hydraulic", "impartial", "impetus", "inception", "indigo", "inertia", "infancy",
    "inferno", "informant", "insincere", "insurgent", "integrate", "intention", "inventive", "Istanbul", "Jamaica", "Jupiter",
    "leprosy", "letterhead", "liberty", "maritime", "matchmaker", "maverick", "Medusa", "megaton", "microscope", "microwave",
    "midsummer", "millionaire", "miracle", "misnomer", "molasses", "molecule", "Montana", "monument", "mosquito", "narrative",
    "nebula", "newsletter", "Norwegian", "October", "Ohio", "onlooker", "opulent", "Orlando", "outfielder", "Pacific",
    "pandemic", "pandora", "paperweight", "paragon", "paragraph", "paramount", "passenger", "pedigree", "Pegasus", "penetrate",
    "perceptive", "performance", "pharmacy", "phonetic", "photograph", "pioneer", "pocketful", "politeness", "positive", "potato",
    "processor", "prophecy", "provincial", "proximate", "puberty", "publisher", "pyramid", "quantity", "racketeer", "rebellion",
    "recipe", "recover", "repellent", "replica", "reproduce", "resistor", "responsive", "retraction", "retrieval", "retrospect",
    "revenue", "revival", "revolver", "Sahara", "sandalwood", "sardonic", "Saturday", "savagery", "scavenger", "sensation",
    "sociable", "souvenir", "specialist", "speculate", "stethoscope", "stupendous", "supportive", "surrender", "suspicious", "sympathy",
    "tambourine", "telephone", "therapist", "tobacco", "tolerance", "tomorrow", "torpedo", "tradition", "travesty", "trombonist",
    "truncated", "typewriter", "ultimate", "undaunted", "underfoot", "unicorn", "unify", "universe", "unravel", "upcoming",
    "vacancy", "vagabond", "versatile", "vertigo", "Virginia", "visitor", "vocalist", "voyager", "warranty", "Waterloo",
    "whimsical", "Wichita", "Wilmington", "Wyoming", "yesteryear", "Yucatan",
];


/// Renders the first 16 bits of the SAS hash as two PGP words.
/// 
/// Defined in RFC 6189 Section 5.1.2.
pub fn render_sas_words(sas_hash: &[u8]) -> String {
    if sas_hash.len() < 2 {
        return String::new();
    }
    
    let word1 = PGP_WORDS_EVEN[sas_hash[0] as usize];
    let word2 = PGP_WORDS_ODD[sas_hash[1] as usize];
    
    format!("{} {}", word1, word2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sas_rendering_base32() {
        let hash = [0xFF; 32];
        let sas = render_sas_base32(&hash);
        assert_eq!(sas.len(), 4);
    }

    #[test]
    fn test_sas_rendering_words() {
        let hash = [0x00, 0x01, 0x02, 0x03];
        let sas = render_sas_words(&hash);
        assert!(!sas.is_empty());
        assert!(sas.contains(' '));
    }
}
