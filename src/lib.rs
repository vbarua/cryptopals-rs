use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io;

fn hex_to_byte(h: char) -> u8 {
    match h {
        '0' => 0b0000u8,
        '1' => 0b0001u8,
        '2' => 0b0010u8,
        '3' => 0b0011u8,
        '4' => 0b0100u8,
        '5' => 0b0101u8,
        '6' => 0b0110u8,
        '7' => 0b0111u8,
        '8' => 0b1000u8,
        '9' => 0b1001u8,
        'a' => 0b1010u8,
        'A' => 0b1010u8,
        'b' => 0b1011u8,
        'B' => 0b1011u8,
        'c' => 0b1100u8,
        'C' => 0b1100u8,
        'd' => 0b1101u8,
        'D' => 0b1101u8,
        'e' => 0b1110u8,
        'E' => 0b1110u8,
        'f' => 0b1111u8,
        'F' => 0b1111u8,
        _ => panic!("Invalid Hex Digit"),
    }
}

fn byte_to_hex(b: u8) -> char {
    match b {
        0b0000u8 => '0',
        0b0001u8 => '1',
        0b0010u8 => '2',
        0b0011u8 => '3',
        0b0100u8 => '4',
        0b0101u8 => '5',
        0b0110u8 => '6',
        0b0111u8 => '7',
        0b1000u8 => '8',
        0b1001u8 => '9',
        0b1010u8 => 'a',
        0b1011u8 => 'b',
        0b1100u8 => 'c',
        0b1101u8 => 'd',
        0b1110u8 => 'e',
        0b1111u8 => 'f',
        _ => panic!("Invalid Hex Digit"),
    }
}

fn byte_to_base64(byte: u8) -> char {
    // https://datatracker.ietf.org/doc/html/rfc4648#section-4
    match byte {
        0 => 'A',
        1 => 'B',
        2 => 'C',
        3 => 'D',
        4 => 'E',
        5 => 'F',
        6 => 'G',
        7 => 'H',
        8 => 'I',
        9 => 'J',
        10 => 'K',
        11 => 'L',
        12 => 'M',
        13 => 'N',
        14 => 'O',
        15 => 'P',
        16 => 'Q',
        17 => 'R',
        18 => 'S',
        19 => 'T',
        20 => 'U',
        21 => 'V',
        22 => 'W',
        23 => 'X',
        24 => 'Y',
        25 => 'Z',
        26 => 'a',
        27 => 'b',
        28 => 'c',
        29 => 'd',
        30 => 'e',
        31 => 'f',
        32 => 'g',
        33 => 'h',
        34 => 'i',
        35 => 'k',
        36 => 'k',
        37 => 'l',
        38 => 'm',
        39 => 'n',
        40 => 'o',
        41 => 'p',
        42 => 'q',
        43 => 'r',
        44 => 's',
        45 => 't',
        46 => 'u',
        47 => 'v',
        48 => 'w',
        49 => 'x',
        50 => 'y',
        51 => 'z',
        52 => '0',
        53 => '1',
        54 => '2',
        55 => '3',
        56 => '4',
        57 => '5',
        58 => '6',
        59 => '7',
        60 => '8',
        61 => '9',
        62 => '+',
        63 => '/',
        _ => panic!("Invalid Base64 Pattern"),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    // let mut iter = bytes.iter();
    let mut s = String::new();
    for byte in bytes {
        s.push(byte_to_hex(byte >> 4));
        s.push(byte_to_hex(byte & 0b00001111u8));
    }
    s
}

fn hex_to_bytes(input: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut iter = input.chars();
    while let Some(left) = iter.next() {
        match iter.next() {
            Some(right) => bytes.push((hex_to_byte(left) << 4) | hex_to_byte(right)),
            None => bytes.push(hex_to_byte(left) << 4),
        }
    }
    bytes
}

fn bytes_to_base64(bytes: &[u8]) -> String {
    let mut iter = bytes.iter();
    let mut s = String::new();
    while let Some(first) = iter.next() {
        // https://datatracker.ietf.org/doc/html/rfc4648#section-4
        match (iter.next(), iter.next()) {
            // Example
            // Octets:  00000011
            // Sextets: 000000 110000
            (None, None) => {
                s.push(byte_to_base64(first >> 2));
                s.push(byte_to_base64((first & 0b00000011u8) << 4));
                s.push('=');
                s.push('=');
            }
            // Example
            // Octets:  00000011 11011001
            // Sextets: 000000 111101 100100
            (Some(second), None) => {
                s.push(byte_to_base64(first >> 2));
                s.push(byte_to_base64(
                    ((first & 0b00000011u8) << 4) | (second >> 4),
                ));
                s.push(byte_to_base64((second & 0b00001111u8) << 2));
                s.push('=');
            }
            // Octets:  00000011 11011001 01111110
            // Sextets: 000000 111101 100101 111110
            (Some(second), Some(third)) => {
                s.push(byte_to_base64(first >> 2));
                s.push(byte_to_base64(
                    ((first & 0b00000011u8) << 4) | (second >> 4),
                ));
                s.push(byte_to_base64(
                    ((second & 0b00001111u8) << 2) | (third >> 6),
                ));
                s.push(byte_to_base64(third & 0b00111111u8))
            }
            _ => panic!(
                "Unreachable: If the first call to iter.next() returns None, so will the second"
            ),
        }
    }
    s
}

pub fn hex_to_base64(input: &str) -> String {
    bytes_to_base64(&hex_to_bytes(input))
}

pub fn fixed_xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    assert!(left.len() == right.len());
    let mut bytes: Vec<u8> = Vec::new();
    for (l, r) in left.iter().zip(right) {
        bytes.push(l ^ r);
    }
    bytes
}

pub fn xor_with_pattern(input: &[u8], pattern: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for (l, r) in input.iter().zip(pattern.iter().cycle()) {
        bytes.push(l ^ r);
    }
    bytes
}

fn load_dictionary() -> io::Result<Vec<String>> {
    let file = fs::File::open("/usr/share/dict/words")?;
    let reader = io::BufReader::new(file);

    let mut words: Vec<String> = Vec::new();
    for line in io::BufRead::lines(reader) {
        words.push(line?);
    }
    io::Result::Ok(words)
}

fn compute_letter_frequency(words: &[String]) -> HashMap<char, usize> {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for word in words {
        for c in word.to_lowercase().chars() {
            match counts.get_mut(&c) {
                None => {
                    counts.insert(c, 1);
                }
                Some(count) => *count += 1,
            }
        }
    }
    counts
}

pub struct TextScorer {
    character_distributions: HashMap<char, f64>,
    ignore_list: HashSet<char>,
}

impl TextScorer {
    pub fn new() -> TextScorer {
        let words = load_dictionary().unwrap();
        let character_frequencies: HashMap<char, usize> = compute_letter_frequency(&words);
        let total_characters: usize = character_frequencies.values().sum();
        let character_distributions: HashMap<char, f64> = character_frequencies
            .into_iter()
            .map(|(c, f)| (c, (f as f64) / (total_characters as f64)))
            .collect();
        let ignore_list: HashSet<char> = [' ', ',', '.', '?', '\'', '"', '\n']
            .iter()
            .cloned()
            .collect();

        TextScorer {
            character_distributions,
            ignore_list,
        }
    }

    pub fn score(&self, input: &str) -> f64 {
        let total_characters = input.len() as f64;
        let input_character_frequencies = compute_letter_frequency(&[input.to_string()]);
        let mut input_character_distributions: HashMap<char, f64> = input_character_frequencies
            .into_iter()
            .map(|(k, f)| (k, (f as f64) / total_characters))
            .collect();
        for c in 'a'..='z' {
            // If the character is not present on the input, it's distribution is 0.
            input_character_distributions.entry(c).or_insert(0.0);
        }
        let mut score: f64 = 0.0;
        for (c, input_frequency) in input_character_distributions
            .iter()
            .filter(|&(c, _)| !self.ignore_list.contains(c))
        {
            match self.character_distributions.get(c) {
                Some(expected_frequency) => score += (expected_frequency - input_frequency).powi(2),
                None => score += 1.0, // Penalize non-standard characters
            }
        }
        score
    }

    pub fn break_single_byte_xor(&self, bytes: &[u8]) -> Option<(f64, String)> {
        let mut guesses: Vec<(f64, String)> = Vec::new();
        for b in 0b00000000u8..=0b11111111u8 {
            let decoded = xor_with_pattern(bytes, &[b]);
            if let Ok(text) = String::from_utf8(decoded) {
                guesses.push((self.score(&text), text));
            }
        }
        guesses.sort_by(|a, b| a.0.partial_cmp(&(b.0)).unwrap());
        guesses.get(0).map(|(score, text)| (*score, text.clone()))
    }

    pub fn detect_single_byte_xor(&self, inputs: &[Vec<u8>]) -> Option<(f64, String)> {
        let mut guesses: Vec<(f64, usize, String)> = Vec::new();
        for (line, input) in inputs.iter().enumerate() {
            if let Some(g) = self.break_single_byte_xor(input) {
                guesses.push((g.0, line, g.1));
            }
        }
        guesses.sort_by(|a, b| a.0.partial_cmp(&(b.0)).unwrap());
        guesses.get(0).map(|g| (g.0, g.2.clone()))
    }
}

impl Default for TextScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_byte_test() {
        assert_eq!(hex_to_byte('0'), 0b0000u8);
        assert_eq!(hex_to_byte('F'), 0b1111u8);
    }

    #[test]
    #[should_panic]
    fn invalid_hex_to_byte_test() {
        hex_to_byte('G');
    }

    #[test]
    fn hex_to_bytes_test() {
        assert_eq!(hex_to_bytes("F"), vec![0b11110000u8]);
        assert_eq!(hex_to_bytes("FF"), vec![0b11111111u8]);
        assert_eq!(hex_to_bytes("FFF"), vec![0b11111111u8, 0b11110000u8]);
    }

    #[test]
    fn byte_to_base64_test() {
        assert_eq!(byte_to_base64(0), 'A');
        assert_eq!(byte_to_base64(26), 'a');
        assert_eq!(byte_to_base64(52), '0');
        assert_eq!(byte_to_base64(61), '9');
        assert_eq!(byte_to_base64(62), '+');
        assert_eq!(byte_to_base64(63), '/');
    }

    #[test]
    #[should_panic]
    fn invalid_byte_to_base64_test() {
        byte_to_base64(64);
    }

    #[test]
    fn bytes_to_base64_test() {
        assert_eq!(
            bytes_to_base64(&[0b00010100u8, 0b11111011u8, 0b10011100u8]),
            "FPuc"
        );
        assert_eq!(bytes_to_base64(&[0b00000011u8, 0b11011001u8]), "A9k=");
        assert_eq!(bytes_to_base64(&[0b00000011u8]), "Aw==");
    }

    #[test]
    fn hex_to_base64_test() {
        // https://cryptopals.com/sets/1/challenges/1
        assert_eq!(
            hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn fixed_xor_test() {
        // https://cryptopals.com/sets/1/challenges/2
        assert_eq!(
            bytes_to_hex(&fixed_xor(
                &hex_to_bytes("1c0111001f010100061a024b53535009181c"),
                &hex_to_bytes("686974207468652062756c6c277320657965")
            )),
            "746865206b696420646f6e277420706c6179"
        );
    }

    #[test]
    fn load_dictionary_test() {
        let words = load_dictionary().unwrap();
        assert!(!words.is_empty());
    }

    #[test]
    fn compute_letter_frequency_test() {
        let words = vec![
            "a".to_string(),
            "bb".to_string(),
            "ccc".to_string(),
            "dddd".to_string(),
            "zzzzz".to_string(),
            "++++++".to_string(),
        ];
        let counts = compute_letter_frequency(&words);
        assert_eq!(counts[&'a'], 1);
        assert_eq!(counts[&'b'], 2);
        assert_eq!(counts[&'c'], 3);
        assert_eq!(counts[&'d'], 4);
        assert_eq!(counts[&'z'], 5);
        assert_eq!(counts[&'+'], 6);
    }

    #[test]
    fn break_single_byte_xor_test() {
        // https://cryptopals.com/sets/1/challenges/3
        let scorer = TextScorer::default();
        assert_eq!(
            scorer
                .break_single_byte_xor(&hex_to_bytes(
                    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
                ))
                .unwrap()
                .1,
            "Cooking MC's like a pound of bacon"
        );

        assert_eq!(
            scorer
                .break_single_byte_xor(&hex_to_bytes(
                    "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
                ))
                .unwrap()
                .1,
            "Now that the party is jumping\n"
        );
    }

    #[test]
    fn detect_single_byte_xor_test() {
        // https://cryptopals.com/sets/1/challenges/4
        let scorer = TextScorer::default();

        let file = fs::File::open("src/resources/set1challenge4.txt").unwrap();
        let reader = io::BufReader::new(file);
        let inputs: Vec<Vec<u8>> = io::BufRead::lines(reader)
            .map(|l| hex_to_bytes(&l.unwrap()))
            .collect();
        assert_eq!(
            scorer.detect_single_byte_xor(&inputs).unwrap().1,
            "Now that the party is jumping\n"
        );
    }

    #[test]
    fn repeated_xor() {
        // https://cryptopals.com/sets/1/challenges/5
        let input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let encrypted = xor_with_pattern(input, b"ICE");
        let output = bytes_to_hex(&encrypted);
        assert_eq!(
            output,
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        );
    }
}
