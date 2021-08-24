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
}
