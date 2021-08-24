pub fn hex_to_byte(h: char) -> u8 {
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
        'A' => 0b1010u8,
        'B' => 0b1011u8,
        'C' => 0b1100u8,
        'D' => 0b1101u8,
        'E' => 0b1110u8,
        'F' => 0b1111u8,
        _ => panic!("Invalid Hex Digit"),
    }
}

pub fn hex_to_bytes(input: &str) -> Vec<u8> {
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
}
