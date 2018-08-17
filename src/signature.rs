use md5;

use std::fs::File;

use std::io::Read;

pub fn generate_signature(filename: &str) -> Signature {
    let mut file = match File::open(filename) {
        Ok(file) => file,
        Err(e) => panic!("Could not open file {}: {}", filename, e),
    };
    let mut buf = vec![];
    match file.read_to_end(&mut buf) {
        Ok(num) => num,
        Err(e) => panic!("Failed reading file {}: {}", filename, e),
    };
    generate_signature_from_bytes(buf)
}

pub fn generate_signature_from_bytes(bytes: Vec<u8>) -> Signature {
    let len = bytes.len();
    let start = bytes[0..4].to_vec();
    let hash = format!("{:x}", md5::compute(bytes));
    Signature { hash, len, start }
}

pub struct Signature {
    pub hash: String,
    pub len: usize,
    pub start: Vec<u8>,
}

impl Signature {
    pub fn new(hash: String, len: usize, start: Vec<u8>) -> Signature {
        Signature { hash, len, start }
    }

    pub fn to_string(&self) -> String {
        let mut format = String::new();
        format.push_str(&self.hash);
        format.push(':');
        format.push_str(&self.len.to_string());
        format.push(':');

        let mut start_bytes_str = String::new();
        for byte in &self.start {
            start_bytes_str.push_str(&byte.to_string());
        }
        start_bytes_str.pop();
        format.push_str(&start_bytes_str);
        format
    }
}