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
    let start = bytes[0];
    let hash = format!("{:x}", md5::compute(bytes));
    Signature { hash, len, start }
}

pub struct Signature {
    pub hash: String,
    pub len: usize,
    pub start: u8,
}

impl Signature {
    pub fn new(hash: String, len: usize, start: u8) -> Signature {
        Signature { hash, len, start }
    }

    pub fn to_string(&self) -> String {
        let mut format = String::new();
        format.push_str(&self.hash);
        format.push(':');
        format.push_str(&self.len.to_string());
        format.push(':');
        format.push_str(&self.start.to_string());
        format
    }
}