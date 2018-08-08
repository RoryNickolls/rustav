extern crate md5;
extern crate walkdir;
extern crate colored;

use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::fs::OpenOptions;
use std::io::SeekFrom;
use std::io::Seek;

use walkdir::WalkDir;

use colored::*;

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
    let hash = format!("{:x}", md5::compute(bytes));
    Signature { hash, len }
}

pub struct Signature {
    pub hash: String,
    pub len: usize,
}

impl Signature {
    pub fn new(hash: String, len: usize) -> Signature {
        Signature { hash, len }
    }

    pub fn to_string(&self) -> String {
        let mut format = String::new();
        format.push_str(&self.hash);
        format.push(':');
        format.push_str(&self.len.to_string());
        format
    }
}

pub struct VirusDatabase {
    pub file: File,
    pub signatures: Vec<Signature>,
}

impl VirusDatabase {
    pub fn new(filename: &str) -> VirusDatabase {

        let mut file = match VirusDatabase::open_file(&filename) {
            Ok(f) => f,   
            Err(e) => panic!("{}", e),
        };

        let mut signatures: Vec<Signature> = vec![];
        
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("could not read file");

        for line in contents.lines() {
            let line_contents = line.to_string();
            let fields: Vec<&str> = line_contents.split(':').collect();
            let sig = Signature::new(fields[0].to_string(), fields[1].parse().unwrap());
            signatures.push(sig);
        }

        VirusDatabase { file, signatures }
    }

    pub fn add_signature(&mut self, signature: Signature) -> Result<(), &'static str> {

        // Create a String to hold the data we write to file 
        let mut sig_str = signature.to_string();
        sig_str.push('\n');

        // Convert data into bytes
        let write_data: Vec<u8> = sig_str.into_bytes();

        // Attempt to write data to file
        if let Err(e) = &self.file.write_all(write_data.as_slice()) {
            panic!("Error writing signature: {:?} to {:?}", e, &self.file);
        }

        // Add data to signatures vec so the file does not need to be re-read
        self.signatures.push(signature);

        Ok(())
    }

    fn open_file(filename: &str) -> Result<File, &'static str> {
        // Open specified file with read and append privileges, and create if does not exist
        let db_file = match OpenOptions::new().read(true).append(true).create(true).open(&filename) {
            Ok(file) => Ok(file),
            Err(e) => Err("Could not open specified file"),
        };
        db_file
    }
}

pub struct Scanner {
    pub db: VirusDatabase,
}

impl Scanner {

    pub fn new(db: VirusDatabase) -> Scanner {
        Scanner { db } 
    }

    pub fn scan_system(&self, root: &str) {
        for entry in WalkDir::new(root) {
            if let Ok(entry) = entry {
                if entry.file_type().is_file() {
                    Scanner::scan_file(self, entry.path().to_str().unwrap());
                }
            }
        }
    }

    pub fn scan_file(&self, filename: &str) -> Result<bool, &'static str> {
        let mut scan_file = match OpenOptions::new().read(true).open(&filename) {
            Ok(f) => f,
            Err(e) => return Err("Could not open file for scanning: {:?}"),
        };

        let mut buf: Vec<u8> = vec![];
        if let Err(e) = &scan_file.read_to_end(&mut buf) {
            panic!("Could not read data from file: {}", e);
        }
        let file_size = buf.len();

        let mut malicious = false;

        print!("Scanning {} with {} signatures", filename, &self.db.signatures.len());
        ::std::io::stdout().flush();
        for signature in &self.db.signatures {
            let len = signature.len;
            let hash = &signature.hash;
            if file_size > (len - 1) {
                let last_byte = file_size - len + 1;
                for i in 0..last_byte {
                    if let Ok(offset) = scan_file.seek(SeekFrom::Start(i as u64)) {
                        let mut scan_buf = vec![0; len];
                        if let Err(e) = &scan_file.read(&mut scan_buf) {
                            panic!("Could not read bytes from file: {}");
                        }
                        let scanned_sig = generate_signature_from_bytes(scan_buf);
                        if &scanned_sig.hash == hash {
                            malicious = true;
                            break;
                        }                       
                    } else {
                        panic!("Could not read bytes from file!");
                    }
                }
            }
        }

        if !malicious {
            print!(" --> {}\n", "CLEAR".green());
        } else {
            print!(" --> {}\n", "MALICIOUS".red());
        }

        Ok(malicious)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn read_database() {
        let db = VirusDatabase::new("db");
    }

    #[test]
    pub fn generate_sig() {
        let sig = generate_signature("MaliciousCode.txt");
        println!("hash:{} len:{}", sig.hash, sig.len);
    }

    #[test]
    pub fn add_sig() {
        let mut db = VirusDatabase::new("db");
        let sig = generate_signature("MaliciousCode.txt");
        db.add_signature(sig);
    }

    #[test]
    pub fn scan_file() {
        let mut db = VirusDatabase::new("db");
        let scanner = Scanner::new(db);
        scanner.scan_file("MaliciousFile.exe");
    }
}
