use std::fs::File;
use std::fs::OpenOptions;

use std::io::Read;
use std::io::Write;

use signature::Signature;

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
            let mut line_contents = line.to_string();
            let fields: Vec<&str> = line_contents.split(':').collect();
            let start_bytes: Vec<u8> = fields[2].split(',').map(|x| x.parse().unwrap()).collect();
            let mut sig = Signature::new(fields[0].to_string(), fields[1].parse().unwrap(), start_bytes);
            sig.set_description(fields[3].to_string());
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
            Err(_e) => Err("Could not open specified file"),
        };
        db_file
    }
}