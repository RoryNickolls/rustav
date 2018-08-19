use virus_database::VirusDatabase;

use signature;
use signature::Signature;

use std::fs;
use std::fs::OpenOptions;

use std::io;
use std::io::Write;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use walkdir::WalkDir;

use colored::*;

pub struct Scanner {
    pub db: VirusDatabase,
}

impl Scanner {
    pub fn new(db: VirusDatabase) -> Scanner {
        Scanner { db } 
    }

    pub fn scan_system(&self, root: &str) {
        let mut malicious_files: Vec<String> = vec![];
        for entry in WalkDir::new(root) {
            if let Ok(entry) = entry {
                if entry.file_type().is_file() {
                    let path = entry.path().to_str().unwrap().clone().to_string();
                    match Scanner::scan_file(self, &path) {
                        Ok(malicious) => {
                            if malicious {
                                malicious_files.push(path);
                            }
                            continue
                        },
                        Err(e) => eprintln!("Could not open file {:?}:{:?}", entry, e),
                    };
                }
            }
        }

        println!("\n{} malicious files found.", malicious_files.len());

        if malicious_files.len() > 0 {
            for file in &malicious_files {
                println!("{}", file.red());
            }
            println!("Would you like to delete these files? y/n");
            let mut input = String::new();
            io::stdin().read_line(&mut input).expect("Could not read console input");
            input.pop();
            if input.to_lowercase() == "y" {
                for file in &malicious_files {
                    fs::remove_file(file).expect("Could not remove file!");
                }
                println!("{} files removed.", malicious_files.len());
            }
        }
        
    }

    pub fn scan_file(&self, filename: &str) -> Result<bool, &'static str> {

        // Open file with read permissions
        let mut scan_file = match OpenOptions::new().read(true).open(&filename) {
            Ok(f) => f,
            Err(_e) => {
                return Err("Failed to open file");
            },
        };

        // Read file into a buffer
        let mut buf: Vec<u8> = vec![];
        if let Err(_e) = &scan_file.read_to_end(&mut buf) {
            return Err("Could not read data from file");
        }
        let file_size = buf.len();

        let mut malicious_sigs: Vec<&Signature> = vec![];
        // Truncate filename to fit on screen
        let max_filename_size = 50;
        let mut slice_start = 0;
        let mut printed_filename = String::from("");
        if filename.len() > max_filename_size {
            slice_start = filename.len() - max_filename_size;
            printed_filename.push_str(&String::from("..."));
        }
        printed_filename.push_str(&filename[slice_start..filename.len()]);
        print!("{0: >50} -> ", printed_filename.blue());

        // Start looping through signatures and checking file
        ::std::io::stdout().flush().expect("Could not flush stdout");
        for signature in &self.db.signatures {
            let len = signature.len;
            let hash = &signature.hash;
            let start = &signature.start;
            if file_size > (len - 1) {
                let last_byte = file_size - len + 1;
                for i in (0..last_byte).step_by(start.len()) {
                    if let Ok(_) = scan_file.seek(SeekFrom::Start(i as u64)) {
                        let mut scan_buf: Vec<u8> = vec![0; len];
                        if let Err(_e) = &scan_file.read(&mut scan_buf) {
                            panic!("Could not read bytes from file: {}");
                        }

                        // Use iterators to skip if start doesn't match
                        let should_skip = !start_bytes_equal(&signature, &scan_buf);             
                        if should_skip {
                            continue;
                        }

                        let scanned_sig = signature::generate_signature_from_bytes(scan_buf);
                        if &scanned_sig.hash == hash {
                            malicious_sigs.push(&signature);
                        }                       
                    } else {
                        panic!("Could not read bytes from file!");
                    }
                }
            }
        }

        let malicious = malicious_sigs.len() != 0;

        if !malicious {
            print!(" {}\n", "CLEAR".green().bold());
        } else {
            let mut descriptions = String::new();
            for sig in malicious_sigs {
                descriptions.push_str(&sig.description);
                descriptions.push(',');
            }
            descriptions.pop();
            print!(" {} ({})\n", "MALICIOUS".red().bold(), descriptions.red());
        }

        Ok(malicious)
    }
}


    
fn start_bytes_equal(sig: &Signature, bytes: &Vec<u8>) -> bool {
    let mut counter = 0;
    let mut result = true;
    for i in &sig.start {
        result = result && i == &bytes[counter];
        counter += 1;
    }

    //println!("{:?} {:?}", &sig.start, &bytes[0..sig.start.len()]);
    result
}