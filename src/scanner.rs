use virus_database::VirusDatabase;

use signature;

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
        let mut scan_file = match OpenOptions::new().read(true).open(&filename) {
            Ok(f) => f,
            Err(_e) => {
                return Err("Failed to open file");
            },
        };

        let mut buf: Vec<u8> = vec![];
        if let Err(_e) = &scan_file.read_to_end(&mut buf) {
            return Err("Could not read data from file");
        }
        let file_size = buf.len();

        let mut malicious = false;

        let mut max_filename_size = 50;
        let mut slice_start = 0;
        if filename.len() > max_filename_size {
            slice_start = filename.len() - max_filename_size;
        }
        print!("{0: >50} -> ", filename[slice_start..filename.len()].blue());
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

                        if scan_buf.iter().zip(start.iter()).filter(|(x, y)| x == y).count() == start.len() {
                            continue;
                        }

                        let scanned_sig = signature::generate_signature_from_bytes(scan_buf);
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
            print!(" {}\n", "CLEAR".green().bold());
        } else {
            print!(" {}\n", "MALICIOUS".red().bold());
        }

        Ok(malicious)
    }
}