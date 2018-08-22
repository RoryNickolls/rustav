extern crate md5;
extern crate walkdir;
extern crate colored;
extern crate boyer_moore;

mod signature;
mod scanner;
mod virus_database;

use virus_database::VirusDatabase;

use scanner::Scanner;

use std::io;
use std::io::Write;

use std::fs::metadata;

fn main() {
    loop {
        println!("Input your command");
        print!(">");
        io::stdout().flush().expect("Error flushing output stream");

        let mut user_input = String::new();
        io::stdin().read_line(&mut user_input).expect("Could not read user input.");
        user_input.pop();

        let parameters: Vec<&str> = user_input.split_whitespace().collect();
        if parameters.len() > 0 {
            match parameters[0] {
                "add" => add_signature(parameters),
                "scan" => perform_scan(parameters),
                "help" => show_help(),
                "exit" => ::std::process::exit(0),
                _ => println!("Command not recognised."),
            }
        }
    }
}

fn perform_scan(parameters: Vec<&str>) {
    if parameters.len() < 3 {
        println!("Not enough arguments");
        ()
    }
    let metadata = metadata(parameters[1]).unwrap();
    let db = VirusDatabase::new(parameters[2]).expect("Could not open database file");
    let scanner = Scanner::new(db);
    if metadata.is_file() {
        scanner.scan_file(parameters[1]).expect("Failed to scan file");
    } else if metadata.is_dir() {
        scanner.scan_system(parameters[1]);
    }
}

fn add_signature(parameters: Vec<&str>) {
    if parameters.len() < 4 {
        println!("Not enough arguments!");
        ()
    }
    let mut db = VirusDatabase::new(parameters[3]).expect("Could not open database file");
    let mut sig = signature::generate_signature(parameters[1]);
    sig.set_description(parameters[2].to_string());
    db.add_signature(sig).expect("Error adding signature");
}

fn show_help() {
    println!("->scan <dir/file> <database>
->add <file> <database>
->help
->exit");
}
