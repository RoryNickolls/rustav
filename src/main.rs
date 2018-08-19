extern crate md5;
extern crate walkdir;
extern crate colored;

mod signature;
mod scanner;
mod virus_database;

use virus_database::VirusDatabase;

use scanner::Scanner;

use std::io;
use std::io::Write;

fn main() {
    loop {
        println!("Input your command");
        print!(">");
        io::stdout().flush().expect("Error flushing output stream");

        let mut user_input = String::new();
        io::stdin().read_line(&mut user_input).expect("Could not read user input.");
        user_input.pop();

        let parameters: Vec<&str> = user_input.split_whitespace().collect();
        match parameters[0] {
            "filescan" => perform_filescan(parameters),
            "add" => add_signature(parameters),
            "systemscan" => perform_systemscan(parameters),
            "help" => show_help(),
            "exit" => ::std::process::exit(0),
            _ => println!("Command not recognised."),
        }
    }
}

fn perform_filescan(parameters: Vec<&str>) {
    if parameters.len() < 3 {
        println!("Not enough arguments!");
        ()
    }
    //println!("Starting scan of {} using database {}", parameters[1], parameters[2]);
    let db = VirusDatabase::new(parameters[2]);
    let scanner = Scanner::new(db);
    scanner.scan_file(parameters[1]).expect("Could not scan file!");
}

fn perform_systemscan(parameters: Vec<&str>) {
    if parameters.len() < 3 {
        println!("Not enough arguments!");
        ()
    }
    let db = VirusDatabase::new(parameters[2]);
    let scanner = Scanner::new(db);
    scanner.scan_system(parameters[1]);
}

fn add_signature(parameters: Vec<&str>) {
    if parameters.len() < 4 {
        println!("Not enough arguments!");
        ()
    }
    let mut db = VirusDatabase::new(parameters[3]);
    let mut sig = signature::generate_signature(parameters[1]);
    sig.set_description(parameters[2].to_string());
    db.add_signature(sig).expect("Error adding signature");
}

fn show_help() {
    println!("
->filescan <file> <database>
->systemscan <root> <database>
->add <file> <database>
->help
->exit");
}
