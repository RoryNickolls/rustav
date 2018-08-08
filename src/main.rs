extern crate antivirus;

use antivirus::VirusDatabase;
use antivirus::Scanner;

use std::io;
use std::io::Write;

fn main() {
    println!("Rory's AV Program");
    loop {
        println!("\nInput your command");
        print!(">");
        io::stdout().flush().expect("Error flushing output stream");

        let mut user_input = String::new();
        io::stdin().read_line(&mut user_input).expect("Could not read user input.");
        user_input.pop();

        let parameters: Vec<&str> = user_input.split_whitespace().collect();
        match parameters[0] {
            "filescan" => perform_filescan(parameters),
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
    scanner.scan_file(parameters[1]);
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

fn show_help() {
    println!(
"filescan <file> <database>
systemscan <root> <database>
help
exit");
}
