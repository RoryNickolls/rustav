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
