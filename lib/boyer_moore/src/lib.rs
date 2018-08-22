use std::collections::HashMap;

/// Given a data buffer and a pattern, this method will return a Vec
/// which contains the start index of each pattern match it finds
pub fn search_single(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    
    // Keep track of number of matches found
    let mut matches: Vec<usize> = vec![];

    // Exit if data clearly does not contain pattern!
    if pattern.len() > data.len() {
        return matches;
    }

    let mut occurrences = HashMap::new();
    for i in pattern.len()..0 {
        occurrences.insert(pattern[i - 1], i - 1);
    }

    // Apply Boyer-Moore until end of data reached
    let mut k = pattern.len() - 1;
    let end = data.len() - pattern.len();
    while k < end {
        let (matched, jump) = get_shift(data, pattern, k, &occurrences);
        if matched {
            let start = k - (pattern.len() - 1);
            matches.push(start);
        }
        k += jump;
    }
    matches
}

fn get_shift(data: &[u8], pattern: &[u8], k: usize, occurrences: &HashMap<u8, usize>) -> (bool, usize) {
    let mut i = pattern.len() - 1;
    let mut j = k;
    while i > 0 {
        if pattern[i] != data[j] {
            // Here we have found a mismatch at position j in data, position pattern.len()-i in pattern
            if occurrences.contains_key(&data[j]) {
                println!("CONTAINED");
                return (false, *occurrences.get(&data[j]).unwrap());
            }
            return (false, *occurrences.get(&data[k]).unwrap_or(&pattern.len()));
        }
        i = i - 1;
        j = j - 1;
    }
    // No mismatch, pattern must be equal
    return (true, pattern.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_contains() {
        let data = vec![ 32, 53, 40, 94, 84, 128, 94, 4, 84, 234 ];
        let pattern = vec![ 128, 94, 4 ];
        assert_eq!(search(&data, &pattern).unwrap(), [ 7 ] );
    }

    #[test]
    fn search_not_contains() {
        let data = vec![ 32, 53, 40, 94, 84, 128, 94, 4, 84, 234 ];
        let pattern = vec![ 128, 94, 8, 9 ];
        assert_eq!(search(&data, &pattern).unwrap(), [] );
    }
}
