/// Given a data buffer and a pattern, this method will return a Vec
/// which contains the start index of each pattern match it finds
pub fn search_single(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    
    // Keep track of number of matches found
    let mut matches: Vec<usize> = vec![];

    // Exit if data clearly does not contain pattern!
    if pattern.len() > data.len() {
        return matches;
    }

    // Apply Boyer-Moore until end of data reached
    let mut k = pattern.len()-1;
    while k < data.len() {
        let (matched, jump) = get_shift(data, pattern, k);
        if matched {
            let start = k - (pattern.len() - 1);
            matches.push(start);
        }
        k += jump;
    }
    matches
}

fn get_shift(data: &[u8], pattern: &[u8], k: usize) -> (bool, usize) {
    // Check if end of pattern is equal to data at position k
    if data[k] == pattern[pattern.len()-1] {
        match compare(data, pattern, k) {
            CompareResult::Match => {
                // Bytes equal, add the start as a match!
                return (true, pattern.len());
            },
            CompareResult::Mismatch(mismatch, last) => {
                return (false, mismatch - last);
            },
        }
    } else {
        // If no match then find last occurrence in pattern
        for i in 0..pattern.len() {
            if pattern[i] == data[k] {
                // Found last occurrence!
                return (false, pattern.len() - i - 1);
            }
        }

        // No subsequent match was found, shift whole pattern
        return (false, pattern.len());
    }
}

enum CompareResult {
    Match,
    Mismatch(usize, usize), // mismatch position, last occurrence
}

fn compare(data: &[u8], pattern: &[u8], k: usize) -> CompareResult {
    for i in 0..pattern.len()  {
        let data_byte = data[k - i];
        let pattern_byte = pattern[pattern.len() - 1 - i];

        // Here we have a mismatch
        if data_byte != pattern_byte {
            // Try to find first position j with a matching byte
            for j in 0..pattern.len()-i {
                // Byte matches
                if pattern[j] == data_byte {
                    return CompareResult::Mismatch(pattern.len()-1-i, j);
                }
            }
            return CompareResult::Mismatch(i, 0);
        }
    }
    CompareResult::Match
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
