// returns the length of the longest substring starting from the beginning of first and second.
pub fn longest_substring(first: &[u8], second: &[u8]) -> usize {
    first
        .clone()
        .into_iter()
        .zip(second)
        .take_while(|(cur, prev)| *cur == *prev)
        .count()
}
