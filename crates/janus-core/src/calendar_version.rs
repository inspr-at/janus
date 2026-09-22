// Canonical UTC validation shared by the compiler build gate and release admission.
pub(crate) fn valid_calendar(value: &str) -> bool {
    let Some(stamp) = value.strip_suffix(".0.0") else {
        return false;
    };
    if stamp.len() != 12 || stamp.starts_with('0') || !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let part = |start| stamp[start..start + 2].parse::<u32>().unwrap_or(100);
    let (year, month, day) = (2000 + part(0), part(2), part(4));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 => 29,
        2 => 28,
        _ => return false,
    };
    day > 0 && day <= max_day && part(6) < 24 && part(8) < 60 && part(10) < 60
}
