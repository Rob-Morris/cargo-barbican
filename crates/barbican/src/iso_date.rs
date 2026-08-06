use thiserror::Error;
use time::{Date, Month};

const ISO_DATE_LEN: usize = 10;

pub fn parse_iso_date(value: &str) -> Result<Date, IsoDateError> {
    let bytes = value.as_bytes();
    if bytes.len() != ISO_DATE_LEN
        || !bytes[0..4].iter().all(u8::is_ascii_digit)
        || bytes[4] != b'-'
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || bytes[7] != b'-'
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        return Err(IsoDateError);
    }

    let year = value[0..4].parse::<i32>().map_err(|_| IsoDateError)?;
    let month_number = value[5..7].parse::<u8>().map_err(|_| IsoDateError)?;
    let day = value[8..10].parse::<u8>().map_err(|_| IsoDateError)?;
    let month = Month::try_from(month_number).map_err(|_| IsoDateError)?;

    Date::from_calendar_date(year, month, day).map_err(|_| IsoDateError)
}

pub fn format_iso_date(date: Date) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected ISO date in YYYY-MM-DD form")]
pub struct IsoDateError;
