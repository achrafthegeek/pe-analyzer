pub fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

pub fn read_u32(data: &[u8], off:usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn get_elfanew(data: &[u8]) -> Option<u16> {
    let a = data.get(0x3c..0x3e).unwrap_or_default();
    Some(u16::from_le_bytes([a[0], a[1]]))
}