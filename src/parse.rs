struct PeHeader {
    machine: u16,
    num_sections: u16,
    timestamp: u32,
}



pub fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

pub fn read_u32(data: &[u8], off:usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn get_mz_signature(data: &[u8]) -> Result<u16, &str> {
    let a = read_u16(&data, 0).unwrap_or_default();
    if a != 0x5a4d {
        return Err("MZ signature not found");
    }
    Ok(a)
}

pub fn get_elfanew(data: &[u8]) -> Result<u32, &str> {
    let a = read_u32(data, 0x3c).unwrap_or_default();
    if a == 0 {return Err("e_lfawnew was not found")};
    Ok(a)
}

pub fn get_pe_signature(data: &[u8]) -> Result<u32, &str> {
    let e_lfanew = get_elfanew(data)?;
    let a = read_u32(data, e_lfanew.try_into().unwrap()).unwrap_or_default();
    if a != 0x4550 {
        return Err("PE signature not found")
    }
    Ok(a)
}

pub fn get_pe_type(data: &[u8]) -> Result<u16, &str> {
    let e_lfanew = get_elfanew(data)?;
    let a = read_u16(data, (e_lfanew + 24).try_into().unwrap()).unwrap_or_default();

    if a != 0x010b && a != 0x020b {
        return Err("Could not parse the option header");
    }

    Ok(a)
}

pub fn get_optional_header_size(data: &[u8]) -> Result<u16, &str> {
    const OPTIONAL_HEADER_OFFSET: u32 = 20;
    let e_lfanew = get_elfanew(data)?;
    let a = read_u16(data, (e_lfanew + OPTIONAL_HEADER_OFFSET).try_into().unwrap()).unwrap_or_default();
    if a == 0 {return Err("Option Header Size not found")}

    Ok(a)
}

pub fn get_number_of_sections(data: &[u8]) -> Result<u16, &str> {
    const NUMBER_OF_SECTIONS_OFFSET: u32 = 6;
    let e_lfanew = get_elfanew(data)?;
    let a = read_u16(data, (e_lfanew + NUMBER_OF_SECTIONS_OFFSET).try_into().unwrap()).unwrap_or_default();
    if a == 0 {return Err("Number of Section not found")}

    Ok(a)
}