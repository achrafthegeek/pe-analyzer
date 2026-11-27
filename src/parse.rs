pub struct PeHeader {
    pub machine: PEType,
    pub num_sections: u16,
    pub timestamp: u32,
}

pub enum PEType {
    PE32,
    PE64,
}

impl PeHeader {
    pub fn new(data: &[u8]) -> Self {
        let pe_type = match get_pe_type(data).unwrap() {
            0x10b => PEType::PE32,
            0x20b => PEType::PE64,
            _ => panic!("Unknown PE format")
        };
        let number_of_sections = get_number_of_sections(data).expect("failed to get number of sections");
        let timestamp = get_timestamp(data).expect("failed to get timestamp");
        Self {
            machine: pe_type,
            num_sections: number_of_sections,
            timestamp: timestamp,
        }
    }
}

pub struct Section<> {
    pub section_name: String,
    pub section_size: u32,
}

impl Section {
    pub fn new(name: String, size: u32) -> Self {
        Self {
            section_name: name,
            section_size: size,
        }
    }
}


pub fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

pub fn read_u32(data: &[u8], off:usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn read_u64(data: &[u8], off:usize) -> Option<u64> {
    let b = data.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
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

pub fn get_timestamp(data: &[u8]) -> Result<u32, &str> {
    const TIMESTAMP_OFFSET: u32 = 8;
    let e_lfanew = get_elfanew(data)?;
    let a = read_u32(data, (e_lfanew + TIMESTAMP_OFFSET).try_into().unwrap()).unwrap_or_default();
    if a == 0 {return Err("Timestamp not found")};

    Ok(a)
}

pub fn get_optional_header_size(data: &[u8]) -> Result<u16, &str> {
    const OPTIONAL_HEADER_OFFSET: u32 = 20;
    let e_lfanew = get_elfanew(data)?;
    let a = read_u16(data, (e_lfanew + OPTIONAL_HEADER_OFFSET).try_into().unwrap()).unwrap_or_default();
    if a == 0 {return Err("Option Header Size not found")};

    Ok(a)
}

pub fn get_number_of_sections(data: &[u8]) -> Result<u16, &str> {
    const NUMBER_OF_SECTIONS_OFFSET: u32 = 6;
    let e_lfanew = get_elfanew(data)?;
    let a = read_u16(data, (e_lfanew + NUMBER_OF_SECTIONS_OFFSET).try_into().unwrap()).unwrap_or_default();
    if a == 0 {return Err("Number of Section not found")};

    Ok(a)
}

pub fn get_sections(data: &[u8]) -> Result<Vec<Section>, &str> {
    let e_lfanew = get_elfanew(data).expect("Unable to get e_lfanew");
    let optional_header_size= get_optional_header_size(data).expect("Unable to get optional header size");
    let section_table_offset = e_lfanew + (optional_header_size as u32) + 24;
    let number_of_sections = get_number_of_sections(data).expect("Unable to get number of sections");

    let mut sections:Vec<Section> = vec![];
    let mut counter = 0;

    while counter != number_of_sections {
        let section_header_offset = section_table_offset + ((counter as u32) * 40);
        let section_name = read_u64(data, section_header_offset.try_into().unwrap()).unwrap_or_default().swap_bytes();
        let section_size = read_u32(data, (section_header_offset + 16).try_into().unwrap()).unwrap_or_default();
        let name_to_string = String::from_utf8_lossy(&section_name.to_be_bytes()).into_owned();

        sections.push(Section::new(name_to_string.to_string(), section_size));

        counter += 1;
    }
    

    Ok(sections)
}