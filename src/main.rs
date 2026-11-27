use std::error::Error;
use std::{env, fs, process};
use std::time::{Duration, UNIX_EPOCH};
use chrono::{DateTime, Utc};
mod parse;



fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pe-analyzer <file>");
        process::exit(1);
    });
    let data = fs::read(&path).expect("could not read file");

    if data.get(0..2) != Some(b"MZ".as_slice()) {
        println!("not a PE file");
        //return;
    }
    //println!("MZ ok, {} bytes", data.len());

    //let pe_magic = parse::read_u16(&data, 0x40);
    //println!("magic value: {:x}", pe_magic.unwrap_or_default());
    //println!("PE signature: {:x?}", data.get(0x40..0x42).unwrap_or_default());
    //println!("PE archeticture: {:x?}", data.get(0x58..0x5a).unwrap_or_default());

    //let mz = parse::get_mz_signature(&data)?;
    //println!("Magic MZ: {:x}", mz);

    //let e_lfanew= parse::get_elfanew(&data)?;
    //println!("e_lfanew: {:x}", e_lfanew);

    //let pe = parse::get_pe_signature(&data)?;
    //println!("PE signature: {:x}", pe);

    //let pe_type = parse::get_pe_type(&data)?;
    //println!("PE type: {:x}", pe_type);

    //let oh_size = parse::get_optional_header_size(&data)?;
    //println!("Optional Header Size: {:x}", oh_size);

    //let number_of_sections = parse::get_number_of_sections(&data)?;
    //println!("Number of Sections: {:x}", number_of_sections);
    let file_header = parse::PeHeader::new(&data);
    println!("PE type: {:?}\nNumber of Sections: {}\nTimestamp: {:?}", 
        match file_header.machine {
            parse::PEType::PE32 => "32 bit PE",
            parse::PEType::PE64 => "64 bit PE"
        }, 
        file_header.num_sections,
        DateTime::from_timestamp(file_header.timestamp as i64, 0).expect("Invalid timestamp")
    );

    let sections = parse::get_sections(&data)?;

    for section in sections {
        println!("Section name: {}\nSection size: {} bytes", section.section_name, section.section_size);
    }
    
    Ok(())
}
