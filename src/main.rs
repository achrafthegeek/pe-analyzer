use std::{env, fs, process};
mod parse;

struct PeHeader {
    machine: u16,
    num_sections: u16,
    timestamp: u32,
}



fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: pe-analyzer <file>");
        process::exit(1);
    });
    let data = fs::read(&path).expect("could not read file");

    if data.get(0..2) != Some(b"MZ".as_slice()) {
        println!("not a PE file");
        return;
    }
    println!("MZ ok, {} bytes", data.len());

    let pe_magic = parse::read_u32(&data, 0xe8);
    println!("magic value: {:?}", pe_magic.unwrap_or_default());
    println!("PE signature: {:?}", data.get(0x40..0x42).unwrap_or_default());
    println!("PE bit: {:x?}", data.get(0x58..0x5a).unwrap_or_default());

    let e_lfanew = parse::get_elfanew(&data);
    println!("e_lfanew: {:x}", e_lfanew.unwrap_or_default());
}
