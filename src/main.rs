use std::io::{self,Read,stdin};
use std::fs::File;
use sha2::{Sha256,Digest};
use generic_array::{GenericArray,ArrayLength};
use hex;

const BUF_SIZE: usize = 1024;

fn main() {
    let cmd = clap::Command::new("sha256sum")
        .bin_name("sha256sum")
        .arg(
            clap::Arg::new("check")
                .long("check")
                .short('c')
                .help("read SHA256 sums from the FILEs and check them")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(clap::arg!([FILE] ... "files to parse, or use stdin if none").trailing_var_arg(true));

    let matches = cmd.get_matches();

    let check = match matches.get_one::<bool>("check") {
        Some(t) => *t,
        None => false
    };

    if !check {
        compute_hashes(matches).unwrap();
    }
}

fn compute_hashes(matches : clap::ArgMatches) -> Result<(), io::Error>{
    let files : Vec<_>= matches.get_many::<String>("FILE").unwrap().collect();
    let mut files_specified = false;
    for f in files {
        if f == "-" {
            break;
        }
        files_specified = true;
        let digest = compute_file_hash::<Sha256>(f)?;
        emit_row(f, &digest)?;
    }

    if !files_specified {
        //let digest = computeHash(stdin);
    }
    return Result::Ok(());
}

fn emit_row<S : ArrayLength<u8>>(filename : &String, bs : &GenericArray<u8, S>) -> Result<(), io::Error> {
    println!("{}\t{}", hex::encode(bs),filename);
    return Ok(())
}

fn compute_file_hash<H : Digest>(path : &str) -> Result<GenericArray<u8, H::OutputSize>, io::Error>{
    let file = File::open(path)?; // closed automatically when it goes out of scope
    return compute_hash::<H,File>(file);
}

fn compute_hash<H : Digest, R: Read>(mut reader : R) -> Result<GenericArray<u8, H::OutputSize>, io::Error>{
    let mut buf = [0; BUF_SIZE];
    let mut hash = H::new();
    loop {
        let cnt = reader.read(&mut buf)?;
        if cnt == 0 {
            break;
        }
        hash.update(&buf[..cnt]);
    }
    return Result::Ok(hash.finalize())
}

