// SPDX-License-Identifier: 0BSD
// Copyright (C) 2022 by rtldg <rtldg@protonmail.com>
//
// Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


#![feature(let_chains)]

use digest::Digest;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

enum MyHash {
    CRC32IEEE(String),
    MD5(String),
    SHA1(String),
    SHA2_256(String),
    SHA2_512(String),
    SHA3_512(String),
}

#[derive(Serialize, Deserialize, Default)]
struct Row {
    mapname: String,
    filesize: usize,
    //filesize_bz2: usize,
    crc32ieee: String,
    md5: String,
    sha1: String,
    sha2_256: String,
    sha2_512: String,
    sha3_512: String,
}

/*
fn main2() {
    let mut in_csv = csv::Reader::from_path("../maps-cstrike/ignore/hashed_bsps (lowercase names).csv").unwrap();
    let mut out_csv =
        csv::Writer::from_path("../maps-cstrike/unprocessed/hashed_bsps (original names).csv").unwrap();
    let lines = BufReader::new(
        std::fs::File::open("../maps-cstrike/ignore/hashed_bsps (original names).txt").unwrap(),
    )
    .lines()
    .collect::<Vec<_>>();
    let mut lines = VecDeque::from(lines);

    for row in in_csv.deserialize::<Row>() {
        let mut row = row.unwrap();
        row.mapname = lines.pop_front().unwrap().unwrap();
        out_csv.serialize(row).unwrap();
    }
}
*/

//fn main3() {
    // get filesize of ../hashed/
//}

fn main() {
    /*
    if true {
        main2();
        return;
    }
    */
    let (res_s, res_r) = crossbeam::channel::unbounded::<MyHash>();
    let mut bus: bus::Bus<Arc<memmap2::Mmap>> = bus::Bus::new(2);

    let mut rx_crc = bus.add_rx();
    let res_crc = res_s.clone();
    let _j_crc = std::thread::spawn(move || {
        while let Ok(mmap) = rx_crc.recv() {
            res_crc
                .send(MyHash::CRC32IEEE(format!(
                    "{:x}",
                    crc32fast::hash(&mmap[..])
                )))
                .unwrap();
        }
    });

    let mut rx_md5 = bus.add_rx();
    let res_md5 = res_s.clone();
    let _j_md5 = std::thread::spawn(move || {
        while let Ok(mmap) = rx_md5.recv() {
            let mut hash = md5::Md5::new();
            hash.update(&mmap[..]);
            let hash = hash.finalize();

            res_md5
                .send(MyHash::MD5(base16ct::lower::encode_string(&hash).into()))
                .unwrap();
        }
    });

    let mut rx_sha1 = bus.add_rx();
    let res_sha1 = res_s.clone();
    let _j_sha1 = std::thread::spawn(move || {
        while let Ok(mmap) = rx_sha1.recv() {
            let mut hash = sha1::Sha1::new();
            hash.update(&mmap[..]);
            let hash = hash.finalize();

            res_sha1
                .send(MyHash::SHA1(base16ct::lower::encode_string(&hash).into()))
                .unwrap();
        }
    });

    let mut rx_sha2_256 = bus.add_rx();
    let res_sha2_256 = res_s.clone();
    let _j_sha2_256 = std::thread::spawn(move || {
        while let Ok(mmap) = rx_sha2_256.recv() {
            let mut hash = sha2::Sha256::new();
            hash.update(&mmap[..]);
            let hash = hash.finalize();

            res_sha2_256
                .send(MyHash::SHA2_256(
                    base16ct::lower::encode_string(&hash).into(),
                ))
                .unwrap();
        }
    });

    let mut rx_sha2_512 = bus.add_rx();
    let res_sha2_512 = res_s.clone();
    let _j_sha2_512 = std::thread::spawn(move || {
        while let Ok(mmap) = rx_sha2_512.recv() {
            let mut hash = sha2::Sha512::new();
            hash.update(&mmap[..]);
            let hash = hash.finalize();

            res_sha2_512
                .send(MyHash::SHA2_512(
                    base16ct::lower::encode_string(&hash).into(),
                ))
                .unwrap();
        }
    });

    let mut rx_sha3_512 = bus.add_rx();
    let res_sha3_512 = res_s.clone();
    let _j_sha3_512 = std::thread::spawn(move || {
        while let Ok(mmap) = rx_sha3_512.recv() {
            let mut hash = sha3::Sha3_512::new();
            hash.update(&mmap[..]);
            let hash = hash.finalize();

            res_sha3_512
                .send(MyHash::SHA3_512(
                    base16ct::lower::encode_string(&hash).into(),
                ))
                .unwrap();
        }
    });

    const DELETE: bool = true;
    let p = "../maps-cstrike/unprocessed/hashed_bsps_kz_makes_me_zzz_p2.csv";
    let g = "../70.34.201.93/cstrike/maps/**/*.bsp";
    //const DELETE: bool = false;
    //let p = "../maps-cstrike/unprocessed/hashed_bsps_a011w.broada.jp_p2.csv";
    //let g = "../a011w.broada.jp/lane/css/maps/**/*.bsp";
    if std::path::Path::new(p).exists() {
        panic!("FUCK");
    }

    let mut csv = csv::Writer::from_path(p).unwrap();
    let mut last: Option<(std::path::PathBuf, String)> = None;

    fn map_move_or_remove(delete: bool, last: &Option<(std::path::PathBuf, String)>) {
        if let Some(x) = &last {
            if !std::path::Path::new(&x.1).exists() {
                println!("copying new! {} -> {}", &x.0.display(), &x.1);
                if delete && let Ok(_) = std::fs::rename(&x.0, &x.1) {
                    return;
                }
                let _ = std::fs::copy(&x.0, &x.1);
            }
            if !delete {
                return;
            };
            // sleep because otherwise Windows doesn't want to delete the files.....
            std::thread::sleep(std::time::Duration::from_millis(100));
            let _ = std::fs::remove_file(&x.0);
        }
    }

    for entry in glob::glob(g).unwrap() {
        if let Ok(path) = entry {
            let start = std::time::Instant::now();
            //let file = std::fs::File::open(&path).unwrap();
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true) // we want exclusive access...
                .open(&path);
            if !file.is_ok() {
                continue;
            }
            let file = file.unwrap();
            if file.metadata().unwrap().len() < 2000 { continue; } // hmm
            let mmap = Arc::new(unsafe { memmap2::Mmap::map(&file).unwrap() });

            bus.broadcast(mmap.clone());

            let mut row = Row {
                mapname: path.file_stem().unwrap().to_str().unwrap().to_string(),
                /*
                    .to_ascii_lowercase()
                    .into_string()
                    .unwrap(),
                    */
                /*
                mapname: path
                    .display()
                    .to_string()
                    .strip_prefix("maps_bsps\\")
                    .unwrap()
                    .strip_suffix(".bsp")
                    .unwrap()
                    .to_ascii_lowercase(),
                */
                filesize: mmap.len(),
                ..Default::default()
            };

            // Do some file operations while the hashers are hashing....
            //let _ = csv.flush();

            map_move_or_remove(DELETE, &last);

            for _ in 0..6 {
                match res_r.recv().unwrap() {
                    MyHash::CRC32IEEE(x) => row.crc32ieee = x,
                    MyHash::MD5(x) => row.md5 = x,
                    MyHash::SHA1(x) => row.sha1 = x,
                    MyHash::SHA2_256(x) => row.sha2_256 = x,
                    MyHash::SHA2_512(x) => row.sha2_512 = x,
                    MyHash::SHA3_512(x) => row.sha3_512 = x,
                }
            }

            let duration = start.elapsed();
            println!(
                "Hashed {} in {:.7}s -- {}",
                row.sha3_512,
                duration.as_secs_f64(),
                path.display()
            );
            last = Some((path, format!("../hashed/{}.bsp", row.sha3_512)));
            csv.serialize(row).unwrap();
            let _ = csv.flush();
        }
    }

    map_move_or_remove(DELETE, &last);

    csv.flush().unwrap();
}
