// started with an implementation of rc4...
//
fn fixed_or<T: AsRef<[u8]>, U: AsRef<[u8]>>(plaintext: U, keystream: T) -> Vec<u8> {
    let plaintext = plaintext.as_ref();
    let keystream = keystream.as_ref().iter().cycle().take(plaintext.len());

    let xor_bytes: Vec<u8> = plaintext
        .iter()
        .zip(keystream)
        .map(|(b1, b2)| b1 ^ b2)
        .collect();

    xor_bytes
}

#[allow(unused)]
fn rc4<U: AsRef<[u8]>, T: AsRef<[u8]>>(plaintext: U, key: T) {
    let plaintext = plaintext.as_ref();
    let key = key.as_ref();
    let range = 0..=255;
    let mut s = range.collect::<Vec<usize>>();
    println!("s = {}", s[0]);
    let keylength = key.len();
    let mut keystream = Vec::new();

    let mut j = 0;
    // KSA
    for i in 0..256 {
        j = (j + s[i] + key[i % keylength] as usize) % 256;
        s.swap(i, j);
    }

    // PRGA
    let (mut i, mut j) = (0, 0);
    for _ in 0..16 {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        // swap s[i] with s[j]
        s.swap(i, j);
        keystream.push(s[(s[i] + s[j]) % 256] as u8)
    }

    let cipher = hex::encode(fixed_or(plaintext, keystream));
    println!("cipher = {cipher}")
}
