use btc_keyaddress::key::{PubKey, PrivKey};

fn main() {
    gen_key_pair_and_print();
}

fn gen_key_pair_and_print() {
    let k = PrivKey::new_rand();
    let K = PubKey::from_priv_key(&k);

    println!("Priv: {}\nPub: {}\n", k, K);
}
