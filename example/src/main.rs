use btc_keyaddress::{
    key::PubKey,
    key::PrivKey,
    address::Address
};

fn main() {
    //gen_key_pair_and_print();
    create_hash160();
}

fn gen_key_pair_and_print() {
    let k = PrivKey::new_rand();
    let K = PubKey::from_priv_key(&k);

    println!("Priv: {}\nPub: {}\n", k, K);
}

fn create_hash160() {
    let k: PrivKey = PrivKey::new_rand();
    let pk: PubKey = PubKey::from_priv_key(&k);
    let a: String = Address::from_pub_key(&pk);

    println!("Priv: {}\n Pub:  {}\n Add: {}", k, pk, a);
}
