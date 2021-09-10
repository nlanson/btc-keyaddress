use btc_keyaddress;

fn main() {
    print_private_key();
}

fn print_private_key() {
    println!("Random Private Key: {}", btc_keyaddress::new_random_priv_key());
}
