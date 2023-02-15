use auther_lib::*;

fn main() {
    let pass = Passkey::Plain("abc".to_string());

    println!("{pass:?}");
}