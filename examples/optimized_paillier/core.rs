use kzen_paillier::BigInt;
use kzen_paillier::optimized_paillier::*;

fn main() {
    // generate a fresh keypair
    println!("key gen...");
    let (ek, dk) = OptimizedPaillier::ngen(0, 0).keys();

    // encrypt two values
    println!("encrypt...");
    let c1 = OptimizedPaillier::encrypt(&ek, RawPlaintext::from(BigInt::from(20)));
    let c2 = OptimizedPaillier::encrypt(&ek, RawPlaintext::from(BigInt::from(30)));

    // add all of them together
    println!("add...");
    let c = OptimizedPaillier::add(&ek, c1, c2);

    // multiply the sum by 2
    println!("mul...");
    let d = OptimizedPaillier::mul(&ek, c, RawPlaintext::from(BigInt::from(2)));

    // decrypt final result
    println!("decrypt...");
    let m: BigInt = OptimizedPaillier::decrypt(&dk, d).into();
    println!("decrypted total sum is {}", m);
}
