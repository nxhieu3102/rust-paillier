use kzen_paillier::BigInt;
use kzen_paillier::optimized_paillier::*;

fn main() {
    // generate a fresh keypair
    let (ek, dk) = OptimizedPaillier::ngen().keys();

    // encrypt two values
    let c1 = OptimizedPaillier::encrypt(&ek, RawPlaintext::from(BigInt::from(20)));
    let c2 = OptimizedPaillier::encrypt(&ek, RawPlaintext::from(BigInt::from(30)));

    // add all of them together
    let c = OptimizedPaillier::add(&ek, c1, c2);

    // multiply the sum by 2
    let d = OptimizedPaillier::mul(&ek, c, RawPlaintext::from(BigInt::from(2)));

    // decrypt final result
    let m: BigInt = OptimizedPaillier::decrypt(&dk, d).into();
    println!("decrypted total sum is {}", m);
}
