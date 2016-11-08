
#[macro_use]
extern crate bencher;
extern crate paillier;

use bencher::Bencher;
use paillier::*;


pub trait TestKeyGeneration
where
    Self : PartiallyHomomorphicScheme
{
    fn test_keypair() -> (Self::EncryptionKey, Self::DecryptionKey);
    fn test_keypair_sized(usize) -> (Self::EncryptionKey, Self::DecryptionKey);
}
 



pub fn bench_key_generation_512<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::test_keypair_sized(512);
    });
}

pub fn bench_key_generation_1024<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::test_keypair_sized(1024);
    });
}

pub fn bench_key_generation_2048<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::test_keypair_sized(2048);
    });
}

pub fn bench_key_generation_4096<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    b.iter(|| {
        PHE::test_keypair_sized(4096);
    });    
}


////////////// END SAFE PRIMES  ////////////// 

pub fn bench_encryption<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, _) = PHE::test_keypair();
    let m = PHE::Plaintext::from(10);
    b.iter(|| {
        let _ = PHE::encrypt(&ek, &m);
    });
}

pub fn bench_decryption<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, dk) = PHE::test_keypair();
    let m = PHE::Plaintext::from(10);
    let c = PHE::encrypt(&ek, &m);
    b.iter(|| {
        let _ = PHE::decrypt(&dk, &c);
    });
}

pub fn bench_rerandomisation<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, _) = PHE::test_keypair();
    let m = PHE::Plaintext::from(10);
    let c = PHE::encrypt(&ek, &m);
    b.iter(|| {
        let _ = PHE::rerandomise(&ek, &c);
    });
}

pub fn bench_addition<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, _) = PHE::test_keypair();

    let m1 = PHE::Plaintext::from(10);
    let c1 = PHE::encrypt(&ek, &m1);

    let m2 = PHE::Plaintext::from(20);
    let c2 = PHE::encrypt(&ek, &m2);

    b.iter(|| {
        let _ = PHE::add(&ek, &c1, &c2);
    });
}

pub fn bench_multiplication<PHE>(b: &mut Bencher)
where
    PHE : PartiallyHomomorphicScheme,
    PHE : TestKeyGeneration,
    PHE::Plaintext : From<usize>
{
    let (ek, _) = PHE::test_keypair();

    let m1 = PHE::Plaintext::from(10);
    let c1 = PHE::encrypt(&ek, &m1);

    let m2 = PHE::Plaintext::from(20);

    b.iter(|| {
        let _ = PHE::mult(&ek, &c1, &m2);
    });
}



#[cfg(feature="inclramp")]
impl TestKeyGeneration for RampPlainPaillier {
    fn test_keypair() -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        <Self as KeyGeneration>::keypair(2048)
    }

     fn test_keypair_sized(bitsize: usize) -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
        <Self as KeyGeneration>::keypair(bitsize)
    }

}



#[cfg(feature="inclnum")]
impl TestKeyGeneration for NumPlainPaillier {
    fn test_keypair(bitsize: usize) -> (<Self as PartiallyHomomorphicScheme>::EncryptionKey, <Self as PartiallyHomomorphicScheme>::DecryptionKey) {
      
      <Self as KeyGeneration>::keypair(bitsize)
    }
}

#[cfg(feature="inclramp")]
benchmark_group!(ramp,
    self::bench_key_generation_512<RampPlainPaillier>,
    self::bench_key_generation_1024<RampPlainPaillier>,
//    self::bench_key_generation_2048<RampPlainPaillier>,    // THIS IS VERY SLOW
//    self::bench_key_generation_4096<RampPlainPaillier>,    // THIS IS VERY SLOW 
    self::bench_encryption<RampPlainPaillier>,
    self::bench_decryption<RampPlainPaillier>,
    self::bench_rerandomisation<RampPlainPaillier>,
    self::bench_addition<RampPlainPaillier>,
    self::bench_multiplication<RampPlainPaillier>

);

#[cfg(feature="inclnum")]
benchmark_group!(num,
    self::bench_encryption<NumPlainPaillier>,
    self::bench_decryption<NumPlainPaillier>,
    self::bench_rerandomisation<NumPlainPaillier>,
    self::bench_addition<NumPlainPaillier>,
    self::bench_multiplication<NumPlainPaillier>
);

pub fn dummy(_: &mut Bencher) {}

#[cfg(not(feature="inclramp"))]
benchmark_group!(ramp, dummy);

#[cfg(not(feature="inclnum"))]
benchmark_group!(num, dummy);

benchmark_main!(ramp, num);
