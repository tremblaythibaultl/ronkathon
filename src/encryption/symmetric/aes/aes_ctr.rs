use super::*;
use crate::encryption::symmetric::{counter::Counter, StreamCipher};

// TODO: put those constants elsewhere
pub const BLOCK_SIZE: usize = 16;
pub const COUNTER_SIZE: usize = 4;
pub struct AesCtr<const N: usize, const C: usize>
where [(); N / 8]: {
  key:   Key<N>,
  nonce: Block,
}
// TODO: Explain how many encryptions this supports, ie 2^COUNTER_SIZE
impl<const N: usize, const C: usize> AesCtr<N, C>
where [(); N / 8]:
{
  pub fn aes_ctr_encrypt(&self, counter: &Counter<C>, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if counter.0.len() > COUNTER_SIZE {
      return Err(String::from(
        "invalid counter length: counter should be at most 64 bits (8 bytes)",
      ));
    }

    let mut ciphertext: Vec<u8> = Vec::new();

    let mut counter_iter = *counter;

    // parse input plaintext in chunks of 16 bytes
    let chunks = plaintext.chunks_exact(BLOCK_SIZE);
    let remainder = chunks.remainder();

    for chunk in chunks {
      let mut counter_bytes = [0_u8; COUNTER_SIZE];
      counter_bytes[..].copy_from_slice(&counter_iter.0[..COUNTER_SIZE]);

      // compute input block by incrementing the 64 LBSs by the counter
      let nonce_value = u128::from_be_bytes(self.nonce.0);
      let nonce_value_msb = nonce_value & &0xffffffffffffffffffffffff00000000;
      let nonce_value_lsb = nonce_value as u32;
      let incremented_lsb = nonce_value_lsb.wrapping_add(u32::from_be_bytes(counter_bytes));
      let input_block =
        Block::from((nonce_value_msb + incremented_lsb as u128).to_be_bytes().to_vec());

      // increment the counter
      counter_iter.increment()?;

      let output_block = AES::encrypt(&self.key, &input_block);

      let ciphertext_block: Vec<u8> =
        chunk.iter().zip(output_block.0.iter()).map(|(a, b)| a ^ b).collect();

      // serialize encrypted bytes to ciphertext
      ciphertext.extend(ciphertext_block);
    }

    // encrypt remainder plaintext bytes separately
    if !remainder.is_empty() {
      let mut counter_bytes = [0_u8; BLOCK_SIZE];
      counter_bytes[..].copy_from_slice(&counter_iter.0[..BLOCK_SIZE]);

      let input_block = Block::from(
        (u128::from_be_bytes(self.nonce.0).wrapping_add(u128::from_be_bytes(counter_bytes)))
          .to_be_bytes()
          .to_vec(),
      );

      let output_block = AES::encrypt(&self.key, &input_block);

      let ciphertext_block: Vec<u8> =
        remainder.iter().zip(output_block.0.iter()).map(|(a, b)| a ^ b).collect();

      // serialize encrypted bytes to ciphertext
      ciphertext.extend(ciphertext_block);
    }

    Ok(ciphertext)
  }

  pub fn aes_ctr_decrypt(&self, counter: &Counter<C>, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    self.aes_ctr_encrypt(counter, plaintext)
  }
}

impl<const N: usize, const C: usize> StreamCipher for AesCtr<N, C>
where [(); N / 8]:
{
  type Counter = Counter<C>;
  type Error = String;
  type Key = Key<N>;
  type Nonce = Block;

  fn new(key: &Self::Key, nonce: &Self::Nonce) -> Result<Self, Self::Error>
  where Self: Sized {
    Ok(Self { key: *key, nonce: *nonce })
  }

  fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
    let counter = Counter::<C>::new([0u8; C]);
    self.aes_ctr_encrypt(&counter, plaintext)
  }

  fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
    let counter = Counter::<C>::new([0u8; C]);
    self.aes_ctr_decrypt(&counter, ciphertext)
  }

  fn encrypt_with_counter(
    &self,
    counter: &Self::Counter,
    plaintext: &[u8],
  ) -> Result<Vec<u8>, Self::Error> {
    self.aes_ctr_encrypt(counter, plaintext)
  }

  fn decrypt_with_counter(
    &self,
    counter: &Self::Counter,
    ciphertext: &[u8],
  ) -> Result<Vec<u8>, Self::Error> {
    self.aes_ctr_decrypt(counter, ciphertext)
  }
}

#[test]
fn test_aes_ctr_192() {
  const KEY_LEN: usize = 192;
  let key = Key::<KEY_LEN>::new([
    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
  ]);

  let initialization_vector: [u8; 16] = [
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
  ];

  let plaintext: [u8; 64] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
  ];

  let expected_ciphertext: [u8; 64] = [
    0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b,
    0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef, 0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94,
    0x1e, 0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70, 0xd1, 0xbd, 0x1d, 0x66, 0x56, 0x20, 0xab, 0xf7,
    0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09, 0x58, 0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50,
  ];

  let aes_ctr: AesCtr<KEY_LEN, COUNTER_SIZE> =
    AesCtr::new(&key, &Block(initialization_vector)).unwrap();
  let ciphertext = aes_ctr.encrypt(&plaintext).unwrap();
  assert_eq!(ciphertext, expected_ciphertext.to_vec());

  let decrypted_plaintext = aes_ctr.decrypt(&ciphertext).unwrap();
  assert_eq!(decrypted_plaintext, plaintext.to_vec())
}

#[test]
fn test_aes_ctr_128() {
  const KEY_LEN: usize = 128;
  let key = Key::<KEY_LEN>::new([
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
  ]);

  let initialization_vector: [u8; 16] = [
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
  ];

  let plaintext: [u8; 64] = [
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
  ];

  let expected_ciphertext: [u8; 64] = [
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
    0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
    0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
  ];

  let aes_ctr: AesCtr<KEY_LEN, COUNTER_SIZE> =
    AesCtr::new(&key, &Block(initialization_vector)).unwrap();
  let ciphertext = aes_ctr.encrypt(&plaintext).unwrap();
  assert_eq!(ciphertext, expected_ciphertext.to_vec());

  let decrypted_plaintext = aes_ctr.decrypt(&ciphertext).unwrap();
  assert_eq!(decrypted_plaintext, plaintext.to_vec())
}
