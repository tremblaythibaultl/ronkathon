//! This module contains the definition of finite fields and their extension fields.

use super::*;

pub mod extension;
pub mod prime;

/// A field is a set of elements on which addition, subtraction, multiplication, and division are
/// defined.
///
/// We restrict to finite fields, which are fields with a finite number of elements.
#[const_trait]
pub trait FiniteField:
  std::fmt::Debug
  + From<usize>
  + Default
  + Sized
  + Copy
  + Clone
  + PartialEq
  + Eq
  + Add<Output = Self>
  + AddAssign
  + Sum
  + Sub<Output = Self>
  + SubAssign
  + Mul<Output = Self>
  + MulAssign
  + Product
  + Div<Output = Self>
  + DivAssign
  + Neg<Output = Self>
  + Rem<Output = Self>
  + Hash
  + 'static {
  /// The order of the field, i.e., the number of elements in the field.
  const ORDER: usize;
  /// The additive identity element.
  const ZERO: Self;
  /// The multiplicative identity element.
  const ONE: Self;
  /// Returns a multiplicative generator of the field.
  const PRIMITIVE_ELEMENT: Self;

  /// Gets the multiplicative inverse of the field element (if it exists).
  fn inverse(&self) -> Option<Self>;

  /// Computes the power of the field element.
  fn pow(self, power: usize) -> Self;

  /// Returns the primitive n-th root of unity in the field.
  ///
  /// ## Notes
  /// In any field of prime order F_p:
  /// - There exists an additive group.
  /// - There exists a multiplicative subgroup generated by a primitive element 'a'.
  ///
  /// According to the Sylow theorems (https://en.wikipedia.org/wiki/Sylow_theorems):
  /// A non-trivial multiplicative subgroup of prime order 'n' exists if and only if
  /// 'p - 1' is divisible by 'n'.
  /// The primitive n-th root of unity 'w' is defined as: w = a^((p - 1) / n),
  /// and the roots of unity are generated by 'w', such that {w^i | i in [0, n - 1]}.
  fn primitive_root_of_unity(n: usize) -> Self {
    let p_minus_one = Self::ORDER - 1;
    assert!(p_minus_one % n == 0, "n must divide p^q - 1");
    let pow = p_minus_one / n;
    Self::PRIMITIVE_ELEMENT.pow(pow)
  }
}
