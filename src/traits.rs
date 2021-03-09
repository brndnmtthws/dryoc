/// Trait for generating random values
pub trait Gen {
    /// This function should return a new instance of `Self` with random values
    fn gen() -> Self;
}
