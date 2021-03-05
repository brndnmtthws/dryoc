use crate::constants::*;

use generic_array::GenericArray;
use salsa20::hsalsa20;

pub(crate) fn crypto_core_hsalsa20(input: &[u8; 16], key: &[u8]) -> [u8; 32] {
    let res = hsalsa20(
        &GenericArray::from_slice(key),
        &GenericArray::from_slice(input),
    );

    res.into()
}
