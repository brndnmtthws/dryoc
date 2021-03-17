pub(crate) struct OnetimeauthPoly1305State {}
pub(crate) fn crypto_onetimeauth_poly1305() {}
pub(crate) fn crypto_onetimeauth_poly1305_init() {}
pub(crate) fn crypto_onetimeauth_poly1305_update() {}
pub(crate) fn crypto_onetimeauth_poly1305_final() {}
pub(crate) fn crypto_onetimeauth_poly1305_verify() {}

pub fn crypto_onetimeauth_keygen() {}
pub fn crypto_onetimeauth() {
    crypto_onetimeauth_poly1305()
}
pub fn crypto_onetimeauth_init() {
    crypto_onetimeauth_poly1305_init()
}
pub fn crypto_onetimeauth_update() {
    crypto_onetimeauth_poly1305_update()
}
pub fn crypto_onetimeauth_verify() {
    crypto_onetimeauth_poly1305_verify()
}
pub fn crypto_onetimeauth_final() {
    crypto_onetimeauth_poly1305_final()
}
