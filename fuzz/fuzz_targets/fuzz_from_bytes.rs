#![no_main]
use dryoc::dryocbox::{DryocBox, VecBox as VecDryocBox};
use dryoc::dryocsecretbox::{DryocSecretBox, VecBox as VecSecretBox};
use dryoc::sign::{SignedMessage, VecSignedMessage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = VecDryocBox::from_bytes(data);
    let _ = VecDryocBox::from_sealed_bytes(data);
    let _ = VecSecretBox::from_bytes(data);
    let _ = VecSignedMessage::from_bytes(data);

    if let Ok(dryocbox) = VecDryocBox::from_bytes(data) {
        let bytes = dryocbox.to_vec();
        let reparsed: VecDryocBox = DryocBox::from_bytes(&bytes).expect("box round trip");
        assert_eq!(bytes, reparsed.to_vec());
    }

    if let Ok(dryocbox) = VecDryocBox::from_sealed_bytes(data) {
        let bytes = dryocbox.to_vec();
        let reparsed: VecDryocBox =
            DryocBox::from_sealed_bytes(&bytes).expect("sealed box round trip");
        assert_eq!(bytes, reparsed.to_vec());
    }

    if let Ok(secretbox) = VecSecretBox::from_bytes(data) {
        let bytes = secretbox.to_vec();
        let reparsed: VecSecretBox =
            DryocSecretBox::from_bytes(&bytes).expect("secretbox round trip");
        assert_eq!(bytes, reparsed.to_vec());
    }

    if let Ok(signed_message) = VecSignedMessage::from_bytes(data) {
        let bytes = signed_message.to_vec();
        let reparsed: VecSignedMessage =
            SignedMessage::from_bytes(&bytes).expect("signed message round trip");
        assert_eq!(bytes, reparsed.to_vec());
    }
});
