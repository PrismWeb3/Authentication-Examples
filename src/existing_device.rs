use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    sign::{Signer, Verifier},
};
use qrcode::{render::svg, QrCode};
use std::{fs, io::Write};

pub fn generate_temp_key() -> PKey<Private> {
    /*
    Step III & IV - Generates temporary key pair using RSA-512 & encodes in QR;
    Only used for signature-based verification between the Existing and New Devices
    This occurs on the Existing Device
    */

    let temp_keypair = Rsa::generate(512).unwrap();
    let qr = QrCode::new(String::from_utf8(temp_keypair.private_key_to_pem().unwrap()).unwrap())
        .unwrap();

    fs::File::create("qr.svg")
        .unwrap()
        .write_all(qr.render::<svg::Color>().build().as_bytes())
        .unwrap();

    /*
    Since there's no way to actually "scan" the generated QR code, we're going to have this function
    return the keypair itself for example simplicity
    */
    return PKey::from_rsa(temp_keypair).unwrap();

    /*
    1. Display qr.svg to the user;
    2. Wait for a response from Prism's Authentication Authority, then start step VIII
    (Implementation Example at verify_new_device)
    *

    CONSIDERATIONS:
    - Origanally was generating a 2048 key pair here, however since this key is only used temportarilly
      to confirm the New Device's authenticity, using a lower-bit key should surfice as using anything higher
      causes the QR code to be very large and uneasy to scan by the New Device
    - Rather than QR encoding a full private key, could a mnemonic phrase be used instead? This would allow
      the QR code to remain small, while still allowing for utilization of secure, high-bit keys
    - How should communication between Prism's Authentication Authority & the Existing Device occur?
    - The QR code will "Expire" once the user closes the "Add Device" page on the  Existing Device,
      as step 3 will only verify signatures from the current temporary key pair (Displayed as a QR code);
    */
}

pub struct VerifyNewDeviceResp {
    pub status: u16,
    pub signed: Option<Vec<u8>>,
    pub unsigned: Option<Vec<u8>>,
}

pub fn verify_new_device(
    signed_message: Vec<u8>,
    new_device_public_key: Vec<u8>,
    temp_public_key: PKey<Public>,
    existing_device_keypair: &PKey<Private>,
) -> VerifyNewDeviceResp {
    /*
    Step VIII - Verifying the new Device;
    This occurs the Existing Device
    */

    let mut verifier = Verifier::new(MessageDigest::sha256(), &temp_public_key).unwrap();
    verifier.update(&new_device_public_key).unwrap();

    if verifier.verify(&signed_message).unwrap() {
        let mut signer = Signer::new(MessageDigest::sha256(), &existing_device_keypair).unwrap();
        signer.update(&new_device_public_key).unwrap();

        let signed_public_key = signer.sign_to_vec().unwrap();
        return VerifyNewDeviceResp {
            status: 200,
            signed: Some(signed_public_key),
            unsigned: Some(new_device_public_key),
        };
    } else {
        return VerifyNewDeviceResp {
            status: 400,
            signed: None,
            unsigned: None,
        };

        /*
        Communicate to the Authentication Authority, who communicates back to the New Device, that the
        keypair could not be verified; In this case, the User should attempt the entire process again,
        including regeneration of the Temp keypair (Reopening the "Add Device" screen), as it's considered
        compromised after the failed communication;
        */
    }

    /*
    1. Send the New Device's Public Key, signed by the Exisitng Device's Private Key, to the
       Authentication Authority for verification & storage along with an unsigned copy;
    CONSIDERATIONS:
      - Since the data passed here would come from the New Device first, then to the Auth Service, then to
        the Existing Device (Where it's used above), the values should likely be standarized before being
        communicated to comply with cross-language data types;
      - In reality the Existing Device would already have the Temporary Keypair after generating it to
        create the QR code, thus temp_public_key wouldn't be passed back from the New Device;
    */
}
