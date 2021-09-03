use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::Rsa,
    sign::{Signer, Verifier},
};
use qrcode::{render::svg, QrCode};
use std::{fs, io::Write};

fn main() {
    let _ = generate_temp_key();
}

/*
POS Auth II: Adding a Device
Implementation Example in Rust
*/

pub fn generate_temp_key() -> Vec<String> {
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

    // Remove me!
    return sign_new_device(String::from_utf8(temp_keypair.private_key_to_pem().unwrap()).unwrap());

    /*
    1. Display qr.svg to the user;
    2. Wait for a response from Prism's Authentication Authority, then start step VIII
    (Implementation Example at verify_new_device)
    *

    CONSIDERATIONS:
    - Origanally was generating a 2048 key pair here, however since this key is only used temportarilly
      to confirm the New Device's authenticity, using a lower-bit key should surfice as using anything higher
      causes the QR code to be very large and uneasy to scan by the New Device
    - How should communication between Prism's Authentication Authority & the Existing Device occur?
    - The QR code will "Expire" once the user closes the "Add Device" page on the  Existing Device,
      as step 3 will only verify signatures from the current temporary key pair (Displayed as a QR code);
    */
}

pub fn sign_new_device(qr: String) -> Vec<String> {
    /*
    Step V, VI, & VII - Authenticates new Device;
    This occurs on the New Device
    */

    let temp_keypair = &PKey::from_rsa(Rsa::private_key_from_pem(qr.as_bytes()).unwrap()).unwrap();
    let new_device_keypair = &PKey::from_rsa(Rsa::generate(4090).unwrap()).unwrap();

    let mut signer = Signer::new(MessageDigest::sha256(), temp_keypair).unwrap();
    signer
        .update(&new_device_keypair.public_key_to_pem().unwrap())
        .unwrap();
    let signed_public_key = signer.sign_to_vec().unwrap();

    // Remove me!
    return verify_new_device(
        signed_public_key,
        new_device_keypair.public_key_to_pem().unwrap(),
        PKey::from_rsa(
            Rsa::public_key_from_pem(&temp_keypair.public_key_to_pem().unwrap()).unwrap(),
        )
        .unwrap(),
    );

    /*
    1. Send the Signed Public Key to Prism's Authentication Authority, along with an unsigned copy;
    2. Wait for a response message from the Authentication Authority;
    3. Store the generated keypair in the local device's Keychain;
    CONSIDERATIONS:
      - This function would be called after the QR code is scanned by the new device;
        As such, the "qr" argument here would be the value provided by the scan, which is
        likely a stringified version of the RSA-512 private key, rather than the QR code itself;
      - The new_device_keypair would be stored in the Local Device's keychain after
      - The Authentication Authority acts as a proxy or middle man here, communicating information
        between the New and Existing devices;
      - In this example, the generated keypair isn't stored in the keychain until after reciving a 200
        response form the Authentication Authority to ensure the keypair (and Device) is verified
        (Thus authorized under the User's account) prior to being stored in the keychain;
        This, however, might not be the best implementation due to the possible case that the Exisitng Device
        verifies the keypair, sends such to the Authentication Authority to be added to the User's account,
        but the Auth Athority never responds to the New Device (Due to some communciation issue).
        In such a case, the keypair would be valid and authorized under the user account, however the
        New Device would not be able to access the account as it would never recive a response from the
        Auth Authority (And thus never store the Keypair). A better implementation may be to store the
        keypair upon generation, and then query the Authentication Authority after X time not reciving
        a response, & whenever the application is opened again. If the API returns a 200 response, the keypair
        will remain stored, however if it returns that the keypair was never added to the User Account (401),
        it can simply remove the keypair and restart the process. It's important to REMOVE THE OLD KEYPAIR
        and generate a new one in this case, rather than trying again with the same keypair, as it's
        considered compromised after the failed communication.


     */
}

pub fn verify_new_device(
    signed_message: Vec<u8>,
    new_device_public_key: Vec<u8>,
    temp_public_key: PKey<Public>,
) -> Vec<String> {
    /*
    Step VIII - Verifying the new Device;
    This occurs the Existing Device
    */

    let mut verifier = Verifier::new(MessageDigest::sha256(), &temp_public_key).unwrap();
    verifier.update(&new_device_public_key).unwrap();

    if verifier.verify(&signed_message).unwrap() {
        // This keypair would be exisiting and thus pulled from the Device's keychain, NOT newly generated
        let existing_device_keypair = PKey::from_rsa(Rsa::generate(4096).unwrap()).unwrap();

        let mut signer = Signer::new(MessageDigest::sha256(), &existing_device_keypair).unwrap();
        signer.update(&new_device_public_key).unwrap();

        let signed_public_key = signer.sign_to_vec().unwrap();
        return authorize_new_device(
            signed_public_key,
            new_device_public_key,
            PKey::from_rsa(
                Rsa::public_key_from_pem(&existing_device_keypair.public_key_to_pem().unwrap())
                    .unwrap(),
            )
            .unwrap(),
        );
    } else {
        panic!("Signed Public key could not be verified by the Existing Device")
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

pub fn authorize_new_device(
    signed_message: Vec<u8>,
    new_device_public_key: Vec<u8>,
    existing_device_public_key: PKey<Public>,
) -> Vec<String> {
    /*
    Step IX - Authorizing the new Device;
    This occurs on Prism's Authentication Authority
    */
    let mut verifier = Verifier::new(MessageDigest::sha256(), &existing_device_public_key).unwrap();
    verifier.update(&new_device_public_key).unwrap();

    if verifier.verify(&signed_message).unwrap() {
        /*
        Add the New Device's Public Key to the User's Account in Prism's Public Key Store;
        The New Device's key is now Authorized under the user's account, and is considered an Existing Device;
        */
        return vec![
            String::from_utf8(new_device_public_key).unwrap(),
            String::from_utf8(existing_device_public_key.public_key_to_pem().unwrap()).unwrap(),
        ];
    } else {
        return vec![];
        /*
        Communicate to the New Device, that the keypair could not be verified by the Exisitng Device;
        In this case, the User should attempt the entire process again, including regeneration of the
        Temp keypair (Reopening the "Add Device" screen), as it's considered compromised after the
        failed communication;
        */
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorizes_new_key() {
        let result = generate_temp_key();
        assert_eq!(result.len(), 2);
        assert!(Rsa::public_key_from_pem(result[0].as_bytes()).is_ok());
        assert!(Rsa::public_key_from_pem(result[1].as_bytes()).is_ok());
    }
}
