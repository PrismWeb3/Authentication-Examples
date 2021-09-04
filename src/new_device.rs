use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer};

pub struct NewDevicePubKey {
    pub signed: Vec<u8>,
    pub unsigned: Vec<u8>,
}

pub fn sign_new_device(qr: String) -> NewDevicePubKey {
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

    return NewDevicePubKey {
        signed: signed_public_key,
        unsigned: new_device_keypair.public_key_to_pem().unwrap(),
    };

    // Remove me!
    /* return verify_new_device(
        signed_public_key,
        new_device_keypair.public_key_to_pem().unwrap(),
        PKey::from_rsa(
            Rsa::public_key_from_pem(&temp_keypair.public_key_to_pem().unwrap()).unwrap(),
        )
        .unwrap(),
    );*/

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
