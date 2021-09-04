use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sign::Verifier,
};

pub struct AuthorizeStatus {
    pub status: u16,
    pub new_authorized_key: Option<String>,
    pub existing_authentication_key: Option<String>,
}

pub fn authorize_new_device(
    signed_message: Vec<u8>,
    new_device_public_key: Vec<u8>,
    existing_device_public_key: PKey<Public>,
) -> AuthorizeStatus {
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
        return AuthorizeStatus {
            status: 200,
            new_authorized_key: Some(String::from_utf8(new_device_public_key).unwrap()),
            existing_authentication_key: Some(
                String::from_utf8(existing_device_public_key.public_key_to_pem().unwrap()).unwrap(),
            ),
        };
    } else {
        return AuthorizeStatus {
            status: 401,
            new_authorized_key: None,
            existing_authentication_key: None,
        };
        /*
        Communicate to the New Device, that the keypair could not be verified by the Exisitng Device;
        In this case, the User should attempt the entire process again, including regeneration of the
        Temp keypair (Reopening the "Add Device" screen), as it's considered compromised after the
        failed communication;
        */
    }
}
