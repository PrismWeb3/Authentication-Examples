mod auth_authority;
mod existing_device;
mod new_device;

use auth_authority::AuthorizeStatus;
use existing_device::VerifyNewDeviceResp;
use new_device::NewDevicePubKey;
use openssl::{
    pkey::{PKey, Private, Public},
    rsa::Rsa,
};
/*
POS Auth II: Adding a Device
Implementation Example in Rust

For this implementation example, we will have a unique main.rs function for each local scope;
Communication between Scope's will be represented as function calls, however, some communications are
omitted for similicity, such as the Authentication Authority's lack-of-use as a proxy;
Additionally, the console will be used to print User-Facing messages, which would be displayed using a UI.
These messages will also include the scope from which they originated;
*/

fn main() {
    /*
     The flow of adding a new device will always begin on the Existing Device; Even though the user could,
     and likely would, phsically begin on the New Device by clicking Login and inputting their username,
     everything programatic (Besides an API call that the username exists) will occur on the Existing Device;
     To prove this is true, however, the below function is interchangable between the two;
    */
    existing_device()
    // OR new_device(None);
}

fn new_device(temp_keypair: Option<String>) -> Option<NewDevicePubKey> {
    // The scope of the New Device
    use crate::new_device::sign_new_device;

    match temp_keypair {
        Some(keypair) => {
            return Some(sign_new_device(keypair));
        }
        None => {
            println!("NEW\n Username _________________");
            println!("NEW\n -- LOGIN --");
            existing_device();
            return None;
        }
    }
}

fn existing_device() {
    // The scope of the Existing Device
    use existing_device::{generate_temp_key, verify_new_device};

    println!("EXISTING:\n   Scan the QR code on your New Device");

    // This keypair would be exisiting and thus pulled from the Device's keychain, NOT newly generated
    let existing_device_keypair: PKey<Private> =
        PKey::from_rsa(Rsa::generate(4096).unwrap()).unwrap();

    let temp_keypair = generate_temp_key();
    let signed_pub_key = new_device(Some(
        String::from_utf8(temp_keypair.private_key_to_pem_pkcs8().unwrap()).unwrap(),
    ))
    .unwrap();

    let verify_response = verify_new_device(
        signed_pub_key.signed,
        signed_pub_key.unsigned,
        PKey::from_rsa(
            Rsa::public_key_from_pem(&temp_keypair.public_key_to_pem().unwrap()).unwrap(),
        )
        .unwrap(),
        &existing_device_keypair,
    );

    match verify_response.status {
        200 => {
            let _ = auth_authority(
                verify_response,
                PKey::from_rsa(
                    Rsa::public_key_from_pem(&existing_device_keypair.public_key_to_pem().unwrap())
                        .unwrap(),
                )
                .unwrap(),
            );
        }
        400 => {
            println!("EXISTING:\n   The authorization failed! Restart the process.");
        }
        _default => {
            panic!("An unknown error status was passed to the existing device!")
        }
    }
}

fn auth_authority(
    verify_response: VerifyNewDeviceResp,
    existing_device_pub_key: PKey<Public>,
) -> AuthorizeStatus {
    // The scope of the Authentication Authority
    use auth_authority::authorize_new_device;

    let resp = authorize_new_device(
        verify_response.signed.unwrap(),
        verify_response.unsigned.unwrap(),
        existing_device_pub_key,
    );

    match resp.status {
        200 => {
            println!(
                "\nNEW KEY AUTHORIZED:\n{}",
                resp.new_authorized_key.as_ref().unwrap()
            );
            println!(
                "AUTHORIZED BY EXISTING KEY:\n{}",
                resp.existing_authentication_key.as_ref().unwrap()
            );
            return resp;
        }
        401 => {
            println!("AUTH:\n   The authorization was denied! Restart the process.");
            return resp;
        }
        _default => {
            panic!("An unknown error status was passed to the auth service!")
        }
    }
}