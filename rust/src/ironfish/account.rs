// Copyright 2021-2021 FoxWallet.

// use bip39::{Language};
use ironfish_rust::{SaplingKey, PublicAddress};
use super::utils::{serialize_sampling_key, serialize_ironfish_error};
use crate::export;

export! {
	// generate new ironfish account
	@Java_com_foxwallet_core_WalletCoreModule_ironfishCreateAccountInternal
	fn ironfish_create_account() -> String {
		let sapling_key = SaplingKey::generate_key();
		serialize_sampling_key(&sapling_key)
	}

	// generate new ironfish account from private key
	@Java_com_foxwallet_core_WalletCoreModule_ironfishCreateAccountFromPrivateKeyInternal
	fn ironfish_create_account_from_pk(
		pk: String
	) -> String {
		let sapling_key = SaplingKey::from_hex(&pk);
		match &sapling_key {
			Ok(key) => serialize_sampling_key(&key),
			Err(err) => serialize_ironfish_error(&err)
		}
	}

	@Java_com_foxwallet_core_WalletCoreModule_ironfishIsValidAddressInternal
	fn ironfish_is_valid_public_address(hex_address: String) -> String {
    if PublicAddress::from_hex(&hex_address).is_ok() {
			"true".to_string()
		} else {
			"false".to_string()
		}
	}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ironfish_create_account() {
        let result = ironfish_create_account();
        assert!(result.len() > 0);
    }

    #[test]
    fn test_ironfish_create_account_from_pk() {
        let result = ironfish_create_account_from_pk(String::from(""));
        assert_eq!(result, r#"{"data":{"incomingViewKey":"38f0ef124757d927ff82de65da80e856194d928449d93b5d141009d0bfe4c102","outgoingViewKey":"3ebf58f366a0c67d505773d98bd27bac9a8adfb1c5ac36cc08e7b56739828d82","publicAddress":"9e55a5269ae1415217ab4416dcf2cd373e035682d28479b51d5d486dfdbd91be","viewKey":"e13da16eb1ad40d84159c46d0279cded925b7ace261cdb46acdc1146d741e889002867a92752ad7c82b7b3f0fda6adb4e6075cdb9a3f21e55ecdc6eb83ba9011"},"error":""}"#);
        let result = ironfish_create_account_from_pk(String::from(""));
        assert_eq!(result, r#"{"data":"","error":"InvalidPaymentAddress"}"#);
    }

	#[test]
    fn test_ironfish_is_valid_public_address() {
        let result = ironfish_is_valid_public_address(String::from("26e687616d5e8c860aae8a7999408696369b6b2f81cb854da03f033c85d9650b"));
        assert_eq!(result, "true");
        let result = ironfish_is_valid_public_address(String::from("0x26e687616d5e8c860aae8a7999408696369b6b2f81cb854da03f033c85d9650b"));
        assert_eq!(result, "false");
    }
}
