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
		// println!("{}", result);
        assert!(result.len() > 0);
    }

    #[test]
    fn test_ironfish_create_account_from_pk() {
        let result = ironfish_create_account_from_pk(String::from("54351d0caba1aa4a4a83a0fb4feff3152274ed4f880ed72bc25b5a52c06c33e9"));
        assert_eq!(result, r#"{"data":{"outgoingViewKey":"fb6889a983e2e59bf4ec27551b13db19afce3ee58ea599734c049e049b01b743","incomingViewKey":"4a4d8a2e0e2fde31708089ea3c61c7766c1576626f0e90aa83d75a328b09ec07","viewKey":"82fc4bd6a0cbfe423d4ba9f229a02749efb9b062a3375ccf778ec6c6defe908ba8fa5985e9e2d3cb567cd18cf8277709a4e309af4c4a2b4babfbf86b01045b97","publicAddress":"b447e2bbeeccf0d445ff672433f28dbcc5a09280931999155e912eb197719141"},"error":""}"#);
        let result = ironfish_create_account_from_pk(String::from(""));
        assert_eq!(result, r#"{"error":"InvalidPaymentAddress","data":""}"#);
    }

	#[test]
    fn test_ironfish_is_valid_public_address() {
        let result = ironfish_is_valid_public_address(String::from("26e687616d5e8c860aae8a7999408696369b6b2f81cb854da03f033c85d9650b"));
        assert_eq!(result, "true");
        let result = ironfish_is_valid_public_address(String::from("0x26e687616d5e8c860aae8a7999408696369b6b2f81cb854da03f033c85d9650b"));
        assert_eq!(result, "false");
    }
}
