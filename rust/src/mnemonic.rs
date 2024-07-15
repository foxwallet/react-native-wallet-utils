// Copyright 2021-2021 FoxWallet.

use bip39::{Language, Mnemonic, MnemonicType};
use crate::export;

export! {
	@Java_com_foxwallet_core_WalletCoreModule_ethkeyRandomPhrase
	fn random_phrase(
		words_number:u32
	) -> String {
		let mnemonic_type = match MnemonicType::for_word_count(words_number as usize) {
			Ok(t) => t,
			Err(_e) => MnemonicType::Words24,
		};
		let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
		mnemonic.into_phrase()
	}
}

#[cfg(test)]
mod tests {
    use super::*;

	#[test]
	fn test_random_phrase() {
		let result_12 = random_phrase(12);
		assert_eq!(12, result_12.split_whitespace().count());
		let result_24 = random_phrase(24);
		assert_eq!(24, result_24.split_whitespace().count());
		let result_17 = random_phrase(17);
		assert_eq!(24, result_17.split_whitespace().count());
	}
}
