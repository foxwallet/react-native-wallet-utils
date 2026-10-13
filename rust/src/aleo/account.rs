use crate::export;
use super::utils::{serialize_account, serialize_aleo_error, hex_to_bytes};
use std::str::FromStr;
use std::convert::TryFrom;
use std::convert::TryInto;
use super::types::{CurrentNetwork, PrivateKeyNative, AddressNative, ViewKeyNative, Environment, FromBytes, ToBytes, PrimeField, Field, PlaintextNative};
use snarkvm_console::network::environment::traits::ToFields;
use alog::alog;

export! {
	// generate new aleo account from private key
	@Java_com_foxwallet_core_WalletCoreModule_aleoCreateAccountFromPrivateKeyInternal
	fn aleo_create_account_from_pk(
		pk: String
	) -> String {
        let private_key = PrivateKeyNative::from_str(&pk).map_err(|e| e.to_string());
        if let Err(error) = private_key {
          return serialize_aleo_error(&error)
        }
        let private_key = private_key.unwrap();
        let address = AddressNative::try_from(private_key).map_err(|e| e.to_string());
        if let Err(error) = address {
          return serialize_aleo_error(&error)
        }
        let address = address.unwrap();
        let view_key = ViewKeyNative::try_from(private_key).map_err(|e| e.to_string());
        if let Err(error) = view_key {
          return serialize_aleo_error(&error)
        }
        let view_key = view_key.unwrap();
        serialize_account(&private_key, &address, &view_key)
	}

    @Java_com_foxwallet_core_WalletCoreModule_aleoCreateAccountFromSeedInternal
    fn aleo_create_account_from_seed(
        seed_str: String
    ) -> String {
        let seed_bytes = hex_to_bytes(&seed_str).map_err(|e| e.to_string());
        if let Err(error) = seed_bytes {
          return serialize_aleo_error(&error);
        }
        let seed_bytes = seed_bytes.unwrap();
        let seed: Result<[u8; 32], _> = seed_bytes.try_into();
        if let Err(error) = seed {
          return serialize_aleo_error(&hex::encode(error))
        }
        let seed = seed.unwrap();
        let field = <<CurrentNetwork as Environment>::Field as PrimeField>::from_bytes_le_mod_order(&seed);
        let field_bytes = field.to_bytes_le().map_err(|e| e.to_string());
        if let Err(error) = field_bytes {
          return serialize_aleo_error(&error);
        }
        let field_bytes = field_bytes.unwrap();
        let field_bytes = FromBytes::read_le(&*field_bytes).map_err(|e| e.to_string());
        if let Err(error) = field_bytes {
          return serialize_aleo_error(&error)
        }
        let field_bytes = field_bytes.unwrap();
        // Cast and recover the private key from the seed.
        let private_key = PrivateKeyNative::try_from(field_bytes).map_err(|e| e.to_string());
        if let Err(error) = private_key {
          return serialize_aleo_error(&error);
        }
        let private_key = private_key.unwrap();
        let address = AddressNative::try_from(private_key).map_err(|e| e.to_string());
        if let Err(error) = address {
          return serialize_aleo_error(&error);
        }
        let address = address.unwrap();
        let view_key = ViewKeyNative::try_from(private_key).map_err(|e| e.to_string());
        if let Err(error) = view_key {
          return serialize_aleo_error(&error);
        }
        let view_key = view_key.unwrap();
        serialize_account(&private_key, &address, &view_key)
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoIsValidAddressInternal
    fn aleo_is_valid_public_address(address: String) -> String {
        if AddressNative::from_str(&address).is_ok() {
          "true".to_string()
        } else {
          "false".to_string()
        }
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoViewKeyToAddressInternal
    fn aleo_view_key_to_address(view_key: String) -> String {
        let view_key = ViewKeyNative::from_str(&view_key).unwrap();
        let address = view_key.to_address();
        address.to_string()
    }

    @Java_com_foxwallet_core_WalletCoreModule_aleoMerkleTreeHashTwoElementsInternal
    fn aleo_merkle_tree_hash_two_elements(prefix: String,left: String,right: String) -> String {
        // if (!left || !right) {
        //   throw new Error("Invalid inputs: elements cannot be empty");
        // }
        // const fields = [
        //   Field.fromString(prefix),
        //   Field.fromString(el1),
        //   Field.fromString(el2),
        // ];
        // const arrayPlaintext = Plaintext.fromString(
        //   `[${fields.map((f) => f.toString()).join(",")}]`
        // );
        //
        // return (new Poseidon4()).hash(arrayPlaintext.toFields()).toString;

        // Validate inputs are not empty, mirroring the JS check.
        if left.is_empty() || right.is_empty() {
            return serialize_aleo_error("Invalid inputs: elements cannot be empty");
        }

        // Parse the three inputs into `Field<CurrentNetwork>`, equivalent to `Field.fromString(...)`.
        let prefix_field = Field::<CurrentNetwork>::from_str(&prefix).map_err(|e| e.to_string());
        if let Err(error) = prefix_field {
            return serialize_aleo_error(&error);
        }
        let prefix_field = prefix_field.unwrap();

        let left_field = Field::<CurrentNetwork>::from_str(&left).map_err(|e| e.to_string());
        if let Err(error) = left_field {
            return serialize_aleo_error(&error);
        }
        let left_field = left_field.unwrap();

        let right_field = Field::<CurrentNetwork>::from_str(&right).map_err(|e| e.to_string());
        if let Err(error) = right_field {
            return serialize_aleo_error(&error);
        }
        let right_field = right_field.unwrap();

        // Convert fields to strings and join with commas, matching JS: fields.map((f) => f.toString()).join(",")
        let field_strings: Vec<String> = vec![prefix_field, left_field, right_field]
            .iter()
            .map(|f| f.to_string())
            .collect();
        let array_string = format!("[{}]", field_strings.join(","));

        alog!("MerkleTreeHashTwoElements {}", array_string);

        // Parse the array string as Plaintext, matching JS: Plaintext.fromString(`[${fields.map(...).join(",")}]`)
        let array_plaintext = PlaintextNative::from_str(&array_string).map_err(|e| e.to_string());
        if let Err(error) = array_plaintext {
            return serialize_aleo_error(&error);
        }
        let array_plaintext = array_plaintext.unwrap();

        // Convert Plaintext to fields, matching JS: arrayPlaintext.toFields()
        let fields = array_plaintext.to_fields().map_err(|e| e.to_string());
        if let Err(error) = fields {
            return serialize_aleo_error(&error);
        }
        let fields = fields.unwrap();

        // Use Poseidon4 to hash the fields, matching JS: (new Poseidon4()).hash(arrayPlaintext.toFields())
        let hash = <CurrentNetwork as snarkvm_console::network::Network>::hash_psd4(&fields)
            .map_err(|e| e.to_string());
        if let Err(error) = hash {
            return serialize_aleo_error(&error);
        }
        let hash = hash.unwrap();

        // On success, return the field hash as a string (matching `.toString()` in JS).
        hash.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aleo_create_account_from_pk() {
        let result = aleo_create_account_from_pk(String::from(""));
        assert_eq!(result, r#"{"data":{"privateKey":"","viewKey":"AViewKey1cxguxtKkjYnT9XDza9yTvVMxt6Ckb1Pv4ck1hppMzmCB","publicAddress":"aleo184vuwr5u7u0ha5f5k44067dd2uaqewxx6pe5ltha5pv99wvhfqxqv339h4"},"error":""}"#);
    }

    #[test]
    fn test_aleo_create_account_from_pk_fail() {
        let result = aleo_create_account_from_pk(String::from(""));
        assert_eq!(result, r#"{"error":"\"Invalid account private key length: found 42, expected 43\"","data":""}"#);
    }

    #[test]
    fn test_aleo_create_account_from_seed() {
        let result = aleo_create_account_from_seed(String::from("5326dbe98520850532ebe611d3fa616e923e87dadcf541b5928efa849a6e07f8"));
        assert_eq!(result, r#"{"data":{"privateKey":"","viewKey":"AViewKey1oGnze8LrFUgpikS5Q8TWXiHMvxMwuA1ZDivzTPsv98pG","publicAddress":"aleo1llwslvhcshwq23dqtwd84un65x5xfkfcuujsjdqzlnc8dea0eyps5ldfnt"},"error":""}"#);
    }

    #[test]
    fn test_aleo_create_account_from_seed_fail() {
        let result = aleo_create_account_from_seed(String::from("5326dbe98520850532ebe611d3fa616e923e87dadcf541b5928efa849a6e07"));
        assert_eq!(result, r#"{"error":"\"5326dbe98520850532ebe611d3fa616e923e87dadcf541b5928efa849a6e07\"","data":""}"#);
    }

    #[test]
    fn test_aleo_is_valid_public_address() {
        let result = aleo_is_valid_public_address(String::from("aleo1llwslvhcshwq23dqtwd84un65x5xfkfcuujsjdqzlnc8dea0eyps5ldfnt"));
        assert_eq!(result, "true");
    }

    #[test]
    fn test_aleo_is_valid_public_address_fail() {
        let result = aleo_is_valid_public_address(String::from("aleo1llwslvhcshwq23dqtwd84un65x5xfkfcuujsjdqzlnc8dea0eyps5lddnt"));
        assert_eq!(result, "false");
    }

    #[test]
    fn test_aleo_view_key_to_address() {
        let address = aleo_view_key_to_address(String::from("AViewKey1oGnze8LrFUgpikS5Q8TWXiHMvxMwuA1ZDivzTPsv98pG"));
        assert_eq!(address, "aleo1llwslvhcshwq23dqtwd84un65x5xfkfcuujsjdqzlnc8dea0eyps5ldfnt");
    }
}
