use crate::aleo::utils::hex_to_bytes;
use crate::export;
use scrypt::{scrypt, ScryptParams};
use serde_json::json;

fn serialize_polkadot_error(err: &str) -> String {
    let result = json!({
      "error": err,
      "data": ""
    });
    result.to_string()
}

fn serialize_polkadot_data(data: &str) -> String {
    let result = json!({
      "error": "",
      "data": data
    });
    result.to_string()
}

export! {
  @Java_com_foxwallet_core_WalletCoreModule_polkadotScryptInternal
  fn polkadot_scrypt(password_str: String, salt_str: String, log2_n: u8, r: u32, p: u32) -> String {
    match ScryptParams::new(log2_n, r, p) {
        Ok(p) => {
            let mut res = [0u8; 64];
            let password_bytes = hex_to_bytes(&password_str).map_err(|e| e.to_string());
            if let Err(error) = password_bytes {
              return serialize_polkadot_error(&error);
            }

            let salt_bytes = hex_to_bytes(&salt_str).map_err(|e| e.to_string());
            if let Err(error) = salt_bytes {
              return serialize_polkadot_error(&error);
            }

            let password = password_bytes.unwrap();
            let salt = salt_bytes.unwrap();

            match scrypt(&password, &salt, &p, &mut res) {
                Ok(_) => {
                    let hash: String = res.to_vec().iter().map(|b| format!("{:02x}", b)).collect();
                    serialize_polkadot_data(&hash)
                },
                _ => panic!("Invalid scrypt hash."),
            }
        }
        _ => panic!("Invalid scrypt params."),
    }
  }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_polkadot_scrypt() {
        let expected = String::from("745731af4484f323968969eda289aeee005b5903ac561e64a5aca121797bf7734ef9fd58422e2e22183bcacba9ec87ba0c83b7a2e788f03ce0da06463433cda6");
        let password_hex = String::from("70617373776f7264");
        let salt_hex = String::from("73616c74");

        let start = Instant::now();
        let scrypt_result = polkadot_scrypt(password_hex, salt_hex, 14, 8, 1);
        let duration = start.elapsed();
        println!("Cost {:?}s to scrypt {:?}", duration, scrypt_result);

        let expected_result = serialize_polkadot_data(&expected);
        assert_eq!(expected_result, scrypt_result);
    }
}
