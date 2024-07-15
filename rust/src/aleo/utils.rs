use super::error::AleoError;
use super::types::{AddressNative, ViewKeyNative, PrivateKeyNative, TransferType};
use serde_json::json;

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, AleoError> {
  let mut bite_iterator = hex.as_bytes().iter().map(|b| match b {
      b'0'..=b'9' => Ok(b - b'0'),
      b'a'..=b'f' => Ok(b - b'a' + 10),
      b'A'..=b'F' => Ok(b - b'A' + 10),
      _ => Err(AleoError::InvalidData),
  });
  let mut bytes = Vec::new();
  let mut high = bite_iterator.next();
  let mut low = bite_iterator.next();
  loop {
      match (high, low) {
          (Some(Ok(h)), Some(Ok(l))) => bytes.push(h << 4 | l),
          (None, None) => break,
          _ => return Err(AleoError::InvalidData),
      }
      high = bite_iterator.next();
      low = bite_iterator.next();
  }

  Ok(bytes)
}

pub fn serialize_account(pk: &PrivateKeyNative, address: &AddressNative, view_key: &ViewKeyNative) -> String {
  let result = json!({
      "data": {
          "privateKey": pk.to_string(),
          "viewKey": view_key.to_string(),
          "publicAddress": address.to_string(),
      },
      "error": "",
	});
  result.to_string()
}


pub fn serialize_aleo_error(err: &str) -> String {
  let content = format!("{:?}", err);
  let result = json!({
    "error": content,
    "data": "",
  });
  result.to_string()
}

pub fn convert_str_to_transfer_type(str: &str) -> Result<TransferType, AleoError> {
  match str {
    "private" => Ok(TransferType::Private),
    "private_to_public" => Ok(TransferType::PrivateToPublic),
    "public" => Ok(TransferType::Public),
    "public_to_private" => Ok(TransferType::PublicToPrivate),
    _ => Err(AleoError::InvalidData),
  }
}