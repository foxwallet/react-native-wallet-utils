use ironfish_rust::{SaplingKey, errors::IronfishError};
use serde_json::json;

pub fn serialize_sampling_key(key: &SaplingKey) -> String {
    // let spending_key = key.hex_spending_key();
    let outgoing_view_key = key.outgoing_view_key().hex_key();
    let incoming_view_key = key.incoming_view_key().hex_key();
    let view_key = key.view_key().hex_key();
    let address = key.public_address().hex_public_address();
    let result = json!({
        "data": {
            // "spendingKey": spending_key,
            "outgoingViewKey": outgoing_view_key,
            "incomingViewKey": incoming_view_key,
            "viewKey": view_key,
            "publicAddress": address,
        },
        "error": "",
	});
    result.to_string()
}

pub fn serialize_ironfish_error(err: &IronfishError) -> String {
    let content = format!("{:?}", err);
    let result = json!({
		"error": content,
        "data": "",
	});
    result.to_string()
}

pub fn serialize_string_result(res: Result<String, String>) -> String {
    match res {
        Ok(data) => json!({ "data": data, "error": "" }).to_string(),
        Err(err) => json!({ "data": "", "error": err }).to_string(),
    }
}

pub fn serialize_bool_result(res: Result<bool, String>) -> String {
    match res {
        Ok(data) => json!({ "data": data.to_string(), "error": "" }).to_string(),
        Err(err) => json!({ "data": "", "error": err }).to_string(),
    }
}