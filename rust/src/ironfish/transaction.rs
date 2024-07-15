use serde::{Deserialize};
use ironfish_rust::{
    sapling_bls12::Scalar,
    witness::{Witness, WitnessNode},
    Note, ProposedTransaction,
    SaplingKey,
};
use subtle::{CtOption};
use crate::export;
use super::utils::{serialize_string_result, serialize_bool_result};
use std::str;
use ironfish_rust::{sapling_bls12::SaplingWrapper};

// pub const MAX_MINT_OR_BURN_VALUE: u64 = 100_000_000_000_000_000;

#[derive(Debug, Deserialize)]
pub struct Mint {
    pub name: String,
    pub metadata: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Burn {
    pub asset_id: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct Output {
    pub note: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPath {
    pub side: String,
    pub hash_of_sibling: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WitnessData {
    pub tree_size: u32,
    pub root_hash: String,
    pub auth_path: Vec<AuthPath>,
}
#[derive(Debug, Deserialize)]
pub struct Spend {
    pub note: String,
    pub witness: WitnessData,
}

#[derive(Debug, Deserialize)]
pub struct RawTransaction {
    pub expiration: u32,
    pub fee: String,
    // pub mints: Vec<Mint>,
    // pub burns: Vec<Burn>,
    pub outputs: Vec<Output>,
    pub spends: Vec<Spend>
}

fn convert_ctoption_to_result<T>(option: CtOption<T>) -> Result<T, &'static str> {
    if bool::from(option.is_some()) {
        Ok(option.unwrap())
    } else {
        Err("Parse scalar error")
    }
}

fn ironfish_sign_transaction_internal(raw_tx_str: String, spend_key: String) -> Result<String, String> {
    let tx: RawTransaction = serde_json::from_str(&raw_tx_str).map_err(|e| e.to_string())?;
    let sapling_key = SaplingKey::from_hex(&spend_key).map_err(|e| e.to_string())?;
    let _ = sapling_key.public_address();
    let mut builder = ProposedTransaction::new(sapling_key);
    let RawTransaction { expiration, fee, outputs, spends  } = tx;
    for spend in spends.iter() {
        let Spend { note, witness } = spend;
        let note_item = {
            let data = hex::decode(note).map_err(|e| e.to_string())?;
            Note::read(&data[..]).map_err(|e| e.to_string())?
        };
        let auth_path = &witness.auth_path;
        let mut auth_path_res: Vec<WitnessNode<Scalar>> = vec![];
        for item in auth_path.iter() {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(&item.hash_of_sibling, &mut bytes).map_err(|e| e.to_string())?;
            let sc = convert_ctoption_to_result(Scalar::from_bytes(&bytes))?;
            let res_item = if item.side.as_str() == "Left" {
                WitnessNode::Left(sc)
            } else {
                WitnessNode::Right(sc)
            };
            auth_path_res.push(res_item);
        }
        let witness_item = Witness {
            tree_size: witness.tree_size as usize,
            root_hash: {
                let mut bytes = [0u8; 32];
                hex::decode_to_slice(&witness.root_hash, &mut bytes).map_err(|e| e.to_string())?;
                convert_ctoption_to_result(Scalar::from_bytes(&bytes))?
            },
            auth_path: auth_path_res,
        };
        builder.add_spend(note_item, &witness_item).map_err(|e| e.to_string())?;
    }

    for output in outputs.iter() {
        let Output { note } = output;
        let note_item = {
            let data = hex::decode(note).map_err(|e| e.to_string())?;
            Note::read(&data[..]).map_err(|e| e.to_string())?
        };
        builder.add_output(note_item).map_err(|e| e.to_string())?;
    }

    builder.set_expiration(expiration);
    let transaction = builder.post(None, fee.parse::<u64>().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    transaction.verify().map_err(|e| e.to_string())?;
    let mut vec: Vec<u8> = vec![];
    transaction.write(&mut vec).map_err(|e| e.to_string())?;
    let signed_transaction = hex::encode(vec);
    Ok(signed_transaction)
}


export! {
	// sign ironfish transaction
	@Java_com_foxwallet_core_WalletCoreModule_ironfishSignTransactionInternal
	fn ironfish_sign_transaction(raw_tx_str: String, spend_key: String) -> String {
        let res = ironfish_sign_transaction_internal(raw_tx_str, spend_key);
        serialize_string_result(res)
    }

    @Java_com_foxwallet_core_WalletCoreModule_ironfishInitSaplingParamsInternal
    fn ironfish_init_sapling_params(mint_params_path: String, spend_params_path: String, output_params_path: String) -> String {
        let res = SaplingWrapper::load(mint_params_path, spend_params_path, output_params_path);
        serialize_bool_result(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_sign_tx() {
        let raw_tx_str = r#"{"expiration":18245,"fee":"1","mints":[],"burns":[],"outputs":[{"note":"7573123a52790b1730d36a6cf327bcc1f0e720db647bff9142cab20a7f153c7051f33a2f14f92735e562dc658a5639279ddca3d5079a6d1242b2a588a9cbf44c809698000000000073576552b0d625b182869e5eae5ed495ace8d943c7a0eba4d2e952a811cc5000000000000000000000000000000000000000000000000000000000000000000086d137aa309cea78fc86b571de5e88e2900ff3f50d5e9f098e5c93461a38d8da"}],"spends":[{"note":"86d137aa309cea78fc86b571de5e88e2900ff3f50d5e9f098e5c93461a38d8da51f33a2f14f92735e562dc658a5639279ddca3d5079a6d1242b2a588a9cbf44c00e1f50500000000e6a710ac1d5e3b59c6b6a1f58bbcc279e76772d9377786d7b631433318a9e5030000000000000000000000000000000000000000000000000000000000000000741b089d588f3f272b7cac7450f755ddce55d50543657206d4bbb2be0009542c","witness":{"treeSize":82544,"rootHash":"0c35f6566eefd5fb18c9624cdebdcc48843943e535e59cd68542c87f649f6763","authPath":[{"side":"Left","hashOfSibling":"37da8a9b7e4be28b7047e81cecc958103503087121a9365324039239f19bd82c"},{"side":"Right","hashOfSibling":"62d2060c2e87d422ec69e45373453e88c81c5b440827725217c3daf0392b5153"},{"side":"Right","hashOfSibling":"e2d0407812994350c55c724f495ec202d67dba3cab6914006341f9b4342c7304"},{"side":"Right","hashOfSibling":"d52f383b9d5c73a3d19844926f5fea5ecbee8616ae8b49f710381871cedacf02"},{"side":"Left","hashOfSibling":"5c278666fdc0b57698158c90ec38c659b07369f89a1e6e25ebb3f657b0906f2a"},{"side":"Left","hashOfSibling":"f4e5521f6fdaa37cb78be740d60549955feae851bfddf0574a404d89e7ed9626"},{"side":"Right","hashOfSibling":"a2e385af08aa7359ef5c98857a5a4cea447182ae343d5369433e6392ca46fb44"},{"side":"Right","hashOfSibling":"a15c0f1f7c0a24eb476d4806e8246b6acfeb5150f53434403abb48c40fd38565"},{"side":"Right","hashOfSibling":"9321d07b244b4c8c111ba7f4035f674d706354806550bc20af12893b17533a2d"},{"side":"Left","hashOfSibling":"3eb43f3ad5325d6fb2da0f46ab42e9742469889beb37faaf1193df7c38c15168"},{"side":"Left","hashOfSibling":"05a909ae8475a4028f808a07a7af75ff1961fb7aee2b2f6a59f74f7064071b4a"},{"side":"Right","hashOfSibling":"1899adf6c0e1db7243bde5d2ff368a498dcbfaf2a1963ab3b527dcc2c21ed45c"},{"side":"Right","hashOfSibling":"2236c6e308e5d17dd157841e71acd9463361b3ac3b2f300ce802929565a3672b"},{"side":"Right","hashOfSibling":"f21f144fb4c99cdda3380f9211931c2ed9bec7ce02142611d0fa0611b5e05a2d"},{"side":"Right","hashOfSibling":"39ffa391c2cc1707b1fde9fa255471a354404ff45c56236ddddf79b902e03a04"},{"side":"Left","hashOfSibling":"7f9b5d36ea78fe7624c0491d42d1ae44524f60de28e262d4f53423a53f6ff86b"},{"side":"Left","hashOfSibling":"abf55ad461493d3f72ce4fff5ad1acd6673c1e720b21b76cc2d60b9604d77e41"},{"side":"Left","hashOfSibling":"edcedd08e3e966814802fca4dbb7417684c01371aab6425383f7864b6f95f748"},{"side":"Left","hashOfSibling":"63128a88dab2212d22784c1ee03379a29a82a142fcc92f63eecfc7be78175f52"},{"side":"Left","hashOfSibling":"884142f2efceb9e401e3b132a9ee699598f20280b632f7ca2fe558a3653d124b"},{"side":"Left","hashOfSibling":"ebb2fec52a6f91044c77129baf5d3061065a85bbe6a2f8a71514b7a93f4f6860"},{"side":"Left","hashOfSibling":"de33ffd763b9428830c9a28d6910aef21a59f923a8e841400cd015fba1687361"},{"side":"Left","hashOfSibling":"41659985813be886a9c613513eb4f2b8433d9c90cc33f42c587139163ba26754"},{"side":"Left","hashOfSibling":"6431f75411a2f56351f7effad9375a747b34bc2d2b227f1a4f5a6e782e0c3d3e"},{"side":"Left","hashOfSibling":"4a2c154c27d80135563d2d6165a0626377c4f11e932b26809521035559282d1e"},{"side":"Left","hashOfSibling":"0e21935c7f6803c5498da448ad896deeea96ac003da2d8defec3a204a10ac95b"},{"side":"Left","hashOfSibling":"ba9b9efa06e08ec61c96f63e58847e5b28b4239752ade0e48b7f44b21a85a06e"},{"side":"Left","hashOfSibling":"ec99cb026552485e8364b3de4ad858625772bfdf99fc1358a57eb43d26c0673e"},{"side":"Left","hashOfSibling":"7d58e27ca1db6f5afb46cd43419ec77ed25796502c7f06f3d64c856af3a31c62"},{"side":"Left","hashOfSibling":"8be458528fafcb94087031ebf316a1ed880ce99ed5c17730be4b66a4e8dc1a57"},{"side":"Left","hashOfSibling":"4eeff7a882e1582fec3cd8c1ff0cde691c60aba72ef6223a4f2acfc02fd2331f"},{"side":"Left","hashOfSibling":"0df6ff3d16d0c66f57d6675c2c18642ee670404db36110101634ce81fbeac75f"}]}}]}"#;
        let spend_key = "";
        let start = Instant::now();
        let res = ironfish_init_sapling_params("./src/sapling_params/sapling-mint.params".to_string(), "./src/sapling_params/sapling-spend.params".to_string(), "./src/sapling_params/sapling-output.params".to_string());
        assert_eq!(res, r#"{"data":"true","error":""}"#);
        let res = ironfish_sign_transaction(raw_tx_str.to_string(), spend_key.to_string());
        let elapsed = start.elapsed();
        println!("Millis: {} ms", elapsed.as_millis());
        assert!(res.contains(r#""error":"""#));
    }

    #[test]
    fn test_sign_tx_error() {
        let wrong_tx_str = r#"{expiration:18245,"fee":"1","mints":[],"burns":[],"outputs":[{"note":"7573123a52790b1730d36a6cf327bcc1f0e720db647bff9142cab20a7f153c7051f33a2f14f92735e562dc658a5639279ddca3d5079a6d1242b2a588a9cbf44c809698000000000073576552b0d625b182869e5eae5ed495ace8d943c7a0eba4d2e952a811cc5000000000000000000000000000000000000000000000000000000000000000000086d137aa309cea78fc86b571de5e88e2900ff3f50d5e9f098e5c93461a38d8da"}],"spends":[{"note":"86d137aa309cea78fc86b571de5e88e2900ff3f50d5e9f098e5c93461a38d8da51f33a2f14f92735e562dc658a5639279ddca3d5079a6d1242b2a588a9cbf44c00e1f50500000000e6a710ac1d5e3b59c6b6a1f58bbcc279e76772d9377786d7b631433318a9e5030000000000000000000000000000000000000000000000000000000000000000741b089d588f3f272b7cac7450f755ddce55d50543657206d4bbb2be0009542c","witness":{"treeSize":82544,"rootHash":"0c35f6566eefd5fb18c9624cdebdcc48843943e535e59cd68542c87f649f6763","authPath":[{"side":"Left","hashOfSibling":"37da8a9b7e4be28b7047e81cecc958103503087121a9365324039239f19bd82c"},{"side":"Right","hashOfSibling":"62d2060c2e87d422ec69e45373453e88c81c5b440827725217c3daf0392b5153"},{"side":"Right","hashOfSibling":"e2d0407812994350c55c724f495ec202d67dba3cab6914006341f9b4342c7304"},{"side":"Right","hashOfSibling":"d52f383b9d5c73a3d19844926f5fea5ecbee8616ae8b49f710381871cedacf02"},{"side":"Left","hashOfSibling":"5c278666fdc0b57698158c90ec38c659b07369f89a1e6e25ebb3f657b0906f2a"},{"side":"Left","hashOfSibling":"f4e5521f6fdaa37cb78be740d60549955feae851bfddf0574a404d89e7ed9626"},{"side":"Right","hashOfSibling":"a2e385af08aa7359ef5c98857a5a4cea447182ae343d5369433e6392ca46fb44"},{"side":"Right","hashOfSibling":"a15c0f1f7c0a24eb476d4806e8246b6acfeb5150f53434403abb48c40fd38565"},{"side":"Right","hashOfSibling":"9321d07b244b4c8c111ba7f4035f674d706354806550bc20af12893b17533a2d"},{"side":"Left","hashOfSibling":"3eb43f3ad5325d6fb2da0f46ab42e9742469889beb37faaf1193df7c38c15168"},{"side":"Left","hashOfSibling":"05a909ae8475a4028f808a07a7af75ff1961fb7aee2b2f6a59f74f7064071b4a"},{"side":"Right","hashOfSibling":"1899adf6c0e1db7243bde5d2ff368a498dcbfaf2a1963ab3b527dcc2c21ed45c"},{"side":"Right","hashOfSibling":"2236c6e308e5d17dd157841e71acd9463361b3ac3b2f300ce802929565a3672b"},{"side":"Right","hashOfSibling":"f21f144fb4c99cdda3380f9211931c2ed9bec7ce02142611d0fa0611b5e05a2d"},{"side":"Right","hashOfSibling":"39ffa391c2cc1707b1fde9fa255471a354404ff45c56236ddddf79b902e03a04"},{"side":"Left","hashOfSibling":"7f9b5d36ea78fe7624c0491d42d1ae44524f60de28e262d4f53423a53f6ff86b"},{"side":"Left","hashOfSibling":"abf55ad461493d3f72ce4fff5ad1acd6673c1e720b21b76cc2d60b9604d77e41"},{"side":"Left","hashOfSibling":"edcedd08e3e966814802fca4dbb7417684c01371aab6425383f7864b6f95f748"},{"side":"Left","hashOfSibling":"63128a88dab2212d22784c1ee03379a29a82a142fcc92f63eecfc7be78175f52"},{"side":"Left","hashOfSibling":"884142f2efceb9e401e3b132a9ee699598f20280b632f7ca2fe558a3653d124b"},{"side":"Left","hashOfSibling":"ebb2fec52a6f91044c77129baf5d3061065a85bbe6a2f8a71514b7a93f4f6860"},{"side":"Left","hashOfSibling":"de33ffd763b9428830c9a28d6910aef21a59f923a8e841400cd015fba1687361"},{"side":"Left","hashOfSibling":"41659985813be886a9c613513eb4f2b8433d9c90cc33f42c587139163ba26754"},{"side":"Left","hashOfSibling":"6431f75411a2f56351f7effad9375a747b34bc2d2b227f1a4f5a6e782e0c3d3e"},{"side":"Left","hashOfSibling":"4a2c154c27d80135563d2d6165a0626377c4f11e932b26809521035559282d1e"},{"side":"Left","hashOfSibling":"0e21935c7f6803c5498da448ad896deeea96ac003da2d8defec3a204a10ac95b"},{"side":"Left","hashOfSibling":"ba9b9efa06e08ec61c96f63e58847e5b28b4239752ade0e48b7f44b21a85a06e"},{"side":"Left","hashOfSibling":"ec99cb026552485e8364b3de4ad858625772bfdf99fc1358a57eb43d26c0673e"},{"side":"Left","hashOfSibling":"7d58e27ca1db6f5afb46cd43419ec77ed25796502c7f06f3d64c856af3a31c62"},{"side":"Left","hashOfSibling":"8be458528fafcb94087031ebf316a1ed880ce99ed5c17730be4b66a4e8dc1a57"},{"side":"Left","hashOfSibling":"4eeff7a882e1582fec3cd8c1ff0cde691c60aba72ef6223a4f2acfc02fd2331f"},{"side":"Left","hashOfSibling":"0df6ff3d16d0c66f57d6675c2c18642ee670404db36110101634ce81fbeac75f"}]}}]}"#;
        let spend_key = "";
        let res = ironfish_init_sapling_params("./src/sapling_params/sapling-mint.params".to_string(), "./src/sapling_params/sapling-spend.params".to_string(), "./src/sapling_params/sapling-output.params".to_string());
        assert_eq!(res, r#"{"data":"true","error":""}"#);
        let res = ironfish_sign_transaction(wrong_tx_str.to_string(), spend_key.to_string());
        assert!(res.contains(r#""data":"""#));
    }

}
