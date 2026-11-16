//! Offline execution fees using the same cost functions as the official Aleo SDK.
use super::types::{
    AddressNative, CurrentAleo, CurrentNetwork, IdentifierNative, PrivateKeyNative, ProcessNative,
    ProgramIDNative, ProgramNative, ValueNative, ValueType,
};
use super::utils::serialize_aleo_error;
use crate::export;
use anyhow::{ensure, Result};
use serde::Deserialize;
use serde_json::json;
use snarkvm_console::network::Network;
use snarkvm_synthesizer::{
    prelude::{execution_cost_for_authorization, execution_cost_for_call},
    program::StackTrait,
};
use std::convert::TryFrom;
use std::str::FromStr;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FeeProgram {
    id: String,
    source: String,
    edition: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FeeRequest {
    network: String,
    block_height: u32,
    program_id: String,
    function_name: String,
    // Dependencies first, then the root program. credits.aleo is built into Process.
    #[serde(default)]
    programs: Vec<FeeProgram>,
    // Optional real inputs stay on the device. No user private key is needed.
    inputs: Option<Vec<String>>,
    address: Option<String>,
}

fn estimate(request: &str) -> Result<serde_json::Value> {
    let request: FeeRequest = serde_json::from_str(request)?;
    ensure!(
        request.network == "mainnet",
        "Fee estimator supports mainnet only"
    );
    ensure!(
        request.programs.len() <= 128,
        "Too many fee estimation programs"
    );
    let consensus = CurrentNetwork::CONSENSUS_VERSION(request.block_height)?;
    ensure!(
        consensus >= snarkvm_console::network::ConsensusVersion::V4,
        "Fee estimation requires consensus V4 or later"
    );
    let process = ProcessNative::load()?;
    for entry in request.programs {
        let program = ProgramNative::from_str(&entry.source)?;
        ensure!(
            program.id().to_string() == entry.id,
            "Fee program ID mismatch"
        );
        ensure!(entry.id != "credits.aleo", "credits.aleo is built in");
        ensure!(
            !process.contains_program(program.id()),
            "Duplicate fee program"
        );
        process
            .lock()
            .add_program_with_edition(&program, entry.edition)?;
    }
    let program_id = ProgramIDNative::from_str(&request.program_id)?;
    let function = IdentifierNative::from_str(&request.function_name)?;
    let stack = process.get_stack(program_id)?;
    let rng = &mut rand::rng();
    let (base_fee, (storage_fee, finalize_fee)) = if let Some(inputs) = request.inputs {
        let address = AddressNative::from_str(
            request
                .address
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Address required with real inputs"))?,
        )?;
        let inputs = inputs
            .iter()
            .map(|value| ValueNative::from_str(value))
            .collect::<Result<Vec<_>>>()?;
        execution_cost_for_call::<CurrentAleo, _>(
            &process,
            address,
            program_id,
            function,
            inputs.iter(),
            consensus,
            rng,
        )?
    } else {
        ensure!(
            !stack.contains_dynamic_call(&function)?,
            "Dynamic calls require real inputs"
        );
        // Match ProgramManager.estimateExecutionFee with a disposable key and sampled inputs.
        let burner = PrivateKeyNative::new(rng)?;
        let address = AddressNative::try_from(&burner)?;
        let mut inputs = Vec::new();
        for input in stack.get_function(&function)?.input_types() {
            let value = match input {
                ValueType::ExternalRecord(locator) => {
                    process.get_stack(locator.program_id())?.sample_value(
                        &address,
                        &ValueType::Record(*locator.resource()).into(),
                        rng,
                    )?
                }
                _ => stack.sample_value(&address, &input.into(), rng)?,
            };
            inputs.push(value);
        }
        let authorization = process.authorize::<CurrentAleo, _>(
            &burner,
            program_id,
            function,
            inputs.iter(),
            rng,
        )?;
        execution_cost_for_authorization(&process, &authorization, consensus)?
    };
    Ok(json!({
        "baseFee": base_fee.to_string(),
        "storageFee": storage_fee.to_string(),
        "finalizeFee": finalize_fee.to_string(),
        "blockHeight": request.block_height,
        "consensusVersion": format!("{:?}", consensus),
    }))
}

export! {
    @Java_com_foxwallet_core_WalletCoreModule_aleoEstimateExecutionFeeInternal
    fn aleo_estimate_execution_fee(request: String) -> String {
        match estimate(&request) {
            Ok(data) => json!({ "data": data, "error": "" }).to_string(),
            Err(error) => serialize_aleo_error(&error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(function: &str, height: u32) -> serde_json::Value {
        json!({"network": "mainnet", "programId": "credits.aleo", "functionName": function, "blockHeight": height})
    }

    #[test]
    fn credits_fees_use_chain_consensus_and_microcredits() {
        for function in [
            "transfer_private",
            "transfer_private_to_public",
            "transfer_public",
            "transfer_public_to_private",
            "join",
        ] {
            let fee = estimate(&request(function, 23_715_963).to_string()).unwrap();
            let base = fee["baseFee"].as_str().unwrap().parse::<u64>().unwrap();
            let storage = fee["storageFee"].as_str().unwrap().parse::<u64>().unwrap();
            let finalize = fee["finalizeFee"].as_str().unwrap().parse::<u64>().unwrap();
            assert_eq!(base, storage + finalize);
            assert!(base > 0);
        }
        let old = estimate(&request("transfer_public", 7_000_000).to_string()).unwrap();
        let current = estimate(&request("transfer_public", 23_715_963).to_string()).unwrap();
        assert_ne!(old["consensusVersion"], current["consensusVersion"]);
        assert_ne!(old["baseFee"], current["baseFee"]);
    }

    #[test]
    fn actual_inputs_need_no_user_private_key() {
        let address =
            AddressNative::try_from(&PrivateKeyNative::new(&mut rand::rng()).unwrap()).unwrap();
        let mut req = request("transfer_public", 23_715_963);
        req["address"] = json!(address.to_string());
        req["inputs"] = json!([address.to_string(), "1u64"]);
        assert_eq!(
            estimate(&req.to_string()).unwrap()["baseFee"],
            estimate(&request("transfer_public", 23_715_963).to_string()).unwrap()["baseFee"]
        );
    }

    #[test]
    fn imports_and_editions_are_loaded_before_the_root() {
        let mut req = request("run", 23_715_963);
        req["programId"] = json!("fee_root.aleo");
        req["programs"] = json!([
            {"id":"fee_dep.aleo", "edition":1, "source":"program fee_dep.aleo;\nfunction run:\n input r0 as u64.public;\n add r0 1u64 into r1;\n output r1 as u64.public;"},
            {"id":"fee_root.aleo", "edition":1, "source":"import fee_dep.aleo;\nprogram fee_root.aleo;\nfunction run:\n input r0 as u64.public;\n call fee_dep.aleo/run r0 into r1;\n output r1 as u64.public;"}
        ]);
        assert!(
            estimate(&req.to_string()).unwrap()["baseFee"]
                .as_str()
                .unwrap()
                .parse::<u64>()
                .unwrap()
                > 0
        );
        req["programs"][0]["id"] = json!("wrong.aleo");
        assert!(estimate(&req.to_string())
            .unwrap_err()
            .to_string()
            .contains("ID mismatch"));
    }

    #[test]
    fn invalid_requests_return_bridge_errors() {
        for req in [
            "{}".to_string(),
            request("missing", 23_715_963).to_string(),
            request("transfer_public", 0).to_string(),
        ] {
            let result: serde_json::Value =
                serde_json::from_str(&aleo_estimate_execution_fee(req)).unwrap();
            assert!(!result["error"].as_str().unwrap().is_empty());
        }
        let mut req = request("transfer_public", 23_715_963);
        req["network"] = json!("testnet");
        assert!(estimate(&req.to_string()).is_err());
    }
}
