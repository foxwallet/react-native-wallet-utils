declare const WalletCore: {
    ironfishCreateAccount(): Promise<string>;
    ironfishCreateAccountFromPrivateKeySync(pk: string): string;
    ironfishCreateAccountFromPrivateKey(pk: string): Promise<string>;
    ironfishSignTransaction(rawTx: string, pk: string): Promise<string>;
    ironfishInitSaplingParams(mintParamsPath: string, spendParamsPath: string, outputParamsPath: string): Promise<string>;
    ironfishIsValidAddress(address: string): Promise<boolean>;
    ironfishIsValidAddressSync(address: string): string;
    aleoCreateAccountFromSeed(seed: string): Promise<string>;
    aleoCreateAccountFromSeedSync(seed: string): string;
    aleoCreateAccountFromPrivateKey(pk: string): Promise<string>;
    aleoCreateAccountFromPrivateKeySync(pk: string): string;
    aleoIsValidAddress(address: string): Promise<string>;
    aleoIsValidAddressSync(address: string): string;
    aleoMerkleTreeHashTwoElements(prefix: string, left: string, right: string): Promise<string>;
    aleoMerkleTreeHashTwoElementsSync(prefix: string, left: string, right: string): string;
    aleoDecryptRecord(ciphertext: string, vk: string): Promise<string>;
    aleoDeserializeCreditsRecord(recordStr: string): Promise<string>;
    aleoSignMessage(pk: string, message: string): Promise<string>;
    /** Offline snarkVM fee in microcredits. JSON request/response documented in README.md. */
    aleoEstimateExecutionFee(request: string): Promise<string>;
    aleoGenerateProverFiles(dir: string, rpc_url: string, network: string, program_id: string, function_name: string, prover_file_path: string, verifier_file_path: string): Promise<string>;
    aleoExecuteProgram(
        dir: string,
        rpc_url: string,
        network: string,
        pk: string,
        program_id: string,
        function_name: string,
        inputs: string,
        fee_record: string,
        base_fee: string,
        priority_fee: string,
        prover_file_path: string,
        verifier_file_path: string,
        fee_prover_file_path: string,
        fee_verifier_file_path: string
    ): Promise<string>;
    aleoParseRecord(plaintext: string): Promise<string>;
    aleoHashBhp256(str: string): Promise<string>;
    spaceMeshAddressFromPubKey(pub: string): Promise<string>;
    spaceMeshAddressFromPubKeySync(pub: string): string;
    spaceMeshStringToAddressSync(pub: string): string;
    spaceMeshCreateTransaction(pk: string, to: string, amount: string, nonce: string, gasPrice: string, genesisID: string): Promise<string>;
    spaceMeshSelfSpawnTx(pk: string, nonce: string, gasPrice: string, genesisID: string): Promise<string>;
    polkadotScrypt(params: { passphrase: string, salt: string, log2_n: number, r: number, p: number }): Promise<string>;
};

export default WalletCore;
