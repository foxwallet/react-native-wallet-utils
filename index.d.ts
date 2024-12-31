declare module '@foxwallet/react-native-wallet-utils' {
    export function ironfishCreateAccount(): Promise<string>;
    export function ironfishCreateAccountFromPrivateKeySync(pk: string): string;
    export function ironfishCreateAccountFromPrivateKey(pk: string): Promise<string>;
    export function ironfishSignTransaction(rawTx: string, pk: string): Promise<string>;
    export function ironfishInitSaplingParams(mintParamsPath: string, spendParamsPath: string, outputParamsPath: string): Promise<string>;
    export function ironfishIsValidAddress(address: string): Promise<boolean>;
    export function ironfishIsValidAddressSync(address: string): string;
    export function aleoCreateAccountFromSeed(seed: string): Promise<string>;
    export function aleoCreateAccountFromSeedSync(seed: string): string;
    export function aleoCreateAccountFromPrivateKey(pk: string): Promise<string>;
    export function aleoCreateAccountFromPrivateKeySync(pk: string): string;
    export function aleoIsValidAddress(address: string): Promise<string>;
    export function aleoIsValidAddressSync(address: string): string;
    export function aleoDecryptRecord(ciphertext: string, vk: string): Promise<string>;
    export function aleoDeserializeCreditsRecord(recordStr: string): Promise<string>;
    export function aleoSignMessage(pk: string, message: string): Promise<string>;
    export function aleoGenerateProverFiles(dir: string, rpc_url: string, network: string, program_id: string, function_name: string, prover_file_path: string, verifier_file_path: string): Promise<string>;
    export function aleoExecuteProgram(
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
    export function aleoParseRecord(plaintext: string): Promise<string>;
    export function aleoHashBhp256(str: string): Promise<string>;
    export function spaceMeshAddressFromPubKey(pub: string): Promise<string>;
    export function spaceMeshAddressFromPubKeySync(pub: string): string;
    export function spaceMeshStringToAddressSync(pub: string): string;
    export function spaceMeshCreateTransaction(pk: string, to: string, amount: string, nonce: string, gasPrice: string, genesisID: string): Promise<string>;
    export function spaceMeshSelfSpawnTx(pk: string, nonce: string, gasPrice: string, genesisID: string): Promise<string>;
    export function polkadotScrypt(params: { passphrase: string, salt: string, log2_n: number, r: number, p: number }): Promise<string>;
}
