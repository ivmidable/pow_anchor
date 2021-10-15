const assert = require("assert");
const anchor = require("@project-serum/anchor");
var splToken = require('@solana/spl-token');
const crypto = require('crypto');
const { SystemProgram, SYSVAR_RENT_PUBKEY } = anchor.web3;

describe("PoW Anchor", () => {
    // Use a local provider.
    const provider = anchor.Provider.local();

    // Configure the client to use the local cluster.
    anchor.setProvider(provider);


    it("Initialize", async () => {
        // The program to execute.
        const pow_program = anchor.workspace.Pow;

        // The Account to create.
        const powAccount = anchor.web3.Keypair.fromSecretKey(new Uint8Array([
            114, 20, 49, 43, 197, 176, 218, 15, 29, 142, 81,
            134, 17, 87, 242, 77, 63, 102, 96, 126, 24, 18,
            218, 11, 142, 87, 178, 76, 105, 102, 213, 180, 5,
            211, 160, 249, 91, 48, 63, 227, 186, 117, 113, 120,
            174, 27, 222, 77, 78, 255, 137, 150, 78, 226, 65,
            234, 15, 46, 95, 17, 209, 200, 201, 83
        ]));

        const mint = anchor.web3.Keypair.fromSecretKey(new Uint8Array([
            242, 199, 117, 9, 209, 195, 151, 180, 130, 156, 1,
            79, 213, 129, 89, 130, 17, 45, 113, 47, 53, 90,
            38, 141, 253, 107, 121, 194, 117, 234, 181, 171, 185,
            153, 15, 71, 154, 186, 254, 178, 164, 190, 136, 81,
            233, 205, 209, 232, 93, 38, 206, 127, 167, 116, 60,
            169, 182, 7, 72, 201, 40, 250, 53, 80
        ]));

        [mintAuth, bump] = await anchor.web3.PublicKey.findProgramAddress(
            [powAccount.publicKey.toBuffer()],
            pow_program._programId,
        );


        // Create the new pow account and initialize it with the program.
        await pow_program.rpc.initialize(
            bump,
            {
                accounts: {
                    powInstance: powAccount.publicKey,
                    payer: provider.wallet.publicKey,
                    mint: mint.publicKey,
                    mintAuth: mintAuth,
                    tokenProgram: splToken.TOKEN_PROGRAM_ID,
                    systemProgram: SystemProgram.programId,
                    rent: SYSVAR_RENT_PUBKEY
                },
                signers: [powAccount, mint],
            }
        );

        // Fetch the newly created account from the cluster.
        const account = await pow_program.account.powBase.fetch(powAccount.publicKey);

        //console.log(account);
        assert.ok(account.tokenMint.toBase58() === mint.publicKey.toBase58());

        // Store the account for the next test.
        _powAccount = powAccount;
        _mint = mint;
        _mintAuth = mintAuth;
    });

    it("Mine PoW Anchor and claim SPL Tokens", async () => {
        const powAccount = _powAccount;
        const mint = _mint;
        const pow_program = anchor.workspace.Pow;
        let user = anchor.web3.Keypair.generate();

        //air drop to user acct so they can create token acct.
        let res = await provider.connection.requestAirdrop(user.publicKey, 9 * anchor.web3.LAMPORTS_PER_SOL);
        await provider.connection.confirmTransaction(res);

        //console.log(mint);
        const token_mint = new splToken.Token(provider.connection, mint.publicKey, splToken.TOKEN_PROGRAM_ID, user);
        let user_token_id = await token_mint.getOrCreateAssociatedAccountInfo(user.publicKey);

        //console.log(powAccount);
        const account_data = await pow_program.account.powBase.fetch(powAccount.publicKey);

        //mining difficulty is set to 1, so the target is 21.
        //if it was set to 2 target would be 21e8.
        //if it was set to 3 target would be 21e800
        //etc..
        let keys = mine(account_data.hash, "21");

        await pow_program.rpc.claim(
            {
                accounts: {
                    powInstance: powAccount.publicKey,
                    claimKey: keys.claim.publicKey,
                    poolKey: keys.pool.publicKey,
                    mint: mint.publicKey,
                    mintAuth: mintAuth,
                    tokenReceiver: user_token_id.address,
                    tokenProgram: splToken.TOKEN_PROGRAM_ID,
                },
                signers: [keys.claim, keys.pool],
            }
        );

        let user_token_info = await token_mint.getAccountInfo(user_token_id.address);
        
        //user wallet should have the tokens they mined.
        assert.ok(user_token_info.amount.toString() === new anchor.BN(100*anchor.web3.LAMPORTS_PER_SOL).toString());
        //if mining difficulty is set higher than 1, you need to raise this timeout limit.
    }).timeout(10000);

});

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

function mine(hash, magic) {
    let pool = anchor.web3.Keypair.generate();
    let keypair = undefined;
    let hash_buf = Buffer.from(hash, 'hex');
    while (true) {
        keypair = new anchor.web3.Keypair();
        let check = sha256(Buffer.concat([hash_buf, keypair.publicKey.toBuffer(), pool.publicKey.toBuffer()])).toString('hex');
        if (check.startsWith(magic) === true) {
            return {claim:keypair, pool:pool};
        }
    }
}
