use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    hash::hash,
    native_token::{lamports_to_sol, sol_to_lamports},
};
use std::convert::TryInto;

use anchor_spl::token::{self, Mint, MintTo, TokenAccount};

declare_id!("7TM227WVFEwEjWdk3euwyd1JdjTs4wyDCy6euRzz5M5T");

#[program]
pub mod pow {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> ProgramResult {
        let pow_inst = &mut ctx.accounts.pow_instance;

        let clock = Clock::get()?;
        pow_inst.epoch = clock.epoch;
        pow_inst.token_mint = ctx.accounts.mint.key();
        pow_inst.mined_count = 0;
        pow_inst.mined_this_epoch = 0;
        pow_inst.diff = 1;
        pow_inst.tokens = sol_to_lamports(100 as f64);
        pow_inst.bump = bump;
        pow_inst.hash = create_hash(&clock, pow_inst, &pow_inst.key())
            .try_into()
            .unwrap();
        Ok(())
    }

    pub fn claim(ctx: Context<Claim>) -> ProgramResult {
        let pow_inst = &mut ctx.accounts.pow_instance;

        let clock = Clock::get()?;

        if clock.epoch.checked_sub(pow_inst.epoch).unwrap() > 0 {
            pow_inst.epoch = clock.epoch;
            pow_inst.mined_this_epoch = 0;
            if pow_inst.mined_this_epoch >= 1320 {
                pow_inst.diff = pow_inst.diff.checked_add(1).unwrap();
                pow_inst.tokens = pow_inst.tokens/2;
            }
        }

        if pow_inst.mined_this_epoch >= 1320 {
            return Err(ErrorCode::MaxMinedEpoch.into());
        }

        check_claim(
            ctx.accounts.claim_key.key,
            ctx.accounts.pool_key.key,
            &pow_inst.hash,
            &pow_inst.diff,
        )?;

        let cpi_program = ctx.accounts.token_program.to_account_info();

        let cpi_accounts = MintTo {
            mint: ctx.accounts.mint.to_account_info().clone(),
            to: ctx.accounts.token_receiver.to_account_info().clone(),
            authority: ctx.accounts.mint_auth.clone(),
        };

        let seeds = &[pow_inst.to_account_info().key.as_ref(), &[pow_inst.bump]];

        let signer = &[&seeds[..]];

        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer);

        anchor_spl::token::mint_to(cpi_ctx, pow_inst.tokens)?;

        pow_inst.hash = create_hash(&clock, pow_inst, &pow_inst.key())
            .try_into()
            .unwrap();

        Ok(())
    }
}

pub fn create_hash(clock: &Clock, instance: &PowBase, instance_id: &Pubkey) -> Vec<u8> {
    let mut data_vec = instance_id.to_bytes().to_vec();
    data_vec.extend_from_slice(&instance.token_mint.to_bytes());
    data_vec.extend_from_slice(&instance.mined_count.to_le_bytes());
    data_vec.extend_from_slice(&clock.slot.to_le_bytes());
    data_vec.extend_from_slice(&clock.epoch.to_le_bytes());
    data_vec.extend_from_slice(&clock.unix_timestamp.to_le_bytes());
    let hash_vec = hash(data_vec.as_slice()).to_bytes().to_vec();
    return hash_vec;
}

pub fn check_claim(
    claim_id: &Pubkey,
    pool_id: &Pubkey,
    sha256: &[u8; 32],
    diff: &u8,
) -> ProgramResult {
    let mut magic_raw: [u8; 32] = [0; 32];
    magic_raw[0] = 33;
    magic_raw[1] = 232;
    let (magic, _rest) = magic_raw.split_at(*diff as usize);
    let mut data_vec = sha256.to_vec();
    data_vec.extend_from_slice(&claim_id.to_bytes());
    data_vec.extend_from_slice(&pool_id.to_bytes());
    let hash_vec = hash(data_vec.as_slice()).to_bytes().to_vec();
    if hash_vec.starts_with(magic) == false {
        return Err(ErrorCode::InvalidClaimHash.into());
    }
    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = 8+32+8+8+8+32+1+8+1)]
    pub pow_instance: Account<'info, PowBase>,
    #[account(init, payer = payer, mint::decimals = 9, mint::authority = mint_auth)]
    pub mint: Account<'info, Mint>,
    #[account(signer)]
    pub payer: AccountInfo<'info>,
    pub mint_auth: AccountInfo<'info>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
    pub system_program: AccountInfo<'info>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub pow_instance: Account<'info, PowBase>,
    #[account(signer)]
    pub claim_key: AccountInfo<'info>,
    #[account(signer)]
    pub pool_key: AccountInfo<'info>,
    #[account(mut)]
    pub mint: Account<'info, Mint>,
    #[account(mut, has_one = mint)]
    pub token_receiver: Account<'info, TokenAccount>,
    #[account(address = token::ID)]
    pub token_program: AccountInfo<'info>,
    pub mint_auth: AccountInfo<'info>,
}

//8+32+8+8+8+32+1+8+1
#[account]
pub struct PowBase {
    pub token_mint: Pubkey,
    pub epoch: u64,
    pub mined_count: u64,
    pub mined_this_epoch: u64,
    pub hash: [u8; 32],
    pub diff: u8,
    pub tokens: u64,
    pub bump: u8,
}

#[error]
pub enum ErrorCode {
    #[msg("Account does not have correct owner.")]
    IncorrectOwner,
    #[msg("Account is not initialized.")]
    Uninitialized,
    #[msg("Init Authority is invalid.")]
    InvalidInitAuth,
    #[msg("Claim hash is invalid.")]
    InvalidClaimHash,
    #[msg("Maxmium ammount mined this epoch.")]
    MaxMinedEpoch,
}
