package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// FIXME: Rewrite all these migrations and rename this file

func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		// Install the uuid extension
		_, err := db.Exec(`
			CREATE EXTENSION IF NOT EXISTS "uuid-ossp"
		`)
		if err != nil {
			return err
		}

		// Each user is identified by their public key
		//
		// phone_number: Starts with +1 for US and represents the international number
		_, err = db.Exec(`
			CREATE TABLE app_user (
                pkid_base58check       			   TEXT NOT NULL PRIMARY KEY,
                username					       TEXT NOT NULL,
                derived_pubkey_base58check         TEXT NOT NULL,
                derived_privkey_base58check        TEXT NOT NULL,

                email                              TEXT NOT NULL,
                email_verification_code            TEXT NOT NULL,
                email_is_verified                  BOOLEAN NOT NULL,

                phone_number                       TEXT NOT NULL,
                phone_number_verification_code     TEXT NOT NULL,
                phone_number_is_verified           BOOLEAN NOT NULL
			);
		`)
		if err != nil {
			return err
		}

		// A round has the following fields:
		// - round_id: A unique identifier
		// - round_name: A human-readable name set by the DAO owner
		// - round_status: {PAUSED, OPEN, FINALIZED}
		// - amount_to_raise_usd_cents: The amount in USD that the DAO owner wants to raise
		// - allow_overflow: Whether or not investments are allowed after the target has been reached
		// - off_chain_deso_balance_nanos: The total amount of DESO that has gone into this
		//   round. We store this DESO until the round is finalized, at which point it is
		//   published.
		// - reserve_rate_basis_points: A percentage of each investment that goes to the founder
		// - global_referral_rate_basis_points: The percentage of each investment that a referrer
		//   gets
		// - start_time/end_time: The period during which investments are allowed. The round is paused
		//   at the end_time, and can be extended before being finalized if desired.
		// - dao_coins_per_deso_nanos_hex: A uint256 expressing how many DAO coins are issued per
		//   DESO invested. Default is 1M DAO coins per DESO.
		// - access_password: If set, only people with the password can invest.
		// - is_investment_immediately_refundable: When set to true, investors can immediately
		//   get a refund of their investment until the round is finalized. Turning this off
		//   means investors can't get a refund while the round is OPEN, but they can get a refund
		//   afterward if the DAO owner specifies that he wants to issue refunds rather than accept
		//   the DAO funds.
		_, err = db.Exec(`
			CREATE TYPE ROUND_STATUS AS ENUM ('OPEN', 'PAUSED', 'FINALIZED');
			CREATE TABLE funding_round (
                round_id                 			UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4 (),
                round_name                 			TEXT NOT NULL,
                round_status  						ROUND_STATUS NOT NULL,
                dao_owner_pkid_base58check    	    TEXT NOT NULL,
                amount_to_raise_usd_cents 			BIGINT NOT NULL,
                allow_overflow                   	BOOLEAN NOT NULL,
                off_chain_deso_balance_nanos  		BIGINT NOT NULL,
                reserve_rate_basis_points       	BIGINT NOT NULL,
                global_referral_rate_basis_points 	BIGINT NOT NULL,
                start_time                       	TIMESTAMP,
                end_time                       		TIMESTAMP,
                dao_coins_per_deso_nanos_hex        TEXT NOT NULL,
                access_password						TEXT NOT NULL,
                is_investment_immediately_refundable            BOOLEAN NOT NULL,
								created_at			TIMESTAMP DEFAULT NOW(),
			    CONSTRAINT fk_funding_round_dao_owner_pkid
				  FOREIGN KEY(dao_owner_pkid_base58check)
				  REFERENCES app_user(pkid_base58check)
			)
		`)
		if err != nil {
			return err
		}

		// This represents an investment in a round. An investment has a few possible
		// states:
		// - status: {PENDING, FINALIZED}
		//
		// Users are issued DAO coins on-chain immediately after sending DESO. While the
		// investment is pending, investors can redeem their DAO coins for a refund of the
		// DESO they put in at any time. They can do this until the round is finalized. Note
		// that investments are immediately finalized if a DAO owner sets their round to
		// non-refundable.
		//
		// These are the rest of the fields:
		// - investment_id: A unique ID for this object
		// - round_id: The round this investment is associated with
		// - investor_pkid: The pkid of the investor
		// - amount_invested_deso_nanos: The amount of DESO the investor put in for this
		//   investment. This is the amount the investor would be refunded.
		// - amount_refunded_deso_nanos: The amount of DESO the investor has been refunded.
		//   Useful for tracking a partial refund.
		// - dao_coins_issued_hex: The number of DAO coins originally issued for this
		//   investment.
		// - dao_coins_returned_hex: The number of DAO coins the investor has redeemed back
		//   for DESO. This is how the investor gets a refund: They must redeem their DAO
		//   coins. They can only do this until the investment is finalized.
		// - referrer_pkid: The pkid of the person who referred this investment
		// - referrer_basis_points: The percentage of the DESO that the referrer will get
		//   when the round is finalized.
		// - reserve_rate_basis_points: The percentage of the DESO that the DAO owner will
		//   get when the round is finalized.
		_, err = db.Exec(`
			CREATE TYPE INVESTMENT_STATUS AS ENUM ('PENDING', 'REFUNDED', 'FINALIZED');
			CREATE TABLE investment (
                investment_id                       UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4 (),
                round_id                 			UUID NOT NULL,
                investor_pkid_base58check           TEXT NOT NULL,
                amount_invested_deso_nanos          BIGINT NOT NULL,
                amount_refunded_deso_nanos          BIGINT NOT NULL,
                dao_coins_issued_hex                TEXT NOT NULL,
                dao_coins_redeemed_hex              TEXT NOT NULL,
                status                              INVESTMENT_STATUS NOT NULL,
                referrer_pkid_base58check           TEXT NOT NULL,
                referrer_basis_points               BIGINT NOT NULL,

                reserve_rate_basis_points           BIGINT NOT NULL,

				deleted_at						   TIMESTAMPTZ
								created_at			TIMESTAMP DEFAULT NOW(),
								CONSTRAINT fk_investment_investor_pkid FOREIGN KEY(investor_pkid_base58check) REFERENCES app_user(pkid_base58check),
								CONSTRAINT fk_investment_round_id FOREIGN KEY(round_id) REFERENCES funding_round(round_id)

			)
		`)
		if err != nil {
			return err
		}

		_, err = db.Exec(`
			CREATE TABLE referral_info (
				round_id                            TEXT NOT NULL,
                referrer_pkid_base58check           TEXT NOT NULL,
				referral_basis_points_nanos			BIGINT NOT NULL,
                PRIMARY KEY(round_id, referrer_pkid_base58check)
			)
		`)
		if err != nil {
			return err
		}

		// Anyone can distribute DESO in bulk to anyone else on the platform.
		// The most common use-case for this will be a DAO owner distributing
		// DESO pro rata to DAO coin holders. In any case, a distribution can
		// require burning one's DAO coins in exchange for DESO.
		//
		// - user_pkid: The pkid of the user who is entitled to this distribution
		// - deso_owed_nanos: The amount of DESO the user is entitled to
		// - dao_owner_pkid: In the event that the user must burn DAO coins for DESO,
		//   this specifies the pkid of the DAO.
		// - dao_coins_required_hex: The number of DAO coins that are required to be burned
		//   in order to redeem the full deso_owed_nanos. Partial redemption is supported by
		//   redeeming a fraction of the dao_coins_required.
		_, err = db.Exec(`
			CREATE TABLE distribution (
                distribution_id                       TEXT NOT NULL PRIMARY KEY,
				user_pkid_base58check                 TEXT NOT NULL,
				deso_owed_nanos						  BIGINT NOT NULL,

				dao_owner_pkid_base58check            TEXT NOT NULL,
                dao_coins_required_hex                TEXT NOT NULL
			)
		`)
		if err != nil {
			return err
		}

		// For every blockchain transaction that a user needs signed - a derived key will be generated.
		// This table will track each derived key that a user generates, and the purpose for that key.
		// This table has a many -> one relationship to the app_users table to identify which user the key belongs to.
		// This table also has a many -> one relationship to the investment table when the derived key will be used to purchase the coins of a DAO.
		// This table also has a many -> one relationship to the funding round table when the derived key will be used to transfer DAO coins from the owner to investors.
		//
		// - derived_key_id: Primary key for the table.
		// - derived_public_key: Public key of the derived key pair.
		// - derived_private_key: Encrypted private key of the derived key pair.
		// - app_user_pkid_base_58_check: Foreign key to relate this table to the app_user table. Represents the user who the derived key belongs to.
		// - investment_id: Foreign key to relate this table to the investments table. Represents the investment a user is making in a DAO, where relevant.
		// - funding_round_id: Foreign key to relate this table to the funding round table. Represents the funding round a DAO is holding, where relevant.
		// - purpose: What this derived key is being used for. i.e. `invest_in_dao`, `transfer_dao_coins`, `send_diamonds`, `update_profile`
		// - status: Status of the derived key i.e. `created`, `authorized`, `expired`, `deleted`

		_, err = db.Exec(`
			CREATE TABLE derived_key (
                derived_key_id                     UUID NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4 (),

				derived_public_key                 TEXT NOT NULL,
				derived_private_key                TEXT NOT NULL,

				app_user_pkid_base58_check        TEXT NOT NULL,
				investment_id                      TEXT,
				funding_round_id                   TEXT,

				purpose						       TEXT NOT NULL,
				status                             TEXT NOT NULL,
				deleted_at						   TIMESTAMPTZ
			)
		`)
		if err != nil {
			return err
		}

		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		_, err := db.Exec(`
			DROP TABLE distribution;
			DROP TABLE referral_info;
			DROP TABLE investment;
			DROP TABLE funding_round;
			DROP TABLE app_user;
			DROP TABLE derived_key;
		`)
		return err
	})
}
