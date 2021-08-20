package globaldb

import (
	"github.com/bitclout/core/lib"
)

type User struct {
	PublicKey       *lib.PublicKey `pg:",pk"`
	HideEverywhere  bool           `pg:",use_zero"`
	HideLeaderboard bool           `pg:",use_zero"`
	Email           string         ``
	EmailVerified   bool           `pg:",use_zero"`
	PhoneNumber     string         ``
	PhoneCountry    string         ``
	PhoneVerified   bool           `pg:",use_zero"`
	WhitelistPosts  bool           `pg:",use_zero"`
	Verified        bool           `pg:",use_zero"`
	Graylisted      bool           `pg:",use_zero"`
	Blacklisted     bool           `pg:",use_zero"`
}

func (global *GlobalDB) GetUser(publicKey *lib.PublicKey) *User {
	var user *User
	err := global.db.Model(&user).Where("public_key = ?", publicKey).Select()
	if err != nil {
		return nil
	}
	return user
}
