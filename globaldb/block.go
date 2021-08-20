package globaldb

import "github.com/bitclout/core/lib"

type Block struct {
	PublicKey        *lib.PublicKey `pg:",pk"`
	BlockedPublicKey *lib.PublicKey `pg:",pk"`
	BlockedAt        uint64
}

func (global *GlobalDB) GetBlocks(publicKey *lib.PublicKey) []*Block {
	var blocks []*Block
	err := global.db.Model(&blocks).Where("public_key = ?", publicKey).Select()
	if err != nil {
		return nil
	}
	return blocks
}
