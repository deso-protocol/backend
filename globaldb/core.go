package globaldb

import "github.com/go-pg/pg/v10"

type GlobalDB struct {
	db *pg.DB
}

func NewGlobalDB(db *pg.DB) *GlobalDB {
	return &GlobalDB{
		db: db,
	}
}

type AuditLog struct {
}

type GlobalFeedPost struct {
}

type NodeParam struct {
}
