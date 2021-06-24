package migrate

import "github.com/golang/glog"

// LoadMigrations forces GO to call init() on all the files in the package
func LoadMigrations() {
	glog.Info("Loading all migrations...")
}
