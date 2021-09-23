// Package safemode implements a wrapper for any DAG store, that refuses to load
// blacklisted content.
package safemode

import (
	logging "github.com/ipfs/go-log"
)

var log = logging.Logger("safemode")
