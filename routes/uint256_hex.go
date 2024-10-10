package routes

import (
	"encoding/json"
	"github.com/holiman/uint256"
)

// Uint256Hex is a wrapper around uint256.Int that serializes to and from hex strings.
// The json marshal and unmarshal functions were updated in one of the latest releases
// to match the behavior of big int json marshal/unmarshal, but we use this to maintain
// the existing marshal behavior so that consumers of this API don't need to update their
// logic.
type Uint256Hex struct {
	*uint256.Int
}

func (u *Uint256Hex) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.Hex())
}

func (u *Uint256Hex) UnmarshalJSON(data []byte) error {
	if u.Int == nil {
		u.Int = &uint256.Int{}
	}
	return u.Int.UnmarshalJSON(data)
}

// NewUint256Hex creates a new Uint256Hex with the given value.
func NewUint256Hex(value *uint256.Int) Uint256Hex {
	return Uint256Hex{value}
}
