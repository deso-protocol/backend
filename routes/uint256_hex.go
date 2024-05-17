package routes

import (
	"encoding/json"
	"github.com/holiman/uint256"
)

type Uint256Hex struct {
	*uint256.Int
}

func (u *Uint256Hex) MarshalJSON() ([]byte, error) {
	if u.Int == nil {
		return json.Marshal(uint256.NewInt(0).Hex())
	}
	return json.Marshal(u.Hex())
}

func (u *Uint256Hex) UnmarshalJSON(data []byte) error {
	if u.Int == nil {
		u.Int = new(uint256.Int)
	}
	return u.Int.UnmarshalJSON(data)
}

// NewUint256Hex creates a new Uint256Hex with the given value.
func NewUint256Hex(value *uint256.Int) Uint256Hex {
	return Uint256Hex{value}
}
