package toolslib

import (
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgrijalva/jwt-go/v4"
	"github.com/fatih/structs"
	"github.com/pkg/errors"
)

// Generate a JWT Token for the provided private key.
// This can be added to the payload for requests that require JWT token authentication.
func GenerateJWTToken(privKey *btcec.PrivateKey) (_JWT string, _err error){
	// Create the ecdsa keys
	ecdsaPrivKey := privKey.ToECDSA()

	// Create a new JWT Token
	token := jwt.New(jwt.SigningMethodES256)

	// Sign using the ECDSA private key
	jwtToken, err := token.SignedString(ecdsaPrivKey)
	if err != nil {
		return "", errors.Wrap(err, "GenerateJWTToken() failed to sign token")
	}
	return jwtToken, nil
}

// Add a JWT token to the specified request payload interface using a provided private key.
//
// Here's an example on how this can be used to execute a request as an admin:
// payload := routes.AdminUpdateUserGlobalMetadataRequest{ ... }
// mPayload, _ := toolslib.AddJWT(payload, adminPrivKey)
// postBody, _ := json.Marshal(mPayload)
// postBuffer := bytes.NewBuffer(postBody)
// resp, _ := http.Post(endpoint, "application/json", postBuffer)
func AddJWT(requestPayload interface{}, privKey *btcec.PrivateKey) (_jwtPayload interface{}, _err error) {
	jwtToken, err := GenerateJWTToken(privKey)
	if err != nil {
		return nil, errors.Wrap(err, "AddJWT() failed to generate jwtToken for private key")
	}
	mPayload := structs.Map(requestPayload)
	mPayload["JWT"] = jwtToken
	return mPayload, nil
}