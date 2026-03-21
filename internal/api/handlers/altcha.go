package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

var altchaHMACKey string

func init() {
	altchaHMACKey = os.Getenv("ALTCHA_HMAC_KEY")
	if altchaHMACKey == "" {
		// Generate a random key if not set
		b := make([]byte, 32)
		rand.Read(b)
		altchaHMACKey = hex.EncodeToString(b)
	}
}

type altchaChallenge struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	MaxNumber int    `json:"maxnumber"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

// AltchaChallenge generates a new ALTCHA challenge.
func AltchaChallenge(c *gin.Context) {
	// Generate random salt (16 bytes hex = 32 chars)
	saltBytes := make([]byte, 16)
	rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)

	// Generate random secret number between 0 and maxNumber
	maxNumber := 50000
	secretBig, _ := rand.Int(rand.Reader, big.NewInt(int64(maxNumber)))
	secret := secretBig.Int64()

	// challenge = SHA-256(salt + secret)
	h := sha256.Sum256([]byte(fmt.Sprintf("%s%d", salt, secret)))
	challenge := hex.EncodeToString(h[:])

	// signature = HMAC-SHA256(challenge, hmacKey)
	mac := hmac.New(sha256.New, []byte(altchaHMACKey))
	mac.Write([]byte(challenge))
	signature := hex.EncodeToString(mac.Sum(nil))

	c.JSON(http.StatusOK, altchaChallenge{
		Algorithm: "SHA-256",
		Challenge: challenge,
		MaxNumber: maxNumber,
		Salt:      salt,
		Signature: signature,
	})
}

// VerifyAltcha verifies an ALTCHA solution payload.
// Returns true if the solution is valid.
func VerifyAltcha(payload string) bool {
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.RawStdEncoding.DecodeString(payload)
		if err != nil {
			return false
		}
	}

	var solution struct {
		Algorithm string `json:"algorithm"`
		Challenge string `json:"challenge"`
		Number    int64  `json:"number"`
		Salt      string `json:"salt"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(decoded, &solution); err != nil {
		return false
	}

	if solution.Algorithm != "SHA-256" {
		return false
	}

	// Verify: SHA-256(salt + number) == challenge
	h := sha256.Sum256([]byte(fmt.Sprintf("%s%d", solution.Salt, solution.Number)))
	expectedChallenge := hex.EncodeToString(h[:])
	if expectedChallenge != solution.Challenge {
		return false
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, []byte(altchaHMACKey))
	mac.Write([]byte(solution.Challenge))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if expectedSig != solution.Signature {
		return false
	}

	return true
}
