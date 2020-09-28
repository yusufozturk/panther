package auth

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// The claims that Cognito's JWT token contains
type CognitoClaims struct {
	jwt.StandardClaims
	EmailVerified       bool   `json:"email_verified"`
	PhoneNumberVerified bool   `json:"phone_number_verified"`
	CognitoUsername     string `json:"cognitousername"`
	GivenName           string `json:"given_name"`
	EventID             string `json:"event_id"`
	TokenUse            string `json:"token_use"`
	AuthTime            int64  `json:"auth_time"`
	PhoneNumber         string `json:"phone_number"`
	FamilyName          string `json:"family_name"`
	Email               string `json:"email"`

	// Extra
	Groups []string `json:"cognito:groups"`
	RoleID string   `json:"custom:role_id,omitempty"`
}

// Check JWT target audience
func (c CognitoClaims) VerifyAudience(audience string) bool {
	return c.Audience == audience
}

// Check if JWT issuer matches
func (c CognitoClaims) VerifyIssuer(issuer string) bool {
	return c.Issuer == issuer
}

// Check the intended JWT usage is correct
func (c CognitoClaims) VerifyUsage() bool {
	return c.TokenUse == "id"
}

// Check the JWT expiration date
func (c CognitoClaims) VerifyExpiresAt() bool {
	now := time.Now().Unix()
	return now < c.ExpiresAt
}

// Check the JWT issue date
func (c CognitoClaims) VerifyIssuedAt() bool {
	now := time.Now().Unix()
	return now >= c.IssuedAt
}

// Checks if the token's claims are valid
func (c CognitoClaims) Valid() error {
	if !c.VerifyExpiresAt() {
		return fmt.Errorf("token has expired")
	}

	if !c.VerifyIssuedAt() {
		return fmt.Errorf("token used before issued")
	}

	if !c.VerifyUsage() {
		return fmt.Errorf("invalid JWT usage")
	}

	if !c.VerifyAudience(appClientID) {
		return fmt.Errorf("invalid JWT issuer")
	}

	expectedIssuer := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", awsRegion, userPoolID)
	if !c.VerifyIssuer(expectedIssuer) {
		return fmt.Errorf("invalid JWT issuer")
	}

	return nil
}
