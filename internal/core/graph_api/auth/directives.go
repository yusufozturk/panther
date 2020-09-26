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
	"context"

	"github.com/99designs/gqlgen/graphql"
	"github.com/juliangruber/go-intersect"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// nolint:golint,stylecheck
// The implementation of the `@aws_auth` GraphQL directive
func AwsAuth(ctx context.Context, _ interface{}, next graphql.Resolver, cognito_groups []string) (interface{}, error) {
	user := ForContext(ctx)

	hasPermission := len(intersect.Simple(user.Groups, cognito_groups).([]interface{})) > 0
	if !hasPermission {
		// block calling the next resolver
		return nil, gqlerror.Errorf("access denied")
	}

	return next(ctx)
}
