// Code generated by go-swagger; DO NOT EDIT.

package operations

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

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/panther-labs/panther/api/gateway/analysis/models"
)

// TestRuleReader is a Reader for the TestRule structure.
type TestRuleReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TestRuleReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTestRuleOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewTestRuleBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 500:
		result := NewTestRuleInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewTestRuleOK creates a TestRuleOK with default headers values
func NewTestRuleOK() *TestRuleOK {
	return &TestRuleOK{}
}

/*TestRuleOK handles this case with default header values.

OK
*/
type TestRuleOK struct {
	Payload *models.TestRuleResult
}

func (o *TestRuleOK) Error() string {
	return fmt.Sprintf("[POST /rule/test][%d] testRuleOK  %+v", 200, o.Payload)
}

func (o *TestRuleOK) GetPayload() *models.TestRuleResult {
	return o.Payload
}

func (o *TestRuleOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TestRuleResult)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestRuleBadRequest creates a TestRuleBadRequest with default headers values
func NewTestRuleBadRequest() *TestRuleBadRequest {
	return &TestRuleBadRequest{}
}

/*TestRuleBadRequest handles this case with default header values.

Bad request
*/
type TestRuleBadRequest struct {
	Payload *models.Error
}

func (o *TestRuleBadRequest) Error() string {
	return fmt.Sprintf("[POST /rule/test][%d] testRuleBadRequest  %+v", 400, o.Payload)
}

func (o *TestRuleBadRequest) GetPayload() *models.Error {
	return o.Payload
}

func (o *TestRuleBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewTestRuleInternalServerError creates a TestRuleInternalServerError with default headers values
func NewTestRuleInternalServerError() *TestRuleInternalServerError {
	return &TestRuleInternalServerError{}
}

/*TestRuleInternalServerError handles this case with default header values.

Internal server error
*/
type TestRuleInternalServerError struct {
}

func (o *TestRuleInternalServerError) Error() string {
	return fmt.Sprintf("[POST /rule/test][%d] testRuleInternalServerError ", 500)
}

func (o *TestRuleInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}
