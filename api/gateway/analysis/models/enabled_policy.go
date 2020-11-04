// Code generated by go-swagger; DO NOT EDIT.

package models

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
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// EnabledPolicy enabled policy
//
// swagger:model EnabledPolicy
type EnabledPolicy struct {

	// body
	Body Body `json:"body,omitempty"`

	// dedup period minutes
	DedupPeriodMinutes DedupPeriodMinutes `json:"dedupPeriodMinutes,omitempty"`

	// id
	ID ID `json:"id,omitempty"`

	// mappings
	Mappings Mappings `json:"mappings,omitempty"`

	// output ids
	OutputIds OutputIds `json:"outputIds,omitempty"`

	// reports
	Reports Reports `json:"reports,omitempty"`

	// resource types
	ResourceTypes TypeSet `json:"resourceTypes,omitempty"`

	// severity
	Severity Severity `json:"severity,omitempty"`

	// suppressions
	Suppressions Suppressions `json:"suppressions,omitempty"`

	// tags
	Tags Tags `json:"tags,omitempty"`

	// version Id
	VersionID VersionID `json:"versionId,omitempty"`
}

// Validate validates this enabled policy
func (m *EnabledPolicy) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBody(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDedupPeriodMinutes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMappings(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOutputIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReports(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceTypes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSeverity(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSuppressions(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTags(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateVersionID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EnabledPolicy) validateBody(formats strfmt.Registry) error {

	if swag.IsZero(m.Body) { // not required
		return nil
	}

	if err := m.Body.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("body")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateDedupPeriodMinutes(formats strfmt.Registry) error {

	if swag.IsZero(m.DedupPeriodMinutes) { // not required
		return nil
	}

	if err := m.DedupPeriodMinutes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("dedupPeriodMinutes")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateID(formats strfmt.Registry) error {

	if swag.IsZero(m.ID) { // not required
		return nil
	}

	if err := m.ID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("id")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateMappings(formats strfmt.Registry) error {

	if swag.IsZero(m.Mappings) { // not required
		return nil
	}

	if err := m.Mappings.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("mappings")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateOutputIds(formats strfmt.Registry) error {

	if swag.IsZero(m.OutputIds) { // not required
		return nil
	}

	if err := m.OutputIds.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("outputIds")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateReports(formats strfmt.Registry) error {

	if swag.IsZero(m.Reports) { // not required
		return nil
	}

	if err := m.Reports.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("reports")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateResourceTypes(formats strfmt.Registry) error {

	if swag.IsZero(m.ResourceTypes) { // not required
		return nil
	}

	if err := m.ResourceTypes.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("resourceTypes")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateSeverity(formats strfmt.Registry) error {

	if swag.IsZero(m.Severity) { // not required
		return nil
	}

	if err := m.Severity.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("severity")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateSuppressions(formats strfmt.Registry) error {

	if swag.IsZero(m.Suppressions) { // not required
		return nil
	}

	if err := m.Suppressions.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("suppressions")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateTags(formats strfmt.Registry) error {

	if swag.IsZero(m.Tags) { // not required
		return nil
	}

	if err := m.Tags.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("tags")
		}
		return err
	}

	return nil
}

func (m *EnabledPolicy) validateVersionID(formats strfmt.Registry) error {

	if swag.IsZero(m.VersionID) { // not required
		return nil
	}

	if err := m.VersionID.Validate(formats); err != nil {
		if ve, ok := err.(*errors.Validation); ok {
			return ve.ValidateName("versionId")
		}
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *EnabledPolicy) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EnabledPolicy) UnmarshalBinary(b []byte) error {
	var res EnabledPolicy
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
