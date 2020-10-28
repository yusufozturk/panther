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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import (
	"time"

	"golang.org/x/oauth2"
)

// SourceIntegration represents a Panther integration with a source.
type SourceIntegration struct {
	SourceIntegrationMetadata
	SourceIntegrationStatus
	SourceIntegrationScanInformation
}

// SourceIntegrationStatus provides information about the status of a source
type SourceIntegrationStatus struct {
	ScanStatus        string     `json:"scanStatus,omitempty"`
	EventStatus       string     `json:"eventStatus,omitempty"`
	LastEventReceived *time.Time `json:"lastEventReceived,omitempty"`
}

// SourceIntegrationScanInformation is detail about the last snapshot.
type SourceIntegrationScanInformation struct {
	LastScanStartTime    *time.Time `json:"lastScanStartTime,omitempty"`
	LastScanEndTime      *time.Time `json:"lastScanEndTime,omitempty"`
	LastScanErrorMessage string     `json:"lastScanErrorMessage,omitempty"`
}

// SourceIntegrationMetadata is general settings and metadata for an integration.
type SourceIntegrationMetadata struct {
	AWSAccountID       string    `json:"awsAccountId,omitempty"`
	CreatedAtTime      time.Time `json:"createdAtTime,omitempty"`
	CreatedBy          string    `json:"createdBy,omitempty"`
	IntegrationID      string    `json:"integrationId,omitempty"`
	IntegrationLabel   string    `json:"integrationLabel,omitempty"`
	IntegrationType    string    `json:"integrationType,omitempty"`
	RemediationEnabled *bool     `json:"remediationEnabled,omitempty"`
	CWEEnabled         *bool     `json:"cweEnabled,omitempty"`
	ScanIntervalMins   int       `json:"scanIntervalMins,omitempty"`
	S3Bucket           string    `json:"s3Bucket,omitempty"`
	S3Prefix           string    `json:"s3Prefix,omitempty"`
	KmsKey             string    `json:"kmsKey,omitempty"`
	// For non-AWS S3 integration, find the log types in the respective config (EventbridgeConfig, PullerConfig, etc).
	LogTypes          []string           `json:"logTypes,omitempty"`
	LogProcessingRole string             `json:"logProcessingRole,omitempty"`
	StackName         string             `json:"stackName,omitempty"`
	EventbridgeConfig *EventbridgeConfig `json:"eventbridgeConfig,omitempty"`
	PullerConfig      *PullerConfig      `json:"pullerConfig,omitempty"`
	SqsConfig         *SqsConfig         `json:"sqsConfig,omitempty"`
}

const (
	resourceSnapshotLogType   = "Snapshot.ResourceHistory"
	complianceSnapshotLogType = "Snapshot.ComplianceHistory"
)

func (info *SourceIntegration) RequiredLogTypes() (logTypes []string) {
	// We use a switch to avoid git conflicts with enterprise
	switch {
	case info.IntegrationType == IntegrationTypeAWSScan:
		return []string{resourceSnapshotLogType, complianceSnapshotLogType}
	case info.SqsConfig != nil:
		return info.SqsConfig.LogTypes
	case info.PullerConfig != nil:
		return info.PullerConfig.LogTypes
	case info.EventbridgeConfig != nil:
		return []string{
			info.EventbridgeConfig.LogType,
		}
	default:
		return info.LogTypes
	}
}

func (info *SourceIntegration) IsLogAnalysisIntegration() bool {
	switch integType := info.IntegrationType; integType {
	case IntegrationTypeAWSScan:
		return false
	case IntegrationTypeAWS3, IntegrationTypeSqs:
		return true
	default:
		panic("Unexpected integration type " + integType)
	}
}

type SourceIntegrationHealth struct {
	IntegrationType string `json:"integrationType"`

	// Checks for cloudsec integrations
	AuditRoleStatus       SourceIntegrationItemStatus `json:"auditRoleStatus,omitempty"`
	CWERoleStatus         SourceIntegrationItemStatus `json:"cweRoleStatus,omitempty"`
	RemediationRoleStatus SourceIntegrationItemStatus `json:"remediationRoleStatus,omitempty"`

	// Checks for log analysis integrations
	ProcessingRoleStatus SourceIntegrationItemStatus `json:"processingRoleStatus,omitempty"`
	S3BucketStatus       SourceIntegrationItemStatus `json:"s3BucketStatus,omitempty"`
	KMSKeyStatus         SourceIntegrationItemStatus `json:"kmsKeyStatus,omitempty"`

	// Checks for Sqs integrations
	SqsStatus SourceIntegrationItemStatus `json:"sqsStatus"`

	// Checks for Amazon EventBridge integrations
	EventBridgeBusStatus SourceIntegrationItemStatus `json:"eventBridgeStatus,omitempty"`

	// Checks for Log Polling integrations
	LogPullingStatus SourceIntegrationItemStatus `json:"logPullingStatus,omitempty"`
}

type SourceIntegrationItemStatus struct {
	Healthy      bool   `json:"healthy"`
	Message      string `json:"message"`
	ErrorMessage string `json:"rawErrorMessage,omitempty"`
}

type SourceIntegrationTemplate struct {
	Body      string `json:"body"`
	StackName string `json:"stackName"`
}

// The S3 Prefix where the SQS data will be stored
const (
	SqsS3Prefix           = "forwarder"
	CloudSecurityS3Prefix = "cloudsecurity"
)

type SqsConfig struct {
	// The log types associated with the source. Needs to be set by UI.
	LogTypes []string `json:"logTypes" validate:"required,min=1"`
	// The AWS Principals that are allowed to send data to this source. Needs to be set by UI.
	AllowedPrincipalArns []string `json:"allowedPrincipalArns"`
	// The ARNS (e.g. SNS topic ARNs) that are allowed to send data to this source. Needs to be set by UI.
	AllowedSourceArns []string `json:"allowedSourceArns"`

	// The Panther-internal S3 bucket where the data from this source will be available
	S3Bucket string `json:"s3Bucket"`
	// The S3 prefix where the data from this source will be available
	S3Prefix string `json:"s3Prefix"`
	// The Role that the log processor can use to access this data
	LogProcessingRole string `json:"logProcessingRole"`
	// THe URL of the SQS queue
	QueueURL string `json:"queueUrl"`
}

const EventbridgeS3Prefix = "eventbridge"

type EventbridgeConfig struct {
	BusName           string `json:"busName" validate:"required"`
	LogType           string `json:"logType" validate:"required"`
	S3Bucket          string `json:"s3Bucket,omitempty"`
	S3Prefix          string `json:"s3Prefix,omitempty"`
	LogProcessingRole string `json:"logProcessingRole,omitempty"`
}

type PullerConfig struct {
	// The log types configured for this puller
	LogTypes []string `json:"logTypes" validate:"required,min=1"`
	// Configuration for Okta pulling
	Okta *OktaConfig `json:"okta,omitempty"`
	// Configuration for GSuite pulling
	GSuite *GSuiteConfig `json:"gsuite,omitempty"`
	// Configuration for Box pulling
	Box *BoxConfig `json:"box,omitempty"`
	// Configuration for Slack logs pulling
	Slack *SlackConfig `json:"slack,omitempty"`

	// UI doesn't haven't to populate the values below here
	S3Bucket          string `json:"s3Bucket,omitempty"`
	S3Prefix          string `json:"s3Prefix,omitempty"`
	LogProcessingRole string `json:"logProcessingRole,omitempty"`
}

const (
	OktaPullerS3Prefix = "puller/okta"
)

// Configuration for Okta onboarding
type OktaConfig struct {
	// The Okta domain. It must be in the form:
	// https://<customerDomain>.okta.com or
	// https://<customerDomain>.oktapreview.com
	Domain string `json:"domain"`
	// The Okta API token that will be used for accessing the remote Okta endpoint
	APIToken string `json:"apiToken"`

	// DEPRECATED field - use PullerConfig.LogTypes instead
	LogTypes []string `json:"types,omitempty" validate:"omitempty,min=1"`
}

const (
	BoxPullerS3Prefix = "puller/box"
)

type BoxConfig struct {
	// ClientID that will be used for OAuth2 auth
	ClientID string `json:"clientId"`
	// ClientSecret that will be used for OAuth2 auth
	ClientSecret string `json:"clientSecret"`
	// UI doesn't haven't to populate this value
	Token *oauth2.Token `json:"token,omitempty"`
}

// 10 minutes should give a safety margin for the puller to refresh the token in time
const BoxTokenDelta = 10 * time.Minute

func (c *BoxConfig) SetToken(t *oauth2.Token) {
	// Shorten the life of the token so it is refreshed on time
	boxToken := *t
	if time.Until(boxToken.Expiry) > BoxTokenDelta {
		boxToken.Expiry = boxToken.Expiry.Add(-1 * BoxTokenDelta)
	}
	c.Token = &boxToken
}

const (
	GSuiteS3Prefix = "puller/gsuite"
)

// Configuration for GSuite onboarding
type GSuiteConfig struct {
	// ClientID that will be used for OAuth2 auth. It is not required for Update operation.
	ClientID string `json:"clientId"`
	// ClientSecret that will be used for OAuth2 auth. It is not required for Update operation.
	ClientSecret string `json:"clientSecret"`
	// The AuthCode that will be used for the OAuth2 auth. It is not required for Update operation.
	AuthCode string `json:"authCode"`
	// The GSuite applications that the user wants to pull data from
	// Options are: access_transparency, admin, calendar, chat, drive, groups, groups_enterprise, jamboard, login,
	// meet, mobile, rules, saml, token, user_accounts
	// Reference: https://developers.google.com/admin-sdk/reports/v1/reference/activities/list
	Applications []string `json:"applications" validate:"omitempty,min=1"`
	// UI doesn't haven't to populate this value
	Token *oauth2.Token `json:"token"`
}

const SlackPullerS3Prefix = "puller/slack"

type SlackConfig struct {
	// ClientID that will be used for OAuth2 auth
	ClientID string `json:"clientId"`
	// ClientSecret that will be used for OAuth2 auth
	ClientSecret string `json:"clientSecret"`
	// UI doesn't haven't to populate this value
	Token *oauth2.Token `json:"token,omitempty"`
}
