// Package e2e provides an end-to-end deployment test, triggered by 'mage test:e2e'
package e2e

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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	cfn "github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/awscfn"
	"github.com/panther-labs/panther/tools/mage/clients"
	"github.com/panther-labs/panther/tools/mage/logger"
	"github.com/panther-labs/panther/tools/mage/util"
)

const (
	numStages    = 8
	pollInterval = 5 * time.Minute

	masterStackName     = "panther"
	deployRoleStackName = "panther-e2e-deploy-role"
	deployRoleName      = "PantherE2EDeploy"
	ecrRepoName         = "panther-e2e-test"

	companyName   = "panther-e2e-test"
	userFirstName = "E2E"
	userLastName  = "Test"
)

// TODO - separate mage packages for *everything*, explicitly build the mage targets
// TODO - chdir at the beginning of this test to the repo root

// We want timestamps, colors, and levels, so we use the standard mage logger
// instead of t.Log() from the testing library.
var log = logger.Get()

// The working directory at runtime will be the directory containing this file: tools/mage/e2e
var repoRoot = filepath.Join("..", "..", "..")

// Using the testing library (instead of adding to mage directly) makes it easier to add assertions.
// This also avoids bloating mage with all of the compiled testing code.
//
// It's recommended to run this test in a fresh account when possible.
//
// 'mage test:e2e' will set the following environment variables based on user input:
//     EMAIL: (first user email)
//     INTEGRATION_TEST: True (to enable the test)
//     OLD_VERSION: (published panther version we will migrate from, e.g. "1.7.1")
//     STAGE: (testing stage to start at)
func TestIntegrationEndToEnd(t *testing.T) {
	if strings.ToLower(os.Getenv("INTEGRATION_TEST")) != "true" {
		t.Skip()
	}

	startStage, err := strconv.Atoi(os.Getenv("STAGE"))
	require.NoError(t, err)

	if startStage == 1 {
		t.Run("1_PreTeardown", preTeardown)
	}
	if startStage <= 2 && !t.Failed() {
		t.Run("2_DeployPreviousVersion", deployPreviousVersion)
	}
	if startStage <= 3 && !t.Failed() {
		t.Run("3_InteractWithOldVersion", interactWithOldVersion)
	}
	if startStage <= 4 && !t.Failed() {
		t.Run("4_Migrate", migrate)
	}
}

// Teardown all Panther resources in the region to start with a clean slate.
func preTeardown(t *testing.T) {
	log.Infof("***** test:e2e : Stage 1/%d : Pre-Teardown *****", numStages)

	// Same as 'mage teardown', except clearing both source and master deployments
	// NOTE: AWS does not allow programmatically removing AWSService IAM roles
	require.NoError(t, util.DestroyCfnStacks("", pollInterval))
	require.NoError(t, util.DestroyCfnStacks(masterStackName, pollInterval))
	require.NoError(t, util.DestroyPantherBuckets(clients.S3()))
}

// Deploy the official published pre-packaged deployment for the previous version.
func deployPreviousVersion(t *testing.T) {
	log.Infof("***** test:e2e : Stage 2/%d : Deploy Previous Release *****", numStages)

	// Download previous published release
	s3URL := fmt.Sprintf("https://panther-community-%s.s3.amazonaws.com/v%s/panther.yml",
		clients.Region(), os.Getenv("OLD_VERSION"))
	downloadPath, err := filepath.Abs(filepath.Join(repoRoot, "out", "deployments", "panther.yml"))
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(downloadPath), 0700))

	log.Infof("downloading %s to %s", s3URL, downloadPath)
	require.NoError(t, util.RunWithCapturedOutput("curl", s3URL, "--output", downloadPath))

	// Deploy the template directly
	require.NoError(t, samDeploy(masterStackName, downloadPath,
		"CompanyDisplayName="+companyName, "FirstUserEmail="+os.Getenv("EMAIL"),
		"FirstUserGivenName="+userFirstName, "FirstUserFamilyName="+userLastName,
	))
}

func interactWithOldVersion(t *testing.T) {
	log.Infof("***** test:e2e : Stage 3/%d : Add Data To Old Version (TODO) *****", numStages)

	// TODO: add the following here to ensure they are migrated correctly later:
	//   - ingested logs
	//   - new policy and rule
	//   - modify an existing policy/rule (ensure update does not overwrite changes to default rules)
	//   - SQS destination
}

// Using the deployment role, update the deployment to the current master stack
func migrate(t *testing.T) {
	log.Infof("***** test:e2e : Stage 4/%d : Migrate to Current Master Template *****", numStages)

	// Ensure the version in the master stack is different from the deployed version.
	// This is required to trigger custom resource updates.
	// TODO

	// Create/update deployment role
	deploymentRoleTemplate := filepath.Join(
		"deployments", "auxiliary", "cloudformation", "panther-deployment-role.yml")
	log.Infof("creating/updating deployment role from %s", deploymentRoleTemplate)
	require.NoError(t, samDeploy(deployRoleStackName, deploymentRoleTemplate, "DeploymentRoleName="+deployRoleName))
	deployRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", clients.AccountID(), deployRoleName)

	// Create S3 bucket and ECR repo for staging master package assets
	bucket := "panther-e2e-test-" + clients.AccountID()
	var err error
	if _, err = clients.S3().CreateBucket(&s3.CreateBucketInput{Bucket: &bucket}); err != nil {
		if awsErr := err.(awserr.Error); awsErr.Code() == s3.ErrCodeBucketAlreadyExists ||
			awsErr.Code() == s3.ErrCodeBucketAlreadyOwnedByYou {

			err = nil // bucket already exists
		}
	}
	require.NoError(t, err, "failed to create s3 staging bucket %s", bucket)

	_, err = clients.ECR().CreateRepository(&ecr.CreateRepositoryInput{RepositoryName: aws.String(ecrRepoName)})
	if err != nil {
		if awsErr := err.(awserr.Error); awsErr.Code() == ecr.ErrCodeRepositoryAlreadyExistsException {
			err = nil // ECR repo already exists
		}
	}
	require.NoError(t, err, "failed to create ECR repo %s", ecrRepoName)
	log.Infof("created/validated S3 bucket %s and ECR repo %s for staging master assets", bucket, ecrRepoName)
}

/* Helper functions */

// Returns the outputs for the given nested stack in the master template.
func getStackOutputs(t *testing.T, resourceID string) map[string]string {
	// The stack name is dynamic - we have to look it up in the master stack resources.
	output, err := clients.Cfn().DescribeStackResource(&cfn.DescribeStackResourceInput{
		StackName:         aws.String(masterStackName),
		LogicalResourceId: &resourceID,
	})
	require.NoError(t, err, "failed to describe stack resource")

	parsedArn, err := arn.Parse(aws.StringValue(output.StackResourceDetail.PhysicalResourceId))
	require.NoError(t, err)

	// Example: "arn:aws:...:stack/panther-BootstrapGateway-Y6DFB9SJ5MEL/8eac6ab0-eca3-11ea-b51f-06499c67a6ab"
	resourceParts := strings.Split(parsedArn.Resource, "/")
	require.Len(t, resourceParts, 3)
	stackName := resourceParts[1]

	return awscfn.StackOutputs(clients.Cfn(), log, stackName)
}
