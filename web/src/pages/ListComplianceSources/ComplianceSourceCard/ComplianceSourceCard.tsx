import React from 'react';
import { Flex, Link } from 'pouncejs';
import GenericItemCard from 'Components/GenericItemCard';
import { ComplianceIntegration } from 'Generated/schema';
import { formatDatetime } from 'Helpers/utils';
import urls from 'Source/urls';
import logo from 'Assets/aws-minimal-logo.svg';
import { Link as RRLink } from 'react-router-dom';

import ComplianceSourceCardOptions from './ComplianceSourceCardOptions';
import ComplianceSourceCardHealthBadge from './ComplianceSourceCardHealthBadge';

interface ComplianceSourceCardProps {
  source: ComplianceIntegration;
}

const ComplianceSourceCard: React.FC<ComplianceSourceCardProps> = ({ source }) => {
  return (
    <GenericItemCard>
      <GenericItemCard.Logo src={logo} />
      <ComplianceSourceCardOptions source={source} />
      <GenericItemCard.Body>
        <Link as={RRLink} to={urls.compliance.sources.edit(source.integrationId)} cursor="pointer">
          <GenericItemCard.Heading>{source.integrationLabel}</GenericItemCard.Heading>
        </Link>
        <GenericItemCard.ValuesGroup>
          <GenericItemCard.Value label="AWS Account ID" value={source.awsAccountId} />
          <GenericItemCard.Value
            label="Real-Time Updates"
            value={source.cweEnabled ? 'Enabled' : 'Disabled'}
          />
          <GenericItemCard.Value
            label="Auto-Remediations"
            value={source.remediationEnabled ? 'Enabled' : 'Disabled'}
          />

          <GenericItemCard.LineBreak />
          <GenericItemCard.Value
            label="Date Created"
            value={formatDatetime(source.createdAtTime, true)}
          />
          <Flex ml="auto" mr={0} align="flex-end">
            <ComplianceSourceCardHealthBadge complianceSourceHealth={source.health} />
          </Flex>
        </GenericItemCard.ValuesGroup>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default ComplianceSourceCard;
