import React from 'react';
import { Flex, Link } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import GenericItemCard from 'Components/GenericItemCard';
import { LogIntegration } from 'Generated/schema';
import { PANTHER_USER_ID } from 'Source/constants';
import urls from 'Source/urls';
import LogSourceCardOptions from './LogSourceCardOptions';
import LogSourceCardHealthBadge from './LogSourceCardHealthBadge';

interface LogSourceCardProps {
  source: LogIntegration;
  logo: string;
  children: React.ReactNode;
}

const LogSourceCard: React.FC<LogSourceCardProps> = ({ source, children, logo }) => {
  const isCreatedByPanther = source.createdBy === PANTHER_USER_ID;

  return (
    <GenericItemCard>
      <GenericItemCard.Logo src={logo} />
      {!isCreatedByPanther && <LogSourceCardOptions source={source} />}
      <GenericItemCard.Body>
        <Link
          as={RRLink}
          to={urls.logAnalysis.sources.edit(source.integrationId, 'sqs')}
          cursor="pointer"
        >
          <GenericItemCard.Heading>{source.integrationLabel}</GenericItemCard.Heading>
        </Link>
        <GenericItemCard.ValuesGroup>
          {children}
          <Flex ml="auto" mr={0} align="flex-end">
            <LogSourceCardHealthBadge logSourceHealth={source.health} />
          </Flex>
        </GenericItemCard.ValuesGroup>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default LogSourceCard;
