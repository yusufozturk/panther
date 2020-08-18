import React from 'react';
import { Box, Flex } from 'pouncejs';
import { SqsLogSourceIntegration } from 'Generated/schema';
import GenericItemCard from 'Components/GenericItemCard';
import { formatDatetime } from 'Helpers/utils';
import sqsLogo from 'Assets/sqs-minimal-logo.svg';
import BulletedLogType from 'Components/BulletedLogType';
import LogSourceCard from './LogSourceCard';

interface SqsLogSourceCardProps {
  source: SqsLogSourceIntegration;
}

const SqsLogSourceCard: React.FC<SqsLogSourceCardProps> = ({ source }) => {
  return (
    <LogSourceCard logo={sqsLogo} source={source}>
      <GenericItemCard.Value label="SQS Queue URL" value={source.sqsConfig.queueUrl} />
      <GenericItemCard.Value
        label="Allowed Principal ARNs"
        value={
          <React.Fragment>
            {source.sqsConfig.allowedPrincipalArns.map(arn => (
              <Box key={arn}>{arn}</Box>
            ))}
          </React.Fragment>
        }
      />
      <GenericItemCard.Value
        label="Allowed Source ARNs"
        value={
          <React.Fragment>
            {source.sqsConfig.allowedSourceArns.map(arn => (
              <Box key={arn}>{arn}</Box>
            ))}
          </React.Fragment>
        }
      />
      <GenericItemCard.LineBreak />
      <GenericItemCard.Value
        label="Date Created"
        value={formatDatetime(source.createdAtTime, true)}
      />
      <GenericItemCard.Value
        label="Last Received Events At"
        value={formatDatetime(source.lastEventReceived, true)}
      />
      <GenericItemCard.LineBreak />
      <GenericItemCard.Value
        label="Log Types"
        value={
          <Flex align="center" spacing={4} mt={1}>
            {source.sqsConfig.logTypes.map(logType => (
              <BulletedLogType key={logType} logType={logType} />
            ))}
          </Flex>
        }
      />
    </LogSourceCard>
  );
};

export default SqsLogSourceCard;
