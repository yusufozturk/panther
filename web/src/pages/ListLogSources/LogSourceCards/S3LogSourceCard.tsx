import React from 'react';
import { S3LogIntegration } from 'Generated/schema';
import GenericItemCard from 'Components/GenericItemCard';
import { formatDatetime } from 'Helpers/utils';
import { Box, Flex } from 'pouncejs';
import s3Logo from 'Assets/s3-minimal-logo.svg';
import LogSourceCard from './LogSourceCard';
import BulletedLogType from 'Components/BulletedLogType';

interface S3LogSourceCardProps {
  source: S3LogIntegration;
}

const S3LogSourceCard: React.FC<S3LogSourceCardProps> = ({ source }) => {
  return (
    <LogSourceCard logo={s3Logo} source={source}>
      <GenericItemCard.Value label="AWS Account ID" value={source.awsAccountId} />
      <GenericItemCard.Value label="S3 Bucket" value={source.s3Bucket} />
      <GenericItemCard.Value label="S3 Prefix" value={source.s3Prefix} />
      <GenericItemCard.Value label="KMS Key" value={source.kmsKey} />
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
          <Flex align="center" spacing={6} mt={1}>
            {source.logTypes.map(logType => (
              <BulletedLogType key={logType} logType={logType} />
            ))}
          </Flex>
        }
      />
    </LogSourceCard>
  );
};

export default React.memo(S3LogSourceCard);
