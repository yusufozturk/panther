import React from 'react';
import { Box, Flex } from 'pouncejs';
import logTypeColorMappings from 'Helpers/logTypeColorMappings';

interface BulletedLogTypeProps {
  logType: string;
}

const BulletedLogType: React.FC<BulletedLogTypeProps> = ({ logType }) => {
  return (
    <Flex spacing={2} align="center">
      <Box
        as="span"
        width={12}
        height={12}
        backgroundColor={logTypeColorMappings[logType]}
        borderRadius="circle"
      />
      <Box as="span" fontSize="small">
        {logType}
      </Box>
    </Flex>
  );
};

export default BulletedLogType;
