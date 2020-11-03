import React from 'react';
import { Text, Flex, Img } from 'pouncejs';
import NothingFound from 'Assets/illustrations/nothing-found.svg';

const NoResultsFound: React.FC = () => {
  return (
    <Flex justify="center">
      <Flex
        direction="column"
        align="center"
        justify="center"
        backgroundColor="navyblue-500"
        borderRadius="circle"
        width={260}
        height={260}
      >
        <Img
          ml={6}
          nativeWidth={95}
          nativeHeight={90}
          alt="Document and magnifying glass"
          src={NothingFound}
        />
        <Text color="navyblue-100" fontWeight="bold" mt={2}>
          No Results
        </Text>
      </Flex>
    </Flex>
  );
};

export default NoResultsFound;
