import { render, buildSqsLogSourceIntegration } from 'test-utils';
import React from 'react';
import { formatDatetime } from 'Helpers/utils';
import { SqsLogSourceCard } from './index';

describe('SqsLogSourceCard', () => {
  it('displays the needed data for Sqs', async () => {
    const source = buildSqsLogSourceIntegration();
    const { getByText, getByAriaLabel, getByAltText } = render(
      <SqsLogSourceCard source={source} />
    );

    expect(getByAltText(/Logo/i)).toBeInTheDocument();
    expect(getByAriaLabel(/Toggle Options/i)).toBeInTheDocument();
    expect(getByText(source.integrationLabel)).toBeInTheDocument();
    source.sqsConfig.allowedPrincipalArns.forEach(arn => {
      expect(getByText(arn)).toBeInTheDocument();
    });
    source.sqsConfig.allowedSourceArns.forEach(arn => {
      expect(getByText(arn)).toBeInTheDocument();
    });
    expect(getByText(formatDatetime(source.createdAtTime, true))).toBeInTheDocument();
    expect(getByText(formatDatetime(source.lastEventReceived, true))).toBeInTheDocument();
    source.sqsConfig.logTypes.forEach(logType => {
      expect(getByText(logType)).toBeInTheDocument();
    });
  });
});
