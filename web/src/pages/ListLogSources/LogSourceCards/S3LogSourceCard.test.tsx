import { render, buildS3LogIntegration } from 'test-utils';
import React from 'react';
import { formatDatetime } from 'Helpers/utils';
import { S3LogSourceCard } from './index';

describe('S3LogSourceCard', () => {
  it('displays the needed data for S3', async () => {
    const source = buildS3LogIntegration();
    const { getByText, getByAriaLabel, getByAltText } = render(<S3LogSourceCard source={source} />);

    expect(getByAltText(/Logo/i)).toBeInTheDocument();
    expect(getByAriaLabel(/Toggle Options/i)).toBeInTheDocument();
    expect(getByText(source.integrationLabel)).toBeInTheDocument();
    expect(getByText(source.s3Prefix)).toBeInTheDocument();
    expect(getByText(source.s3Bucket)).toBeInTheDocument();
    expect(getByText(source.kmsKey)).toBeInTheDocument();
    expect(getByText(formatDatetime(source.createdAtTime, true))).toBeInTheDocument();
    expect(getByText(formatDatetime(source.lastEventReceived, true))).toBeInTheDocument();
    source.logTypes.forEach(logType => {
      expect(getByText(logType)).toBeInTheDocument();
    });
  });
});
