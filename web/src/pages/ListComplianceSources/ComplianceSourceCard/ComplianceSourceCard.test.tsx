import { render, buildComplianceIntegration } from 'test-utils';
import React from 'react';
import { formatDatetime } from 'Helpers/utils';
import ComplianceSourceCard from './index';

describe('ComplianceSourceCard', () => {
  it('displays the needed data', async () => {
    const source = buildComplianceIntegration();
    const { getByText, getByAriaLabel, getByAltText } = render(
      <ComplianceSourceCard source={source} />
    );

    expect(getByAltText(/Logo/i)).toBeInTheDocument();
    expect(getByAriaLabel(/Toggle Options/i)).toBeInTheDocument();
    expect(getByText(source.integrationLabel)).toBeInTheDocument();
    expect(getByText(source.awsAccountId)).toBeInTheDocument();
    expect(getByText(/Enabled/i)).toBeInTheDocument();
    expect(getByText(/Disabled/i)).toBeInTheDocument();
    expect(getByText(/Unhealthy/i)).toBeInTheDocument();
    expect(getByText(formatDatetime(source.createdAtTime, true))).toBeInTheDocument();
  });
});
