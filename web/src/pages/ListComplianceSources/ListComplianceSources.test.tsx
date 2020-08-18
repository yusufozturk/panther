import { render, waitForElementToBeRemoved, buildComplianceIntegration } from 'test-utils';
import React from 'react';
import { mockListComplianceSources } from './graphql/listComplianceSources.generated';
import ListComplianceSources from './index';

describe('ListComplianceSources', () => {
  it('renders a list of compliance cards', async () => {
    const sources = [
      buildComplianceIntegration({ integrationId: '1', integrationLabel: 'First' }),
      buildComplianceIntegration({ integrationId: '2', integrationLabel: 'Second' }),
    ];

    const mocks = [mockListComplianceSources({ data: { listComplianceIntegrations: sources } })];

    const { getByText, getByAriaLabel } = render(<ListComplianceSources />, { mocks });

    // Expect to see a loading interface
    const loadingInterfaceElement = getByAriaLabel('Loading interface...');
    expect(loadingInterfaceElement).toBeInTheDocument();

    // Wait for it to not exist anymore
    await waitForElementToBeRemoved(loadingInterfaceElement);

    // Expect to see a list of names and emails
    sources.forEach(source => {
      expect(getByText(source.integrationLabel)).toBeInTheDocument();
    });
  });
});
