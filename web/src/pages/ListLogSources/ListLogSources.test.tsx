import React from 'react';
import {
  render,
  waitForElementToBeRemoved,
  buildS3LogIntegration,
  buildSqsLogSourceIntegration,
} from 'test-utils';
import { LogIntegrationsEnum } from 'Source/constants';
import { mockListLogSources } from './graphql/listLogSources.generated';
import ListLogSources from './index';

describe('ListLogSources', () => {
  it('renders a list of compliance cards', async () => {
    const sources = [
      buildSqsLogSourceIntegration({
        integrationId: '1',
        integrationLabel: 'First',
        integrationType: LogIntegrationsEnum.sqs,
      }),
      buildS3LogIntegration({
        integrationId: '2',
        integrationLabel: 'Second',
        integrationType: LogIntegrationsEnum.s3,
      }),
    ];

    const mocks = [mockListLogSources({ data: { listLogIntegrations: sources } })];

    const { getByText, getByAriaLabel } = render(<ListLogSources />, { mocks });

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
