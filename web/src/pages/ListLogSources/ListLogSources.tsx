/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React from 'react';
import { Alert, Box, Button, Flex, Heading } from 'pouncejs';
import Panel from 'Components/Panel';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import ErrorBoundary from 'Components/ErrorBoundary';
import { extractErrorMessage } from 'Helpers/utils';
import withSEO from 'Hoc/withSEO';
import useUrlParams from 'Hooks/useUrlParams';
import { useListLogSources } from './graphql/listLogSources.generated';
import EmptyDataFallback from './EmptyDataFallback';
import Skeleton from './Skeleton';
import ListDestinationsCards from './ListLogSourceCards';
import ListLogSourcesFilters, { ListLogSourcesFiltersValues } from './ListLogSourcesFilters';

const ListLogSources = () => {
  const { loading, error, data } = useListLogSources();
  const { urlParams, updateUrlParams } = useUrlParams<ListLogSourcesFiltersValues>();

  const filterValues: ListLogSourcesFiltersValues = React.useMemo(
    () => ({
      q: urlParams.q || '',
      sortBy: urlParams.sortBy || 'default',
    }),
    [urlParams]
  );

  const filteredSources = React.useMemo(() => {
    let sources = data?.listLogIntegrations ?? [];

    if (urlParams.q) {
      sources = sources.filter(source => source.integrationLabel.includes(filterValues.q));
    }

    if (urlParams.sortBy !== 'default') {
      sources = sources.sort((source1, source2) => {
        const unix1 = new Date(source1.createdAtTime).getTime();
        const unix2 = new Date(source2.createdAtTime).getTime();

        if (urlParams.sortBy === 'most_recent') {
          return unix1 < unix2 ? 1 : -1;
        }

        if (urlParams.sortBy === 'oldest') {
          return unix1 > unix2 ? 1 : -1;
        }

        return 0;
      });
    }
    return sources;
  }, [data, urlParams]);

  if (loading && !data) {
    return <Skeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load your sources"
        description={
          extractErrorMessage(error) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  if (!data.listLogIntegrations.length) {
    return <EmptyDataFallback />;
  }

  return (
    <Box mb={6}>
      <Panel
        title="Log Sources"
        actions={
          <Flex spacing={4}>
            <ListLogSourcesFilters onSubmit={updateUrlParams} initialValues={filterValues} />
            <Button icon="add" as={RRLink} to={urls.logAnalysis.sources.create()}>
              Add Source
            </Button>
          </Flex>
        }
      >
        <ErrorBoundary>
          {filteredSources.length ? (
            <ListDestinationsCards sources={filteredSources} />
          ) : (
            <Heading color="navyblue-100" textAlign="center" py={10} size="small">
              No matches found
            </Heading>
          )}
        </ErrorBoundary>
      </Panel>
    </Box>
  );
};

export default withSEO({ title: 'Log Analysis Sources' })(ListLogSources);
