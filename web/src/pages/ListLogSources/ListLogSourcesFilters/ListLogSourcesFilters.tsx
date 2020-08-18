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
import { Box, Flex } from 'pouncejs';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import FormikCombobox from 'Components/fields/ComboBox';
import { capitalize } from 'Helpers/utils';
import SubmitFormOnChange from 'Components/utils/SubmitFormOnChange';

const sortByOptions = ['most_recent', 'oldest', 'default'] as const;
const sortByOptionToString = (str: typeof sortByOptions[number]) =>
  str.split('_').map(capitalize).join(' ');

export interface ListLogSourcesFiltersValues {
  q: string;
  sortBy: typeof sortByOptions[number];
}

export interface ListLogSourcesFiltersProps {
  onSubmit: (values: ListLogSourcesFiltersValues) => Promise<void> | void;
  initialValues: ListLogSourcesFiltersValues;
}

const validationSchema = Yup.object().shape({
  q: Yup.string(),
  sortBy: Yup.string(),
});

const ListLogSourcesFilters: React.FC<ListLogSourcesFiltersProps> = ({
  initialValues,
  onSubmit,
}) => {
  return (
    <Formik<ListLogSourcesFiltersValues>
      initialValues={initialValues}
      onSubmit={onSubmit}
      validationSchema={validationSchema}
    >
      <Form>
        <Flex spacing={4}>
          <Box width={235}>
            <Field
              name="q"
              as={FormikTextInput}
              label="Filter by name"
              placeholder="Search for a source..."
            />
          </Box>
          <Box width={145}>
            <Field
              name="sortBy"
              as={FormikCombobox}
              label="Sort by"
              items={sortByOptions}
              itemToString={sortByOptionToString}
              placeholder="Sort by..."
            />
          </Box>
        </Flex>
        <SubmitFormOnChange />
      </Form>
    </Formik>
  );
};

export default ListLogSourcesFilters;
