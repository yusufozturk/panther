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
import { Box, Flex, Heading, Card, Checkbox } from 'pouncejs';

interface PanelProps {
  title: string;
  filters?: React.ReactNode;
  select: React.ReactNode;
  selected: string[];
  selectAll: () => void;
  deselectAll: () => void;
}

const PanelWithSelection: React.FC<PanelProps> = ({
  title,
  selected,
  select,
  filters,
  children,
  selectAll,
  deselectAll,
}) => {
  return (
    <Card as="section" width={1}>
      <Flex
        p={6}
        borderBottom="1px solid"
        borderColor={children ? 'navyblue-300' : 'transparent'}
        justify="space-between"
        align="center"
        maxHeight={80}
      >
        <Flex align="center" spacing={2} ml={4}>
          <Checkbox
            checked={!!selected.length}
            onClick={() => {
              if (selected.length) {
                deselectAll();
              } else {
                selectAll();
              }
            }}
            aria-label="select all checkbox"
          />
          <Heading size="x-small" as="h4">
            {title}
          </Heading>
        </Flex>
        {selected.length ? select : filters || select}
      </Flex>
      {children && <Box p={6}>{children}</Box>}
    </Card>
  );
};

export default PanelWithSelection;
