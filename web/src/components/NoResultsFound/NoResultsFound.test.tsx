import React from 'react';
import { render } from 'test-utils';
import NoResultsFound from './NoResultsFound';

describe('NoResultsFound', () => {
  it('matches snapshot', () => {
    const { container } = render(<NoResultsFound />);
    expect(container).toMatchSnapshot();
  });

  it('contains proper semantics', () => {
    const { getByText, getByAltText } = render(<NoResultsFound />);
    expect(getByAltText('Document and magnifying glass')).toBeInTheDocument();
    expect(getByText('No Results')).toBeInTheDocument();
  });
});
