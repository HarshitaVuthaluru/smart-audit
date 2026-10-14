import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import ProjectContextPanel from './ProjectContextPanel';

jest.mock('mermaid', () => ({
  initialize: jest.fn(),
  render: jest.fn(),
}));

test('renders structured context vulnerability findings', () => {
  render(
    <ProjectContextPanel
      contextData={{
        vulnerabilities: [
          {
            vulnerability_type: 'Reentrancy',
            description: 'External call occurs before state update.',
          },
        ],
        stats: { total_vulnerabilities: 1 },
      }}
    />
  );

  fireEvent.click(screen.getByRole('button', { name: /Context Risk Flags/ }));

  expect(screen.getByText('Reentrancy: External call occurs before state update.')).toBeTruthy();
});
