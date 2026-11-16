import React, { useState } from 'react';

const byPath = (a, b) => a.path.localeCompare(b.path, undefined, { numeric: true });

export function ReviewedFiles({ files, findings }) {
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState('path');
  const [withSignals, setWithSignals] = useState(false);
  const [pageSize, setPageSize] = useState(25);
  const [page, setPage] = useState(0);

  const signalCounts = new Map();
  for (const { path, line } of findings) {
    if (line != null) signalCounts.set(path, (signalCounts.get(path) ?? 0) + 1);
  }
  const countSignals = path => signalCounts.get(path) ?? 0;
  const search = query.trim().toLowerCase();
  const matches = files.filter(({ path }) =>
    path.toLowerCase().includes(search) && (!withSignals || countSignals(path) > 0)
  );
  matches.sort((a, b) => {
    if (sort === 'lines') return b.lines - a.lines || byPath(a, b);
    if (sort === 'signals') return countSignals(b.path) - countSignals(a.path) || byPath(a, b);
    return byPath(a, b);
  });

  const start = page * pageSize;
  const end = Math.min(start + pageSize, matches.length);

  return <details className="reviewedFiles">
    <summary>Reviewed files ({files.length.toLocaleString()})</summary>
    <div className="reviewedFileControls">
      <label>Search file paths
        <input type="search" value={query} onChange={event => { setQuery(event.target.value); setPage(0); }}/>
      </label>
      <label>Sort by
        <select value={sort} onChange={event => { setSort(event.target.value); setPage(0); }}>
          <option value="path">Path (A–Z)</option>
          <option value="lines">Most lines</option>
          <option value="signals">Most review signals</option>
        </select>
      </label>
      <label>Files per page
        <select value={pageSize} onChange={event => { setPageSize(Number(event.target.value)); setPage(0); }}>
          {[25, 50, 100].map(size => <option key={size}>{size}</option>)}
        </select>
      </label>
      <label className="reviewedFileFilter">
        <input type="checkbox" checked={withSignals} onChange={event => { setWithSignals(event.target.checked); setPage(0); }}/>
        Only files with review signals
      </label>
    </div>
    <p role="status">
      {matches.length ? `Showing ${start + 1}–${end} of ${matches.length.toLocaleString()} files` : 'No files match your filters.'}
    </p>
    {matches.length > 0 && <table>
      <thead><tr><th scope="col">File path</th><th scope="col">Lines</th><th scope="col">Signals</th></tr></thead>
      <tbody>{matches.slice(start, end).map(({ path, lines }, index) => <tr key={`${start + index}:${path}`}>
        <th scope="row">{path}</th><td>{lines.toLocaleString()}</td><td>{countSignals(path)}</td>
      </tr>)}</tbody>
    </table>}
    {matches.length > pageSize && <nav className="reviewedFilePages" aria-label="Reviewed file pages">
      <button type="button" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
      <button type="button" disabled={end === matches.length} onClick={() => setPage(page + 1)}>Next</button>
    </nav>}
  </details>;
}
