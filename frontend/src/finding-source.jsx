import React, { useLayoutEffect, useRef, useState } from 'react';

export function FindingSource({ source, path, line, endLine }) {
  const [expanded, setExpanded] = useState(false);
  const viewport = useRef(null);
  const highlight = useRef(null);
  const lines = source.split('\n', expanded ? undefined : endLine);

  useLayoutEffect(() => {
    const view = viewport.current;
    const matched = highlight.current;
    view.scrollTop = expanded ? matched.offsetTop - 3 * parseFloat(getComputedStyle(matched).lineHeight) : 0;
    view.scrollLeft = 0;
  }, [expanded]);

  return <div className="findingSource">
    <button type="button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>
      {expanded ? 'Show matching lines only' : 'View full file'}
    </button>
    <div className="sourceViewport" ref={viewport} tabIndex={0} role="region" aria-label={`Source code for ${path}`}>
      <pre className="sourceCode"><code>
        {expanded && line > 1 && <span className="sourceBlock">{lines.slice(0, line - 1).join('\n')}{'\n'}</span>}
        <mark className="sourceBlock sourceMatch" ref={highlight}>{lines.slice(line - 1, endLine).join('\n')}{'\n'}</mark>
        {expanded && endLine < lines.length && <span className="sourceBlock">{lines.slice(endLine).join('\n')}{'\n'}</span>}
      </code></pre>
    </div>
  </div>;
}
