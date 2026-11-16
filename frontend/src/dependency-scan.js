const MAX_PACKAGES = 500;
const NAME = /^(?:@[A-Za-z0-9_.-]+\/)?[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const VERSION = /^[0-9][A-Za-z0-9_.+!-]{0,79}$/;
const PIN = /^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]\n]*\])?\s*==\s*([^\s;#]+)\s*(?:[;#].*)?$/;
const ADVISORY = /^[A-Za-z0-9][A-Za-z0-9.-]{0,79}$/;

export function collectDependencies(source, path, packages) {
  const filename = path.replaceAll('\\', '/').split('/').at(-1);
  let ecosystem;
  let candidates;
  if (filename === 'package-lock.json') {
    let lock;
    try {
      lock = JSON.parse(source);
    } catch {
      return;
    }
    const entries = lock?.packages;
    if (!entries || typeof entries !== 'object' || Array.isArray(entries)) return;
    ecosystem = 'npm';
    candidates = Object.entries(entries)
      .filter(([key, entry]) => key.includes('node_modules/') && entry && typeof entry === 'object' && !entry.link)
      .map(([key, entry]) => [entry.name ?? key.split('node_modules/').at(-1), entry.version]);
  } else if (filename === 'requirements.txt') {
    ecosystem = 'PyPI';
    candidates = source.split('\n').flatMap(line => {
      const match = PIN.exec(line);
      return match ? [match.slice(1)] : [];
    });
  } else {
    return;
  }

  for (let [name, version] of candidates) {
    if (packages.size > MAX_PACKAGES) return;
    if (typeof name !== 'string' || name.length > 214 || !NAME.test(name) ||
        typeof version !== 'string' || !VERSION.test(version)) continue;
    if (ecosystem === 'PyPI') name = name.toLowerCase().replace(/[-_.]+/g, '-');
    const key = JSON.stringify([ecosystem, name, version]);
    if (!packages.has(key)) packages.set(key, { ecosystem, name, version, path });
  }
}

export async function scanDependencies(report, packages, request = fetch) {
  if (!packages.size) {
    report.dependencyScan = { status: 'no-packages', checked: 0 };
    return;
  }

  const selected = [...packages.values()].slice(0, MAX_PACKAGES);
  const queries = selected.map(({ ecosystem, name, version }) => ({ package: { ecosystem, name }, version }));
  let results;
  try {
    const response = await request('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'omit',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(8000),
      body: JSON.stringify({ queries }),
    });
    if (!response.ok) throw new Error('OSV request failed');
    ({ results } = await response.json());
    if (!Array.isArray(results) || results.length !== selected.length ||
        !results.every(result => result && typeof result === 'object' && !Array.isArray(result))) {
      throw new Error('Unexpected OSV response');
    }
  } catch {
    report.dependencyScan = { status: 'unavailable', checked: 0 };
    return;
  }

  const dependencyFindings = selected.flatMap(({ name, version, path }, index) => {
    const { vulns } = results[index];
    if (!Array.isArray(vulns)) return [];
    const advisories = [...new Set(vulns.map(item => item?.id).filter(id => typeof id === 'string' && ADVISORY.test(id)))].sort();
    if (!advisories.length) return [];
    return [{
      id: `DEPENDENCY-${index + 1}`,
      title: `Known vulnerability in ${name} ${version}`,
      severity: 'medium',
      path,
      line: null,
      advisories,
      remediation: 'Review the linked advisories for severity and affected versions, then update the dependency.',
      status: 'Needs review',
    }];
  });
  const firstLow = report.findings.findIndex(finding => finding.severity === 'low');
  report.findings.splice(firstLow < 0 ? report.findings.length : firstLow, 0, ...dependencyFindings);
  const partial = packages.size > selected.length || results.some(result => result.next_page_token);
  report.dependencyScan = { status: partial ? 'partial' : 'complete', checked: selected.length };
}
