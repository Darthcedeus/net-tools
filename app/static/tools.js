// Planned entries have no route until their implementation exists.
export const TOOLS = Object.freeze([
  { id: 'subdomains', name: 'Subdomain Finder', description: 'Discover subdomains from passive sources.', path: '/tools/subdomains', icon: 'search', available: true },
  { id: 'dns', name: 'DNS Lookup', description: 'Inspect DNS records for a domain.', path: null, icon: 'database', available: false },
  { id: 'tls', name: 'TLS Inspector', description: 'Check certificate names, issuer, and expiry.', path: null, icon: 'lock', available: false },
  { id: 'http', name: 'HTTP Inspector', description: 'Inspect response headers and redirect chains.', path: null, icon: 'file', available: false },
]);
export const SUBDOMAINS = TOOLS.find((tool) => tool.id === 'subdomains');
export const toolName = (id) => TOOLS.find((tool) => tool.id === id)?.name || 'Unknown tool';

const ICONS = {
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4.5 4.5"/>',
  database: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
  file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 12h8M8 16h8"/>',
};

export function renderToolDirectory(container) {
  const fragment = document.createDocumentFragment();
  for (const tool of TOOLS) {
    const row = document.createElement('li'), icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    row.className = 'tool-row';
    icon.setAttribute('viewBox', '0 0 24 24'); icon.setAttribute('aria-hidden', 'true'); icon.classList.add('tool-icon');
    // Markup is from this trusted static catalog, never from API data.
    icon.innerHTML = ICONS[tool.icon];
    const copy = document.createElement('div'), name = document.createElement('h3'), description = document.createElement('p');
    copy.className = 'tool-copy'; name.textContent = tool.name; description.textContent = tool.description; copy.append(name, description);
    const action = document.createElement(tool.available ? 'a' : 'span');
    if (tool.available) {
      action.className = 'button primary tool-action'; action.href = tool.path; action.dataset.route = 'discovery';
      action.textContent = 'Open tool'; action.setAttribute('aria-label', `Open ${tool.name}`);
    } else {
      action.className = 'planned'; action.textContent = 'Planned';
    }
    row.append(icon, copy, action); fragment.append(row);
  }
  container.replaceChildren(fragment);
}
