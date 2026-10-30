// Helpers shared by pyLot's pages. Text from captures and imports only reaches the page as textContent.
const pyLot = (() => {
    function el(tag, props = {}, ...children) {
        const node = document.createElement(tag);
        for (const [key, value] of Object.entries(props)) {
            if (key === 'class') node.className = value;
            else if (key === 'text') node.textContent = value;
            else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
            else node.setAttribute(key, value);
        }
        children.filter(child => child != null).forEach(child => node.append(child));  // strings become text nodes
        return node;
    }

    const fmt = n => (n == null ? '' : Number(n).toLocaleString());
    const when = t => (t == null ? '' : new Date(t * 1000).toLocaleString());

    async function request(url, options = {}) {
        const response = await fetch(url, options);
        if (response.status === 401) {  // signed out (expired, or the password changed): sign in and come back
            location.assign(`/login?next=${encodeURIComponent(location.pathname + location.search)}`);
        }
        const data = response.status === 204 ? {} : await response.json();
        if (!response.ok) throw new Error(data.error || response.statusText);
        return data;
    }

    const getJSON = url => request(url);
    const sendJSON = (url, method, body) => request(url, { method, headers: { 'Content-Type': 'application/json' },
                                                         body: body === undefined ? undefined : JSON.stringify(body) });

    function table(columns, rows, onRowClick) {
        const head = el('tr', {}, ...columns.map(c => el('th', { text: c.label })));
        const body = rows.map(row => el('tr', onRowClick ? { class: 'clickable', onclick: () => onRowClick(row) } : {},
            ...columns.map(c => {
                const value = (c.format || (v => v ?? ''))(row[c.key], row);
                return el('td', c.num ? { class: 'num' } : {}, value instanceof Node ? value : String(value));
            })));
        return el('div', { class: 'table-wrap' }, el('table', { class: 'data' }, el('thead', {}, head), el('tbody', {}, ...body)));
    }

    // Viewers can't change anything, so pages leave out the controls that would; the server checks too
    const canEdit = document.querySelector('.account-bar')?.dataset.role !== 'viewer';

    return { el, fmt, when, request, getJSON, sendJSON, table, canEdit };
})();
