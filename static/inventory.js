// Asset inventory page
(() => {
    const { el, fmt, when, getJSON } = pyLot;
    const columns = [
        { key: 'label', label: 'Asset', format: (label, a) => el('a', { href: `/inventory/${a.id}`, text: label }) },
        { key: 'ips', label: 'IP addresses', format: ips => ips.join(', ') },
        { key: 'mac', label: 'MAC' },
        { key: 'vendor', label: 'Vendor', value: a => a.device_vendor || a.mac_vendor },
        { key: 'model', label: 'Model' },
        { key: 'firmware', label: 'Firmware' },
        { key: 'serial', label: 'Serial' },
        { key: 'category', label: 'Category' },
        { key: 'sessions', label: 'Sessions', num: true },
        { key: 'first_seen', label: 'First seen', num: true, format: when },
        { key: 'last_seen', label: 'Last seen', num: true, format: when },
        { key: 'changes', label: 'Changes', num: true, format: n => n ? el('span', { class: 'status-possible', text: fmt(n) }) : '' },
        { key: 'vulnerabilities', label: 'Vulnerabilities', num: true, format: (n, a) => n
            ? el('span', { class: 'status-affected', text: fmt(n) })
            : (a.possible_vulnerabilities ? el('span', { class: 'hint', text: `${fmt(a.possible_vulnerabilities)} possible` }) : '') },
    ];
    let assets = [];
    let sort = { key: 'last_seen', desc: true };

    const value = (asset, column) => column.value ? column.value(asset) : asset[column.key];

    function compare(a, b) {
        const column = columns.find(c => c.key === sort.key);
        let x = value(a, column), y = value(b, column);
        if (Array.isArray(x)) [x, y] = [x.join(' '), y.join(' ')];
        if (x == null || x === '') return 1;  // blanks last either way
        if (y == null || y === '') return -1;
        const order = typeof x === 'number' ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true });
        return sort.desc ? -order : order;
    }

    function render() {
        const query = document.getElementById('filter').value.trim().toLowerCase();
        const changed = document.getElementById('only-changed').checked;
        const vulnerable = document.getElementById('only-vulnerable').checked;
        const missing = document.getElementById('only-missing').checked;
        const shown = assets.filter(a => (!changed || a.changes) && (!vulnerable || a.vulnerabilities) && (!missing || !a.in_latest_session)
            && (!query || [a.label, a.given_name, a.name, a.mac, a.mac_vendor, a.device_vendor, a.model, a.firmware, a.serial,
                           a.category, a.role, a.notes, ...a.all_ips].join(' ').toLowerCase().includes(query)));
        shown.sort(compare);
        const container = document.getElementById('assets');
        if (!assets.length) {
            container.replaceChildren(el('div', { class: 'empty', text: 'No assets yet. Upload a capture or run a live capture, and the devices it sees are added here.' }));
            return;
        }
        const head = el('tr', {}, ...columns.map(c => el('th', {
            class: `sortable${sort.key === c.key ? ' sorted' : ''}${sort.key === c.key && sort.desc ? ' desc' : ''}`,
            text: c.label,
            onclick: () => { sort = { key: c.key, desc: sort.key === c.key ? !sort.desc : !!c.num }; render(); } })));
        const rows = shown.slice(0, 2000).map(a => el('tr', { class: a.in_latest_session ? '' : 'faded' }, ...columns.map(c => {
            const formatted = c.format ? c.format(a[c.key], a) : (value(a, c) ?? '');
            return el('td', c.num ? { class: 'num' } : {}, formatted instanceof Node ? formatted : String(formatted));
        })));
        container.replaceChildren(
            el('p', { class: 'hint', text: `${fmt(shown.length)} of ${fmt(assets.length)} assets${shown.length > 2000 ? ', the first 2,000 shown' : ''}. Faded ones weren't in the newest session.` }),
            el('div', { class: 'table-wrap' }, el('table', { class: 'data' }, el('thead', {}, head), el('tbody', {}, ...rows))));
    }

    function renderSummary(data) {
        const box = (n, label, warn) => el('div', { class: `stat-box${warn && n ? ' warn' : ''}` }, el('strong', { text: fmt(n) }), ` ${label}`);
        document.getElementById('summary').replaceChildren(
            box(data.assets.length, 'assets'),
            box(data.assets.filter(a => a.model).length, 'with a model'),
            box(data.assets.filter(a => a.vulnerabilities).length, 'vulnerable', true),
            box(data.assets.filter(a => a.changes).length, 'changed identity', true),
            box(data.sessions, 'sessions recorded'));
    }

    for (const id of ['filter', 'only-changed', 'only-vulnerable', 'only-missing']) {
        document.getElementById(id).addEventListener('input', render);
    }
    getJSON('/api/inventory').then(data => {
        assets = data.assets;
        renderSummary(data);
        render();
    }).catch(error => {
        document.getElementById('assets').replaceChildren(el('p', { class: 'error-text', text: error.message }));
    });
})();
