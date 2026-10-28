// Session page: the network graph, host and flow tables, and a details panel.
// Text from captures is attacker-controllable, so it only ever reaches the page as textContent.
(() => {
    const SESSION_ID = Number(document.body.dataset.sessionId);
    const API = `/api/sessions/${SESSION_ID}`;
    // GRASSMARLIN device categories
    const CATEGORY_COLORS = {
        PLC: '#d9534f', RTU: '#e8743b', IED: '#f0ad4e', MTU: '#8e44ad', HMI: '#c0398f',
        ICS_HOST: '#2e8b57', PROTOCOL_CONVERTER: '#16a085', NETWORK_DEVICE: '#7f8c8d',
        FIREWALL: '#34495e', WORKSTATION: '#3b7dd8', OTHER: '#95a5a6', UNKNOWN: '#95a5a6'
    };
    const UNCLASSIFIED_COLOR = '#0074D9';
    const MERGED_COLOR = '#9aa5b1';
    // Initiating roles are drawn as diamonds, responding roles as rectangles
    const ROLE_SHAPES = { MASTER: 'diamond', CLIENT: 'diamond', OPERATOR: 'diamond', ENGINEER: 'diamond',
                          SLAVE: 'round-rectangle', SERVER: 'round-rectangle' };
    // Above this many hosts, force-directed layout stalls the browser, so the graph is drawn as a plain grid
    const MAX_FORCE_LAYOUT_NODES = 1500;
    const MAX_EDGE_LABELS = 150;
    const PAGE_SIZE = 100;

    let cy = null;
    let collapse = null;  // null lets the server decide whether to merge hosts behind routers
    let graphLoaded = false;
    let tooltip = null;

    // --- helpers

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
    const portPair = f => (f.src_port || f.dst_port ? `${f.src_port} → ${f.dst_port}` : '');

    async function getJSON(url) {
        const response = await fetch(url);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || response.statusText);
        return data;
    }

    function setText(id, text) {
        document.getElementById(id).textContent = text;
    }

    function notice(message, isError = false) {
        const box = document.getElementById('notice');
        box.textContent = message || '';
        box.className = message ? (isError ? 'notice error' : 'notice') : 'notice hidden';
    }

    function download(href, filename) {
        el('a', { href, download: filename }).click();
    }

    // --- session status

    async function watchStatus() {
        let session;
        try {
            session = await getJSON(API);
        } catch (error) {
            notice(`Could not load this session: ${error.message}`, true);
            return;
        }
        setText('status', session.status);
        setText('packet-count', fmt(session.packet_count));
        document.getElementById('stop-form').classList.toggle('hidden', session.status !== 'capturing');
        document.getElementById('refresh').classList.toggle('hidden', session.status !== 'capturing');
        if (session.status === 'processing') {
            notice('Analyzing this capture. The results appear here when it finishes.');
            setTimeout(watchStatus, 1500);
            return;
        }
        if (session.status === 'failed') notice(session.error || 'This session failed.', true);
        else if (session.status === 'capturing') notice('Capturing live traffic. Use Refresh to redraw with the newest results.');
        else notice('');
        if (session.status === 'capturing') setTimeout(watchStatus, 5000);
        if (!graphLoaded) {
            graphLoaded = true;
            loadGraph();
        }
    }

    // --- graph

    function firstToken(value) {
        return value ? value.split(', ')[0] : null;
    }

    function nodeLabel(node) {
        if (node.merged) return `${node.merged.toLocaleString()} hosts via router\n${node.via_mac}`;
        const kind = [node.category, node.role].filter(Boolean).join(' ');
        return kind ? `${node.ip}\n${kind}` : node.ip;
    }

    function searchText(node) {
        const values = Object.values(node.properties).flatMap(p => p.values);
        return [node.ip, node.mac, node.vendor, node.via_mac, node.kind, ...node.fingerprints, ...values]
            .filter(Boolean).join(' ').toLowerCase();
    }

    function forceLayoutName() {
        try {
            if (cytoscape('layout', 'fcose')) return 'fcose';
        } catch (error) { /* extension not loaded */ }
        return 'cose';
    }

    // Fit the graph to the view, without blowing a handful of hosts up to giant size
    function fitGraph() {
        cy.fit(undefined, 30);
        if (cy.zoom() > 1.2) {
            cy.zoom(1.2);
            cy.center();
        }
    }

    function runLayout() {
        if (!cy) return;
        const visible = cy.nodes(':visible').filter(n => !n.isParent());
        const options = visible.length > MAX_FORCE_LAYOUT_NODES
            ? { name: 'grid', avoidOverlap: true }
            : { name: forceLayoutName(), animate: false, nodeDimensionsIncludeLabels: true,
                idealEdgeLength: 160, nodeRepulsion: 9000, packComponents: true };
        cy.elements(':visible').layout(options).run();
        fitGraph();
    }

    async function loadGraph() {
        const query = collapse === null ? '' : `?collapse=${collapse}`;
        let data;
        try {
            data = await getJSON(`${API}/graph${query}`);
        } catch (error) {
            document.getElementById('cy').textContent = `Could not load the graph: ${error.message}`;
            return;
        }
        const hostCount = data.nodes.reduce((sum, n) => sum + (n.merged || 1), 0);
        setText('host-count', fmt(hostCount));
        setText('classified-count', fmt(data.nodes.filter(n => n.category || n.role).length));
        setText('edge-count', fmt(data.edges.length));

        const toggle = document.getElementById('collapse-toggle');
        if (data.collapsed) {
            toggle.textContent = `Show all ${data.external_hosts.toLocaleString()} hosts behind routers`;
            toggle.classList.remove('hidden');
        } else if (collapse === false) {
            toggle.textContent = 'Merge hosts behind routers';
            toggle.classList.remove('hidden');
        } else {
            toggle.classList.add('hidden');
        }

        const large = data.nodes.length > MAX_FORCE_LAYOUT_NODES;
        const showEdgeLabels = data.edges.length <= MAX_EDGE_LABELS;
        const categories = new Set();
        const groups = large ? [] : data.groups.map(g => ({ data: { id: `group:${g.id}`, label: g.label, isGroup: true } }));
        const nodes = data.nodes.map(node => {
            const category = firstToken(node.category);
            if (category) categories.add(category);
            const item = {
                id: node.id, label: nodeLabel(node), host: node, search: searchText(node),
                color: node.merged ? MERGED_COLOR : (CATEGORY_COLORS[category] || UNCLASSIFIED_COLOR),
                shape: node.merged ? 'round-hexagon' : (ROLE_SHAPES[firstToken(node.role)] || 'ellipse'),
                faded: !['unicast', 'merged'].includes(node.kind)
            };
            if (!large && node.group) item.parent = `group:${node.group}`;
            return { data: item };
        });
        const edges = data.edges.map(edge => ({
            data: {
                id: `${edge.source}>${edge.target}`, source: edge.source, target: edge.target, edge,
                label: showEdgeLabels ? edge.protocols.slice(0, 3).join(', ') + (edge.protocols.length > 3 ? '…' : '') : '',
                width: Math.min(1 + Math.log10(1 + edge.bytes) / 1.5, 8),
                search: edge.protocols.join(' ').toLowerCase()
            }
        }));

        const legend = document.getElementById('legend');
        legend.replaceChildren();
        [...categories].sort().forEach(category => {
            const item = el('span', { text: category });
            item.style.setProperty('--swatch', CATEGORY_COLORS[category] || UNCLASSIFIED_COLOR);
            legend.append(item);
        });
        if (categories.size) {
            const item = el('span', { text: 'Unclassified' });
            item.style.setProperty('--swatch', UNCLASSIFIED_COLOR);
            legend.append(item, el('span', { class: 'shape-note', text: 'Diamond: master/client · Rectangle: slave/server' }));
        }

        if (cy) cy.destroy();
        // Thousands of hosts: skip labels, arrows and curves, which dominate drawing time (hover still shows each host)
        const fastStyle = large ? [
            { selector: 'node', style: { 'label': '', 'width': 24, 'height': 24 } },
            { selector: 'edge', style: { 'label': '', 'curve-style': 'haystack', 'target-arrow-shape': 'none', 'width': 1 } }
        ] : [];
        cy = cytoscape({
            container: document.getElementById('cy'),
            elements: groups.concat(nodes, edges),
            hideEdgesOnViewport: large,
            textureOnViewport: large,
            style: [
                { selector: 'node', style: { 'label': 'data(label)', 'color': 'white', 'text-valign': 'center', 'text-halign': 'center',
                                             'width': 120, 'height': 60, 'font-size': 10, 'font-weight': 'bold',
                                             'text-wrap': 'wrap', 'text-max-width': 110 } },
                { selector: 'node[color]', style: { 'background-color': 'data(color)', 'shape': 'data(shape)' } },
                { selector: 'node[?faded]', style: { 'opacity': 0.55, 'width': 90, 'height': 40 } },
                { selector: ':parent', style: { 'background-color': '#eef3f8', 'background-opacity': 0.7, 'border-color': '#9fb3c8',
                                                'border-width': 1, 'shape': 'round-rectangle', 'color': '#555', 'text-valign': 'top',
                                                'font-size': 12, 'font-weight': 'normal', 'padding': 20 } },
                { selector: 'edge', style: { 'label': 'data(label)', 'width': 'data(width)', 'line-color': '#999',
                                             'target-arrow-shape': 'triangle', 'target-arrow-color': '#999', 'curve-style': 'bezier',
                                             'font-size': 9, 'text-rotation': 'autorotate', 'color': '#444' } },
                { selector: '.selected', style: { 'border-width': 4, 'border-color': '#222', 'line-color': '#222', 'target-arrow-color': '#222' } },
                { selector: '.filtered-out', style: { 'display': 'none' } }
            ].concat(fastStyle)
        });
        runLayout();

        cy.on('tap', 'node', event => {
            const node = event.target;
            if (node.data('isGroup')) return;
            select(node);
            const host = node.data('host');
            if (host.merged) showMergedPanel(host);
            else showHostPanel(host.ip);
        });
        cy.on('tap', 'edge', event => {
            select(event.target);
            showEdgePanel(event.target.data('edge'));
        });
        cy.on('mouseover', 'node', event => {
            const host = event.target.data('host');
            if (!host) return;
            const lines = host.merged ? [`${host.merged} hosts reached via router ${host.via_mac}`]
                : [host.ip, host.vendor ? `${host.mac} (${host.vendor})` : host.mac, [host.category, host.role].filter(Boolean).join(' ')];
            showTooltip(event, lines.filter(Boolean).join('\n') + '\nClick for details');
        });
        cy.on('mouseout', 'node', hideTooltip);
        applyGraphFilter();
    }

    function select(element) {
        cy.elements().removeClass('selected');
        element.addClass('selected');
    }

    function showTooltip(event, text) {
        hideTooltip();
        tooltip = el('div', { class: 'tooltip', text });
        document.body.append(tooltip);
        const original = event.originalEvent;
        tooltip.style.left = `${(original ? original.pageX : 0) + 16}px`;
        tooltip.style.top = `${(original ? original.pageY : 0) + 8}px`;
    }

    function hideTooltip() {
        if (tooltip) tooltip.remove();
        tooltip = null;
    }

    function applyGraphFilter() {
        if (!cy) return;
        const filter = document.getElementById('graph-filter').value.trim().toLowerCase();
        cy.batch(() => {
            cy.elements().removeClass('filtered-out');
            if (!filter) return;
            // Keep matching hosts and connections, the hosts at either end of a matching connection, and their groups
            const hosts = cy.nodes().filter(n => !n.isParent() && n.data('search').includes(filter));
            const edges = cy.edges().filter(e => e.data('search').includes(filter) || (hosts.contains(e.source()) && hosts.contains(e.target())));
            const shown = hosts.union(edges.connectedNodes());
            const keep = shown.union(edges).union(shown.parents());
            cy.elements().not(keep).addClass('filtered-out');
        });
        runLayout();
    }

    // --- details panel

    function openPanel(title, ...content) {
        const panel = document.getElementById('panel');
        panel.replaceChildren(el('button', { class: 'close', title: 'Close', text: '×', onclick: closePanel }),
                              el('h2', { text: title }), ...content);
        panel.classList.remove('hidden');
        panel.scrollTop = 0;
    }

    function closePanel() {
        document.getElementById('panel').classList.add('hidden');
        if (cy) cy.elements().removeClass('selected');
    }

    function facts(pairs) {
        return el('dl', {}, ...pairs.filter(([, value]) => value != null && value !== '')
            .flatMap(([label, value]) => [el('dt', { text: label }), el('dd', { text: String(value) })]));
    }

    function table(columns, rows, onRowClick) {
        const head = el('tr', {}, ...columns.map(c => el('th', { text: c.label })));
        const body = rows.map(row => el('tr', onRowClick ? { class: 'clickable', onclick: () => onRowClick(row) } : {},
            ...columns.map(c => el('td', c.num ? { class: 'num' } : {}, String((c.format || (v => v ?? ''))(row[c.key], row))))));
        return el('div', { class: 'table-wrap' }, el('table', { class: 'data' }, el('thead', {}, head), el('tbody', {}, ...body)));
    }

    const PANEL_FLOW_COLUMNS = [
        { key: 'src', label: 'Source' }, { key: 'dst', label: 'Destination' }, { key: 'protocol', label: 'Protocol' },
        { key: 'src_port', label: 'Ports', format: (v, f) => portPair(f) },
        { key: 'packets', label: 'Packets', num: true, format: fmt }, { key: 'bytes', label: 'Bytes', num: true, format: fmt }
    ];

    async function showHostPanel(ip) {
        openPanel(ip, el('p', { text: 'Loading…' }));
        let host;
        try {
            host = await getJSON(`${API}/hosts/${encodeURIComponent(ip)}`);
        } catch (error) {
            openPanel(ip, el('p', { text: `Could not load this host: ${error.message}` }));
            return;
        }
        const properties = Object.entries(host.properties).map(([name, p]) => ({ name, values: p.values.join(', '), confidence: p.confidence }));
        openPanel(ip,
            facts([['MAC', host.mac], ['Vendor', host.vendor], ['Reached via router', host.via_mac],
                   ['Address type', host.kind === 'unicast' ? null : host.kind],
                   ['ARP', host.arp.map(a => a.mac).join(', ')],
                   ['Packets', `${fmt(host.packets_sent)} sent, ${fmt(host.packets_received)} received`],
                   ['Bytes', `${fmt(host.bytes_sent)} sent, ${fmt(host.bytes_received)} received`],
                   ['First seen', when(host.first_seen)], ['Last seen', when(host.last_seen)]]),
            el('h3', { text: 'Classification' }),
            properties.length
                ? table([{ key: 'name', label: 'Property' }, { key: 'values', label: 'Value' },
                         { key: 'confidence', label: 'Confidence', num: true }], properties)
                : el('p', { text: 'No fingerprint matched this host.' }),
            properties.length ? el('p', { class: 'legend', text: 'Confidence runs from 1 (high) to 5 (low). Values shown are those at the best confidence, as in GRASSMARLIN.' }) : null,
            host.evidence.length ? el('h3', { text: `Fingerprint evidence (${host.evidence.length})` }) : null,
            host.evidence.length
                ? table([{ key: 'fingerprint', label: 'Fingerprint' }, { key: 'name', label: 'Property' }, { key: 'value', label: 'Value' },
                         { key: 'confidence', label: 'Conf.', num: true }, { key: 'count', label: 'Packets', num: true, format: fmt },
                         { key: 'first_frame', label: 'First frame', num: true }], host.evidence)
                : null,
            el('h3', { text: `Flows (${host.flows.length < host.flow_count ? `busiest ${host.flows.length} of ${fmt(host.flow_count)}` : fmt(host.flow_count)})` }),
            table(PANEL_FLOW_COLUMNS, host.flows),
            el('p', {}, el('a', { href: '#', text: 'Show all of its flows in the Flows tab',
                                  onclick: event => { event.preventDefault(); closePanel(); flowsTable.setHost(ip); showTab('flows'); } })));
    }

    function showMergedPanel(node) {
        openPanel(`${node.merged.toLocaleString()} hosts via router`,
            facts([['Router MAC', node.via_mac],
                   ['Packets', `${fmt(node.packets_sent)} sent, ${fmt(node.packets_received)} received`],
                   ['Bytes', `${fmt(node.bytes_sent)} sent, ${fmt(node.bytes_received)} received`]]),
            el('p', { text: 'These hosts are on other networks: their traffic arrived through this router, so their own MAC addresses and vendors are unknown.' }),
            el('p', {}, el('a', { href: '#', text: 'List them in the Hosts tab',
                                  onclick: event => { event.preventDefault(); closePanel(); hostsTable.setQuery(node.via_mac); showTab('hosts'); } })));
    }

    async function showEdgePanel(edge) {
        const summary = facts([['Protocols', edge.protocols.join(', ')], ['Flows', fmt(edge.flows)], ['Packets', fmt(edge.packets)],
                               ['Bytes', fmt(edge.bytes)], ['First seen', when(edge.first_seen)], ['Last seen', when(edge.last_seen)]]);
        const title = `${edge.source} → ${edge.target}`;
        if (edge.source.startsWith('via:') || edge.target.startsWith('via:')) {
            openPanel(title, summary, el('p', { text: 'This connection includes merged hosts. Show every host behind routers to see individual flows.' }));
            return;
        }
        openPanel(title, summary, el('p', { text: 'Loading flows…' }));
        try {
            const data = await getJSON(`${API}/flows?src=${encodeURIComponent(edge.source)}&dst=${encodeURIComponent(edge.target)}&limit=${PAGE_SIZE}`);
            openPanel(title, summary, el('h3', { text: `Flows (${data.flows.length < data.total ? `busiest ${data.flows.length} of ${fmt(data.total)}` : fmt(data.total)})` }),
                      table(PANEL_FLOW_COLUMNS, data.flows));
        } catch (error) {
            openPanel(title, summary, el('p', { text: `Could not load flows: ${error.message}` }));
        }
    }

    // --- host and flow tables

    class PagedTable {
        constructor({ name, endpoint, rowsKey, columns, sort, order, onRowClick }) {
            Object.assign(this, { name, endpoint, rowsKey, columns, onRowClick });
            this.state = { q: '', sort, order, offset: 0, host: null };
            this.loaded = false;
            this.container = document.getElementById(`${name}-table`);
            this.pager = document.getElementById(`${name}-pager`);
            const search = document.getElementById(`${name}-filter`);
            let timer = null;
            search.addEventListener('input', () => {
                clearTimeout(timer);
                timer = setTimeout(() => { this.state.q = search.value; this.state.offset = 0; this.load(); }, 300);
            });
            this.search = search;
        }

        setQuery(q) {
            this.search.value = q;
            this.state.q = q;
            this.state.offset = 0;
            this.loaded = false;
        }

        setHost(host) {
            this.state.host = host;
            this.state.offset = 0;
            this.loaded = false;
            const chip = document.getElementById(`${this.name}-host`);
            if (chip) {
                chip.classList.toggle('hidden', !host);
                document.getElementById(`${this.name}-host-label`).textContent = host ? `Only flows to or from ${host}` : '';
            }
        }

        async load() {
            this.loaded = true;
            const params = new URLSearchParams({ q: this.state.q, sort: this.state.sort, order: this.state.order,
                                                 offset: this.state.offset, limit: PAGE_SIZE });
            if (this.state.host) params.set('host', this.state.host);
            let data;
            try {
                data = await getJSON(`${this.endpoint}?${params}`);
            } catch (error) {
                this.container.replaceChildren(el('div', { class: 'empty', text: `Could not load: ${error.message}` }));
                return;
            }
            const rows = data[this.rowsKey];
            const head = el('tr', {}, ...this.columns.map(c => {
                const sorted = this.state.sort === c.key;
                return el('th', { class: `sortable${sorted ? ' sorted' : ''}${sorted && this.state.order === 'desc' ? ' desc' : ''}`,
                                  text: c.label, onclick: () => this.sortBy(c) });
            }));
            const body = rows.map(row => el('tr', this.onRowClick ? { class: 'clickable', onclick: () => this.onRowClick(row) } : {},
                ...this.columns.map(c => el('td', c.num ? { class: 'num' } : {}, String((c.format || (v => v ?? ''))(row[c.key], row))))));
            this.container.replaceChildren(rows.length
                ? el('div', { class: 'table-wrap' }, el('table', { class: 'data' }, el('thead', {}, head), el('tbody', {}, ...body)))
                : el('div', { class: 'empty', text: 'Nothing matches.' }));
            const first = data.total ? this.state.offset + 1 : 0;
            const last = this.state.offset + rows.length;
            this.pager.replaceChildren(
                el('button', { class: 'btn secondary', text: '‹ Previous', onclick: () => this.page(-1), ...(this.state.offset ? {} : { disabled: '' }) }),
                el('span', { text: `${fmt(first)}–${fmt(last)} of ${fmt(data.total)}` }),
                el('button', { class: 'btn secondary', text: 'Next ›', onclick: () => this.page(1), ...(last < data.total ? {} : { disabled: '' }) }));
        }

        sortBy(column) {
            if (this.state.sort === column.key) this.state.order = this.state.order === 'desc' ? 'asc' : 'desc';
            else Object.assign(this.state, { sort: column.key, order: column.num ? 'desc' : 'asc' });
            this.state.offset = 0;
            this.load();
        }

        page(direction) {
            this.state.offset = Math.max(0, this.state.offset + direction * PAGE_SIZE);
            this.load();
        }
    }

    const hostsTable = new PagedTable({
        name: 'hosts', endpoint: `${API}/hosts`, rowsKey: 'hosts', sort: 'ip', order: 'asc',
        onRowClick: row => showHostPanel(row.ip),
        columns: [
            { key: 'ip', label: 'IP' }, { key: 'mac', label: 'MAC' }, { key: 'vendor', label: 'Vendor' },
            { key: 'category', label: 'Category' }, { key: 'role', label: 'Role' }, { key: 'kind', label: 'Type' },
            { key: 'via_mac', label: 'Via router' },
            { key: 'packets_sent', label: 'Pkts sent', num: true, format: fmt },
            { key: 'packets_received', label: 'Pkts received', num: true, format: fmt },
            { key: 'bytes_sent', label: 'Bytes sent', num: true, format: fmt },
            { key: 'last_seen', label: 'Last seen', num: true, format: when }
        ]
    });

    const flowsTable = new PagedTable({
        name: 'flows', endpoint: `${API}/flows`, rowsKey: 'flows', sort: 'packets', order: 'desc',
        onRowClick: row => showHostPanel(row.src),
        columns: [
            { key: 'src', label: 'Source' }, { key: 'dst', label: 'Destination' }, { key: 'protocol', label: 'Protocol' },
            { key: 'transport', label: 'IP proto', num: true }, { key: 'src_port', label: 'Src port', num: true },
            { key: 'dst_port', label: 'Dst port', num: true },
            { key: 'packets', label: 'Packets', num: true, format: fmt }, { key: 'bytes', label: 'Bytes', num: true, format: fmt },
            { key: 'first_seen', label: 'First seen', num: true, format: when }, { key: 'last_seen', label: 'Last seen', num: true, format: when }
        ]
    });

    // --- tabs and controls

    function showTab(name) {
        document.querySelectorAll('.tab').forEach(tab => tab.classList.toggle('active', tab.dataset.tab === name));
        document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.toggle('hidden', pane.id !== `tab-${name}`));
        if (name === 'graph' && cy) {
            cy.resize();
            fitGraph();
        }
        if (name === 'hosts' && !hostsTable.loaded) hostsTable.load();
        if (name === 'flows' && !flowsTable.loaded) flowsTable.load();
    }

    document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => showTab(tab.dataset.tab)));
    document.getElementById('flows-host-clear').addEventListener('click', () => { flowsTable.setHost(null); flowsTable.load(); });

    let filterTimer = null;
    document.getElementById('graph-filter').addEventListener('input', () => {
        clearTimeout(filterTimer);
        filterTimer = setTimeout(applyGraphFilter, 300);
    });
    document.getElementById('fit').addEventListener('click', () => cy && fitGraph());
    document.getElementById('relayout').addEventListener('click', runLayout);
    document.getElementById('refresh').addEventListener('click', () => {
        loadGraph();
        if (hostsTable.loaded) hostsTable.load();
        if (flowsTable.loaded) flowsTable.load();
    });
    document.getElementById('collapse-toggle').addEventListener('click', async event => {
        collapse = collapse === false ? true : false;
        const button = event.target;
        button.disabled = true;
        button.textContent = collapse ? 'Merging…' : 'Drawing every host, this can take a while…';
        await loadGraph();
        button.disabled = false;
    });
    document.getElementById('export-png').addEventListener('click', () => {
        if (cy) download(cy.png({ full: true, scale: 2, bg: '#ffffff' }), `session_${SESSION_ID}_graph.png`);
    });
    document.addEventListener('keydown', event => { if (event.key === 'Escape') closePanel(); });

    watchStatus();
})();
