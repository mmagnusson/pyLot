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
    // Connections that carried industrial operations changing a device: program and control first, then writes
    const IMPACT_COLORS = { program: '#c0392b', control: '#c0392b', write: '#e8743b' };
    const KIND_LABELS = { program: 'Program', control: 'Control', write: 'Write', read: 'Read', diagnostic: 'Diagnostic',
                          data: 'Data', session: 'Session', error: 'Error', other: 'Other' };

    let cy = null;
    let collapse = null;  // null lets the server decide whether to merge hosts behind routers
    let baseline = '';    // session id to mark changes against, or '' for none
    let graphLoaded = false;
    let tooltip = null;

    // --- helpers

    const { el, fmt, when, getJSON, sendJSON, table } = pyLot;
    const portPair = f => (f.src_port || f.dst_port ? `${f.src_port} → ${f.dst_port}` : '');

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
        const reanalyze = document.getElementById('reanalyze-form');
        if (reanalyze) reanalyze.classList.toggle('hidden', !['ready', 'failed'].includes(session.status));
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
            loadAlerts();
        }
    }

    // --- alerts

    let alertList = [];
    const severityBadge = severity => el('span', { class: `severity severity-${severity}`, text: severity });
    const hostLink = ip => el('a', { href: '#', text: ip, onclick: event => { event.preventDefault(); showHostPanel(ip); } });
    const ALERT_COLUMNS = [
        { key: 'severity', label: 'Severity', format: severityBadge }, { key: 'title', label: 'Alert' },
        { key: 'src', label: 'Client', format: (v, a) => v || (a.clients ? `${a.clients.length} hosts` : '') },
        { key: 'dst', label: 'Device', format: v => v || 'many' },
        { key: 'protocols', label: 'Protocols', format: v => v.join(', ') },
        { key: 'operations', label: 'Operations', format: v => v.slice(0, 3).join(', ') + (v.length > 3 ? ` and ${v.length - 3} more` : '') },
        { key: 'count', label: 'Count', num: true, format: fmt }, { key: 'first_seen', label: 'First seen', format: when },
        { key: 'first_frame', label: 'First frame', num: true }
    ];

    async function loadAlerts() {
        let data;
        try {
            data = await getJSON(`${API}/alerts`);
        } catch (error) {
            document.getElementById('alerts-table').replaceChildren(el('div', { class: 'empty', text: `Could not load alerts: ${error.message}` }));
            return;
        }
        alertList = data.alerts;
        const box = document.getElementById('alert-box');
        const total = alertList.length;
        box.classList.toggle('hidden', !total);
        box.classList.toggle('alert-high', data.counts.high > 0);
        setText('alert-count', fmt(data.counts.high ? data.counts.high : total));
        setText('alert-label', data.counts.high ? `high-severity alert${data.counts.high === 1 ? '' : 's'} (${fmt(total)} in all)`
                                                : `alert${total === 1 ? '' : 's'}`);
        renderAlerts();
    }

    function renderAlerts() {
        const severity = document.getElementById('alerts-severity').value;
        const query = document.getElementById('alerts-filter').value.trim().toLowerCase();
        const shown = alertList.filter(a => (!severity || a.severity === severity) && (!query || [a.title, a.src, a.dst, ...(a.clients || []),
            ...a.protocols, ...a.operations].filter(Boolean).join(' ').toLowerCase().includes(query)));
        document.getElementById('alerts-table').replaceChildren(shown.length
            ? table(ALERT_COLUMNS, shown, showAlertPanel)
            : el('div', { class: 'empty', text: alertList.length ? 'Nothing matches.' : 'No risky activity found in this session.' }));
    }

    function showAlertPanel(alert) {
        const clients = alert.src ? [alert.src] : (alert.clients || []);
        openPanel(alert.title,
            el('p', {}, severityBadge(alert.severity)),
            el('p', { text: alert.description }),
            facts([['Protocols', alert.protocols.join(', ')], ['Count', fmt(alert.count)], ['First seen', when(alert.first_seen)],
                   ['Last seen', when(alert.last_seen)], ['First frame', alert.first_frame]]),
            clients.length ? el('h3', { text: clients.length === 1 ? 'Client' : 'Clients' }) : null,
            clients.length ? el('p', {}, ...clients.flatMap((ip, i) => [i ? ', ' : null, hostLink(ip)])) : null,
            alert.dst ? el('h3', { text: 'Device' }) : null,
            alert.dst ? el('p', {}, hostLink(alert.dst)) : null,
            alert.operations.length ? el('h3', { text: 'Operations' }) : null,
            alert.operations.length ? el('ul', {}, ...alert.operations.map(name => el('li', { text: name }))) : null,
            alert.operations.length ? el('p', {}, el('a', { href: '#', text: 'Show them in the Operations tab', onclick: event => {
                event.preventDefault();
                closePanel();
                operationsTable.setHost(alert.dst || alert.src);
                showTab('operations');
            } })) : null);
    }

    function alertsSection(alerts) {
        if (!alerts || !alerts.length) return [];
        return [el('h3', { text: `Alerts (${alerts.length})` }),
                table([{ key: 'severity', label: 'Severity', format: severityBadge }, { key: 'title', label: 'Alert' },
                       { key: 'src', label: 'Client', format: (v, a) => v || (a.clients ? `${a.clients.length} hosts` : '') },
                       { key: 'dst', label: 'Device', format: v => v || 'many' }, { key: 'count', label: 'Count', num: true, format: fmt }],
                      alerts, showAlertPanel)];
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
        return [node.ip, node.mac, node.vendor, node.via_mac, node.kind, node.change, ...node.fingerprints, ...node.layer2, ...values]
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
        const params = new URLSearchParams();
        if (collapse !== null) params.set('collapse', collapse);
        if (baseline) params.set('baseline', baseline);
        const query = params.toString() ? `?${params}` : '';
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
        const groups = large ? [] : data.groups.map(g => ({ data: { id: `group:${g.id}`, label: g.label, isGroup: true, group: g } }));
        const nodes = data.nodes.map(node => {
            const category = firstToken(node.category);
            if (category) categories.add(category);
            const item = {
                id: node.id, label: nodeLabel(node), host: node, search: searchText(node),
                color: node.merged ? MERGED_COLOR : (CATEGORY_COLORS[category] || UNCLASSIFIED_COLOR),
                shape: node.merged ? 'round-hexagon' : (ROLE_SHAPES[firstToken(node.role)] || 'ellipse'),
                faded: !['unicast', 'merged'].includes(node.kind),
                change: node.change || ''
            };
            if (!large && node.group) item.parent = `group:${node.group}`;
            return { data: item };
        });
        const impacts = new Set();
        const edges = data.edges.map(edge => {
            const impact = ['program', 'control', 'write'].find(kind => edge.operations.includes(kind)) || '';
            if (impact) impacts.add(impact === 'write' ? 'write' : 'program');
            return { data: {
                id: `${edge.source}>${edge.target}`, source: edge.source, target: edge.target, edge,
                label: showEdgeLabels ? edge.protocols.slice(0, 3).join(', ') + (edge.protocols.length > 3 ? '…' : '') : '',
                width: Math.min(1 + Math.log10(1 + edge.bytes) / 1.5, 8),
                search: [...edge.protocols, ...edge.operations].join(' ').toLowerCase() + (edge.new ? ' new' : ''),
                isNew: !!edge.new, impact, impactColor: IMPACT_COLORS[impact] || '#999'
            } };
        });

        const legend = document.getElementById('legend');
        legend.replaceChildren();
        [...categories].sort().forEach(category => {
            const item = el('span', { text: category });
            item.style.setProperty('--swatch', CATEGORY_COLORS[category] || UNCLASSIFIED_COLOR);
            legend.append(item);
        });
        for (const [kind, text] of [['program', 'Program or control operations'], ['write', 'Write operations']]) {
            if (!impacts.has(kind)) continue;
            const item = el('span', { class: 'line-swatch', text });
            item.style.setProperty('--swatch', IMPACT_COLORS[kind]);
            legend.append(item);
        }
        if (data.baseline) {
            const b = data.baseline;
            for (const [text, color] of [['New since baseline', '#1e9e4a'], ['Changed since baseline', '#f0ad4e']]) {
                const item = el('span', { text });
                item.style.setProperty('--swatch', color);
                legend.append(item);
            }
            notice(`Since the baseline: ${fmt(b.new_hosts)} new hosts, ${fmt(b.changed_hosts)} changed, ${fmt(b.new_conversations)} new conversations, `
                   + `${fmt(b.missing_hosts)} hosts no longer seen. Filter on "new" or "changed" to show only those.`);
        } else if (document.getElementById('notice').textContent.startsWith('Since the baseline')) {
            notice('');
        }
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
                { selector: 'edge[impact != ""]', style: { 'line-color': 'data(impactColor)', 'target-arrow-color': 'data(impactColor)' } },
                { selector: 'node[change = "new"]', style: { 'border-width': 5, 'border-color': '#1e9e4a' } },
                { selector: 'node[change = "changed"]', style: { 'border-width': 5, 'border-color': '#f0ad4e' } },
                { selector: 'edge[?isNew]', style: { 'line-color': '#1e9e4a', 'target-arrow-color': '#1e9e4a' } },
                { selector: '.selected', style: { 'border-width': 4, 'border-color': '#222', 'line-color': '#222', 'target-arrow-color': '#222' } },
                { selector: '.filtered-out', style: { 'display': 'none' } }
            ].concat(fastStyle)
        });
        runLayout();

        cy.on('tap', 'node', event => {
            const node = event.target;
            if (node.data('isGroup')) {
                showGroupPanel(node.data('group'));
                return;
            }
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
            const lines = host.merged ? [`${host.merged} hosts reached via router ${host.via_mac}`,
                                         host.new_hosts ? `${host.new_hosts} new since the baseline` : null]
                : [host.ip, host.vendor ? `${host.mac} (${host.vendor})` : host.mac, [host.category, host.role].filter(Boolean).join(' '),
                   [host.model, host.firmware && `firmware ${host.firmware}`].filter(Boolean).join(', '),
                   host.change === 'new' ? 'New since the baseline' : null,
                   ...(host.changes || []).map(c => `${c.what}: ${c.before || 'none'} → ${c.now || 'none'}`)];
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
        if (physicalCy) physicalCy.elements().removeClass('selected');
    }

    function facts(pairs) {
        return el('dl', {}, ...pairs.filter(([, value]) => value != null && value !== '')
            .flatMap(([label, value]) => [el('dt', { text: label }), el('dd', { text: String(value) })]));
    }

    const PANEL_FLOW_COLUMNS = [
        { key: 'src', label: 'Source' }, { key: 'dst', label: 'Destination' }, { key: 'protocol', label: 'Protocol' },
        { key: 'src_port', label: 'Ports', format: (v, f) => portPair(f) },
        { key: 'packets', label: 'Packets', num: true, format: fmt }, { key: 'bytes', label: 'Bytes', num: true, format: fmt }
    ];

    function baselineChanges(ip) {
        const node = cy && cy.getElementById(ip);
        const host = node && node.length ? node.data('host') : null;
        if (!host || !host.change) return [];
        if (host.change === 'new') return [el('p', { class: 'notice', text: 'New since the baseline.' })];
        return [el('h3', { text: 'Changed since the baseline' }),
                table([{ key: 'what', label: 'What' }, { key: 'before', label: 'Before' }, { key: 'now', label: 'Now' }], host.changes)];
    }

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
            ...baselineChanges(ip),
            ...alertsSection(host.alerts),
            ...identitySection(host),
            facts([['Network', host.network], ['MAC', host.mac], ['Vendor', host.vendor], ['Reached via router', host.via_mac],
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
            ...layer2Evidence(host.layer2_evidence),
            host.mac ? el('p', {}, el('a', { href: '#', text: `Layer-2 details for ${host.mac}`,
                                            onclick: event => { event.preventDefault(); showDevicePanel(host.mac); } })) : null,
            ...operationsSection(host.operations, host.operation_count, ip),
            el('h3', { text: `Flows (${host.flows.length < host.flow_count ? `busiest ${host.flows.length} of ${fmt(host.flow_count)}` : fmt(host.flow_count)})` }),
            table(PANEL_FLOW_COLUMNS, host.flows),
            el('p', {}, el('a', { href: '#', text: 'Show all of its flows in the Flows tab',
                                  onclick: event => { event.preventDefault(); closePanel(); flowsTable.setHost(ip); showTab('flows'); } })));
    }

    // What the device said about itself when asked (decoded identity replies), as one block
    const IDENTITY_FIELDS = [['Vendor', 'Vendor'], ['Model', 'Model'], ['Product', 'Product'], ['Order number', 'OrderNumber'],
                             ['Device type', 'DeviceType'], ['Firmware', 'Firmware'], ['Software', 'Software'], ['Serial number', 'Serial'],
                             ['Name', 'Name'], ['Module name', 'ModuleName'], ['Plant ID', 'PlantID'], ['Location', 'Location'],
                             ['Modules', 'Module'], ['Description', 'SystemDescription'], ['Web server', 'HTTPServer'],
                             ['FTP server', 'FTPBanner'], ['SSH server', 'SSHServer']];

    function identitySection(item) {
        const rows = IDENTITY_FIELDS.map(([label, name]) => [label, (item.properties[name] || { values: [] }).values.join('; ')])
            .filter(([, value]) => value);
        if (!rows.length) return [];
        return [el('h3', { text: 'Identity' }), facts(rows),
                el('p', { class: 'hint', text: 'As the device reported it in the capture, for example in an identification reply or a service banner.' })];
    }

    const kindBadge = kind => el('span', { class: `kind kind-${kind}`, text: KIND_LABELS[kind] || kind });
    const OPERATION_COLUMNS = [
        { key: 'src', label: 'Client' }, { key: 'dst', label: 'Server' }, { key: 'protocol', label: 'Protocol' },
        { key: 'operation', label: 'Operation' }, { key: 'kind', label: 'Kind', format: kindBadge },
        { key: 'count', label: 'Count', num: true, format: fmt }
    ];

    function operationsSection(operations, total, ip) {
        if (!operations || !operations.length) return [];
        return [el('h3', { text: `Industrial operations (${operations.length < total ? `${operations.length} of ${fmt(total)}` : fmt(total)})` }),
                table(OPERATION_COLUMNS, operations),
                ip ? el('p', {}, el('a', { href: '#', text: 'Show them in the Operations tab',
                                           onclick: event => { event.preventDefault(); closePanel(); operationsTable.setHost(ip); showTab('operations'); } })) : null];
    }

    function layer2Evidence(evidence) {
        if (!evidence || !evidence.length) return [];
        return [el('h3', { text: `Layer-2 announcements (${evidence.length})` }),
                table([{ key: 'protocol', label: 'Protocol' }, { key: 'name', label: 'Property' }, { key: 'value', label: 'Value' },
                       { key: 'confidence', label: 'Conf.', num: true }, { key: 'count', label: 'Frames', num: true, format: fmt }], evidence)];
    }

    function showGroupPanel(group) {
        const rows = [['Hosts', fmt(group.hosts)], ['Network', group.cidr]];
        if (group.network_id) {
            openPanel(group.label, facts(rows),
                el('p', { class: 'hint', text: 'A named network. Rename or delete it on the Networks page.' }),
                el('p', {}, el('a', { href: '/networks', text: 'Manage networks' })));
            return;
        }
        if (!group.cidr) {
            openPanel(group.label, facts(rows), el('p', { class: 'hint', text: group.id.startsWith('via:')
                ? 'Hosts on other networks, reached through this router. Name their network on the Networks page to group them by address instead.'
                : 'Addresses that are not single hosts.' }));
            return;
        }
        const cidr = el('input', { type: 'text', value: group.cidr, style: 'width: 160px' });
        const name = el('input', { type: 'text', placeholder: 'Name, e.g. Packaging line', maxlength: '100', style: 'width: 220px' });
        const error = el('p', { class: 'error-text' });
        const form = el('form', { class: 'form-row', onsubmit: async event => {
            event.preventDefault();
            try {
                await sendJSON('/api/networks', 'POST', { cidr: cidr.value, name: name.value });
                closePanel();
                loadGraph();
            } catch (e) {
                error.textContent = e.message;
            }
        } }, cidr, name, el('button', { type: 'submit', class: 'btn', text: 'Name this network' }));
        openPanel(group.label, facts(rows),
            el('p', { class: 'hint', text: 'Grouped automatically by address. Give it a name, or widen it (for example to a /16), and it is used in every session.' }),
            form, error, el('p', {}, el('a', { href: '/networks', text: 'Manage networks' })));
        name.focus();
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
        const summary = facts([['Protocols', edge.protocols.join(', ')],
                               ['Operations', edge.operations.map(kind => KIND_LABELS[kind] || kind).join(', ')],
                               ['Flows', fmt(edge.flows)], ['Packets', fmt(edge.packets)],
                               ['Bytes', fmt(edge.bytes)], ['First seen', when(edge.first_seen)], ['Last seen', when(edge.last_seen)]]);
        const title = `${edge.source} → ${edge.target}`;
        if (edge.source.startsWith('via:') || edge.target.startsWith('via:')) {
            openPanel(title, summary, el('p', { text: 'This connection includes merged hosts. Show every host behind routers to see individual flows.' }));
            return;
        }
        openPanel(title, summary, el('p', { text: 'Loading flows…' }));
        try {
            const data = await getJSON(`${API}/flows?src=${encodeURIComponent(edge.source)}&dst=${encodeURIComponent(edge.target)}&limit=${PAGE_SIZE}`);
            const operations = edge.operations.length
                ? (await getJSON(`${API}/operations?host=${encodeURIComponent(edge.source)}&limit=${PAGE_SIZE}`)).operations
                    .filter(o => o.src === edge.source && o.dst === edge.target)
                : [];
            openPanel(title, summary,
                      ...operationsSection(operations, operations.length),
                      el('h3', { text: `Flows (${data.flows.length < data.total ? `busiest ${data.flows.length} of ${fmt(data.total)}` : fmt(data.total)})` }),
                      table(PANEL_FLOW_COLUMNS, data.flows));
        } catch (error) {
            openPanel(title, summary, el('p', { text: `Could not load flows: ${error.message}` }));
        }
    }

    // --- physical view

    const PHYSICAL_COLORS = { switch: '#34495e', announced: '#34495e', neighbor: '#7f8c8d', port: '#aab7c4', capture: '#e8743b' };
    let physicalCy = null;
    let physicalLoaded = false;

    function physicalLayout() {
        if (!physicalCy) return;
        const count = physicalCy.nodes().filter(n => !n.isParent()).length;
        physicalCy.layout(count > MAX_FORCE_LAYOUT_NODES
            ? { name: 'grid', avoidOverlap: true }
            : { name: forceLayoutName(), animate: false, nodeDimensionsIncludeLabels: true, idealEdgeLength: 90,
                nodeRepulsion: 6000, packComponents: true }).run();
        physicalCy.fit(undefined, 30);
        if (physicalCy.zoom() > 1.2) {
            physicalCy.zoom(1.2);
            physicalCy.center();
        }
    }

    async function loadPhysical() {
        physicalLoaded = true;
        const container = document.getElementById('cy-physical');
        let data;
        try {
            data = await getJSON(`${API}/physical`);
        } catch (error) {
            container.textContent = `Could not load the physical view: ${error.message}`;
            return;
        }
        renderSwitchList(data.switches);
        const devices = data.nodes.filter(n => n.type === 'device').length;
        setText('physical-summary', `${fmt(data.switches.length)} imported switches, ${fmt(devices)} devices`);
        const parents = new Set(data.nodes.map(n => n.parent).filter(Boolean));
        const nodes = data.nodes
            .sort((a, b) => (parents.has(b.id) ? 1 : 0) - (parents.has(a.id) ? 1 : 0))  // parents first
            .map(node => ({ data: {
                id: node.id, label: node.label, parent: node.parent, kind: node.type, node,
                color: node.type === 'device' ? (CATEGORY_COLORS[firstToken(node.category)] || UNCLASSIFIED_COLOR) : PHYSICAL_COLORS[node.type],
                shape: node.type === 'device' && node.category === 'NETWORK_DEVICE' ? 'round-rectangle'
                    : ({ port: 'rectangle', capture: 'star', neighbor: 'round-rectangle' }[node.type] || 'ellipse'),
                faded: node.type === 'device' && !node.seen
            } }));
        const edges = data.edges.map((edge, i) => ({ data: { id: `pe${i}`, source: edge.source, target: edge.target, label: edge.label, kind: edge.type } }));
        if (physicalCy) physicalCy.destroy();
        container.textContent = '';
        physicalCy = cytoscape({
            container,
            elements: nodes.concat(edges),
            style: [
                { selector: 'node', style: { 'label': 'data(label)', 'font-size': 10, 'text-wrap': 'wrap', 'text-max-width': 120,
                                             'text-valign': 'bottom', 'text-margin-y': 4, 'background-color': 'data(color)',
                                             'shape': 'data(shape)', 'width': 34, 'height': 34 } },
                { selector: 'node[kind = "port"]', style: { 'width': 22, 'height': 14, 'font-size': 8, 'text-valign': 'center',
                                                            'text-margin-y': 0, 'color': '#222' } },
                { selector: 'node[kind = "capture"]', style: { 'width': 44, 'height': 44, 'font-weight': 'bold' } },
                { selector: 'node[kind = "neighbor"]', style: { 'border-width': 2, 'border-style': 'dashed', 'border-color': '#555',
                                                                'width': 60, 'height': 30 } },
                { selector: 'node[?faded]', style: { 'opacity': 0.5 } },
                { selector: ':parent', style: { 'background-color': '#eef3f8', 'background-opacity': 0.7, 'border-color': '#9fb3c8',
                                                'border-width': 1, 'shape': 'round-rectangle', 'text-valign': 'top', 'font-size': 12,
                                                'padding': 14, 'color': '#555' } },
                { selector: 'node[kind = "switch"]:parent', style: { 'background-color': '#dfe6ee', 'border-color': '#34495e',
                                                                     'border-width': 2, 'font-weight': 'bold', 'color': '#222' } },
                { selector: 'node[kind = "announced"]', style: { 'shape': 'round-rectangle', 'width': 60, 'height': 30 } },
                { selector: 'node[kind = "announced"]:parent', style: { 'background-color': '#dfe6ee', 'border-color': '#34495e',
                                                                        'border-width': 2, 'border-style': 'dashed',
                                                                        'font-weight': 'bold', 'color': '#222' } },
                { selector: 'edge', style: { 'width': 1, 'line-color': '#aaa', 'curve-style': 'bezier', 'label': 'data(label)',
                                             'font-size': 8, 'color': '#555', 'text-rotation': 'autorotate' } },
                { selector: 'edge[kind = "link"]', style: { 'width': 4, 'line-color': '#34495e' } },
                { selector: 'edge[kind = "capture"]', style: { 'width': 3, 'line-color': '#e8743b', 'line-style': 'dashed' } },
                { selector: '.selected', style: { 'border-width': 4, 'border-color': '#222', 'line-color': '#222' } }
            ]
        });
        physicalLayout();
        physicalCy.on('tap', 'node', event => {
            const node = event.target.data('node');
            physicalCy.elements().removeClass('selected');
            event.target.addClass('selected');
            if (node.type === 'device') showDevicePanel(node.mac);
            else if (node.type === 'port') showPortPanel(node);
            else if (node.type === 'switch') showSwitchPanel(node, data.switches);
            else if (node.type === 'announced') showAnnouncedPanel(node);
            else if (node.type === 'neighbor') {
                openPanel(node.label, facts([['Platform', node.platform], ['Address', node.address]]),
                    el('p', { class: 'hint', text: 'A CDP or LLDP neighbor of an imported switch. Import its own output to see what is plugged into it.' }));
            } else if (node.type === 'capture') {
                openPanel('Capture point', el('p', { text: 'Where this capture was taken. LLDP and CDP only travel one hop, so the device '
                    + 'that sent them is on the other end of the capture\'s cable, and the port it announced is the one the capture is plugged into.' }));
            }
        });
    }

    function renderSwitchList(switches) {
        const list = document.getElementById('switch-list');
        list.replaceChildren(...(switches.length ? switches.map(sw => el('li', {},
            el('span', {}, el('strong', { text: sw.name }), el('br'),
               el('span', { class: 'hint', text: `${fmt(sw.ports)} ports, ${fmt(sw.macs)} MAC entries, ${fmt(sw.neighbors)} neighbors` })),
            el('button', { class: 'link-btn danger', text: 'Remove', onclick: async () => {
                if (!confirm(`Remove the imported data for ${sw.name}?`)) return;
                await sendJSON(`${API}/switches/${sw.id}`, 'DELETE');
                loadPhysical();
                if (devicesTable.loaded) devicesTable.load();
            } }))) : [el('li', { class: 'hint', text: 'None yet.' })]));
    }

    function showPortPanel(port) {
        openPanel(`${port.switch} ${port.port}`, facts([['Description', port.description], ['Mode', port.mode],
            [port.mode === 'trunk' ? 'Native VLAN' : 'VLAN', port.vlan], ['Shut down', port.shutdown ? 'yes' : null]]),
            port.announced ? el('p', { class: 'hint', text: 'Announced over LLDP or CDP to the capture point, so the capture is plugged into this port.' }) : null);
    }

    function showAnnouncedPanel(node) {
        openPanel(node.label,
            facts([['Vendor', node.vendor], ['Platform', node.platform], ['Description', node.description],
                   ['Capabilities', node.capabilities], ['Management address', node.addresses.join(', ')]]),
            el('p', { class: 'hint', text: 'This switch announced itself in the capture over LLDP or CDP, from the MAC addresses below. '
                + 'Only the ports it announced are drawn; import its switch data to see what is plugged into the rest.' }),
            el('h3', { text: 'MAC addresses' }),
            el('p', {}, ...node.macs.flatMap((mac, i) => [i ? ', ' : null,
                el('a', { href: '#', text: mac, onclick: event => { event.preventDefault(); showDevicePanel(mac); } })])));
    }

    function showSwitchPanel(node, switches) {
        const sw = switches.find(s => s.id === node.switch_id) || {};
        openPanel(node.label, facts([['Imported from', sw.filename || 'pasted text'], ['Imported', sw.imported_at],
            ['Ports in config', fmt(sw.ports)], ['MAC table entries', fmt(sw.macs)], ['Neighbors', fmt(sw.neighbors)]]),
            el('p', { class: 'hint', text: 'Only ports with something plugged in, a neighbor or the capture are drawn.' }));
    }

    document.getElementById('switch-form').addEventListener('submit', async event => {
        event.preventDefault();
        const form = event.target;
        const error = document.getElementById('switch-error');
        error.textContent = '';
        const button = form.querySelector('button');
        button.disabled = true;
        try {
            await pyLot.request(`${API}/switches`, { method: 'POST', body: new FormData(form) });
            form.reset();
            await loadPhysical();
            if (devicesTable.loaded) devicesTable.load();
        } catch (e) {
            error.textContent = e.message;
        } finally {
            button.disabled = false;
        }
    });

    async function showDevicePanel(mac) {
        openPanel(mac, el('p', { text: 'Loading…' }));
        let device;
        try {
            device = await getJSON(`${API}/devices/${encodeURIComponent(mac)}`);
        } catch (error) {
            openPanel(mac, el('p', { text: `Could not load this device: ${error.message}` }));
            return;
        }
        const properties = Object.entries(device.properties).map(([name, p]) => ({ name, values: p.values.join(', '), confidence: p.confidence }));
        openPanel(device.name ? `${device.name} (${mac})` : mac,
            facts([['Vendor', device.vendor], ['Switch port', device.switch ? `${device.switch} ${device.port}` : null],
                   ['VLANs', device.vlans.join(', ')], ['Routes for', device.routes_for ? `${fmt(device.routes_for)} hosts on other networks` : null],
                   ['Frames sent', device.seen ? fmt(device.packets) : 'Not seen in the capture, only in an imported MAC table'],
                   ['First seen', when(device.first_seen)], ['Last seen', when(device.last_seen)]]),
            device.ips.length ? el('h3', { text: 'IP addresses' }) : null,
            device.ips.length ? el('p', {}, ...device.ips.flatMap((ip, i) => [i ? ', ' : null,
                el('a', { href: '#', text: ip, onclick: event => { event.preventDefault(); showHostPanel(ip); } })])) : null,
            properties.length ? el('h3', { text: 'Classification' }) : null,
            properties.length ? table([{ key: 'name', label: 'Property' }, { key: 'values', label: 'Value' },
                                       { key: 'confidence', label: 'Confidence', num: true }], properties) : null,
            ...layer2Evidence(device.layer2_evidence),
            device.switch_entries.length ? el('h3', { text: 'In imported MAC tables' }) : null,
            device.switch_entries.length ? table([{ key: 'switch', label: 'Switch' }, { key: 'port', label: 'Port' },
                                                  { key: 'vlan', label: 'VLAN', num: true }], device.switch_entries) : null,
            device.l2_flows.length ? el('h3', { text: 'Layer-2 traffic (without IP)' }) : null,
            device.l2_flows.length ? table([{ key: 'src_mac', label: 'From' }, { key: 'dst_mac', label: 'To' },
                                            { key: 'protocol', label: 'Protocol' }, { key: 'packets', label: 'Frames', num: true, format: fmt },
                                            { key: 'bytes', label: 'Bytes', num: true, format: fmt }], device.l2_flows) : null);
    }

    // --- host and flow tables

    class PagedTable {
        constructor({ name, endpoint, rowsKey, columns, sort, order, onRowClick, hostLabel = 'flows', onLoad }) {
            Object.assign(this, { name, endpoint, rowsKey, columns, onRowClick, hostLabel, onLoad });
            this.state = { q: '', sort, order, offset: 0, host: null, kind: '' };
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
                document.getElementById(`${this.name}-host-label`).textContent = host ? `Only ${this.hostLabel} to or from ${host}` : '';
            }
        }

        async load() {
            this.loaded = true;
            const params = new URLSearchParams({ q: this.state.q, sort: this.state.sort, order: this.state.order,
                                                 offset: this.state.offset, limit: PAGE_SIZE });
            if (this.state.host) params.set('host', this.state.host);
            if (this.state.kind) params.set('kind', this.state.kind);
            let data;
            try {
                data = await getJSON(`${this.endpoint}?${params}`);
            } catch (error) {
                this.container.replaceChildren(el('div', { class: 'empty', text: `Could not load: ${error.message}` }));
                return;
            }
            const rows = data[this.rowsKey];
            if (this.onLoad) this.onLoad(data);
            const head = el('tr', {}, ...this.columns.map(c => {
                if (c.sortable === false) return el('th', { text: c.label });
                const sorted = this.state.sort === c.key;
                return el('th', { class: `sortable${sorted ? ' sorted' : ''}${sorted && this.state.order === 'desc' ? ' desc' : ''}`,
                                  text: c.label, onclick: () => this.sortBy(c) });
            }));
            const body = rows.map(row => el('tr', this.onRowClick ? { class: 'clickable', onclick: () => this.onRowClick(row) } : {},
                ...this.columns.map(c => {
                    const value = (c.format || (v => v ?? ''))(row[c.key], row);
                    return el('td', c.num ? { class: 'num' } : {}, value instanceof Node ? value : String(value));
                })));
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
            { key: 'category', label: 'Category' }, { key: 'role', label: 'Role' },
            { key: 'model', label: 'Model' }, { key: 'firmware', label: 'Firmware' }, { key: 'kind', label: 'Type' },
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

    const list = values => (values || []).join(', ');
    const devicesTable = new PagedTable({
        name: 'devices', endpoint: `${API}/devices`, rowsKey: 'devices', sort: 'mac', order: 'asc',
        onRowClick: row => showDevicePanel(row.mac),
        columns: [
            { key: 'mac', label: 'MAC' }, { key: 'vendor', label: 'Vendor' }, { key: 'name', label: 'Name' },
            { key: 'ips', label: 'IPs', sortable: false, format: list }, { key: 'vlans', label: 'VLANs', sortable: false, format: list },
            { key: 'category', label: 'Category' }, { key: 'role', label: 'Role' },
            { key: 'model', label: 'Model' }, { key: 'firmware', label: 'Firmware' },
            { key: 'layer2', label: 'Layer-2 protocols', sortable: false, format: list },
            { key: 'switch', label: 'Switch' }, { key: 'port', label: 'Port' },
            { key: 'packets', label: 'Frames sent', num: true, format: fmt },
            { key: 'last_seen', label: 'Last seen', num: true, format: when }
        ]
    });

    const kindSelect = document.getElementById('operations-kind');
    const operationsTable = new PagedTable({
        name: 'operations', endpoint: `${API}/operations`, rowsKey: 'operations', sort: 'kind', order: 'asc',
        hostLabel: 'operations',
        onRowClick: row => showHostPanel(row.dst),
        onLoad: data => {
            const selected = kindSelect.value;
            kindSelect.replaceChildren(el('option', { value: '', text: `All kinds (${fmt(Object.values(data.kinds).reduce((a, b) => a + b, 0))})` }),
                ...Object.keys(KIND_LABELS).filter(kind => data.kinds[kind])
                    .map(kind => el('option', { value: kind, text: `${KIND_LABELS[kind]} (${fmt(data.kinds[kind])})` })));
            kindSelect.value = selected;
        },
        columns: [
            { key: 'src', label: 'Client' }, { key: 'dst', label: 'Server' }, { key: 'protocol', label: 'Protocol' },
            { key: 'operation', label: 'Operation' }, { key: 'kind', label: 'Kind', format: kindBadge },
            { key: 'count', label: 'Count', num: true, format: fmt },
            { key: 'first_seen', label: 'First seen', num: true, format: when }, { key: 'last_seen', label: 'Last seen', num: true, format: when },
            { key: 'first_frame', label: 'First frame', num: true, sortable: false }
        ]
    });
    kindSelect.addEventListener('change', () => {
        operationsTable.state.kind = kindSelect.value;
        operationsTable.state.offset = 0;
        operationsTable.load();
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
        if (name === 'devices' && !devicesTable.loaded) devicesTable.load();
        if (name === 'operations' && !operationsTable.loaded) operationsTable.load();
        if (name === 'alerts') renderAlerts();
        if (name === 'physical') {
            if (!physicalLoaded) loadPhysical();
            else if (physicalCy) physicalCy.resize();
        }
    }

    document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => showTab(tab.dataset.tab)));
    document.getElementById('flows-host-clear').addEventListener('click', () => { flowsTable.setHost(null); flowsTable.load(); });
    document.getElementById('alerts-severity').addEventListener('change', renderAlerts);
    document.getElementById('alerts-filter').addEventListener('input', renderAlerts);
    document.getElementById('alert-box').addEventListener('click', event => { event.preventDefault(); showTab('alerts'); });
    document.getElementById('operations-host-clear').addEventListener('click', () => { operationsTable.setHost(null); operationsTable.load(); });

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
        if (devicesTable.loaded) devicesTable.load();
        if (operationsTable.loaded) operationsTable.load();
        loadAlerts();
        if (physicalLoaded) loadPhysical();
    });
    document.getElementById('collapse-toggle').addEventListener('click', async event => {
        collapse = collapse === false ? true : false;
        const button = event.target;
        button.disabled = true;
        button.textContent = collapse ? 'Merging…' : 'Drawing every host, this can take a while…';
        await loadGraph();
        button.disabled = false;
    });
    const baselineSelect = document.getElementById('baseline-select');
    if (baselineSelect) {
        baselineSelect.addEventListener('change', () => {
            baseline = baselineSelect.value;
            loadGraph();
        });
    }
    document.getElementById('export-png').addEventListener('click', () => {
        if (cy) download(cy.png({ full: true, scale: 2, bg: '#ffffff' }), `session_${SESSION_ID}_graph.png`);
    });
    document.getElementById('physical-fit').addEventListener('click', () => physicalCy && physicalCy.fit(undefined, 30));
    document.getElementById('physical-relayout').addEventListener('click', physicalLayout);
    document.getElementById('physical-png').addEventListener('click', () => {
        if (physicalCy) download(physicalCy.png({ full: true, scale: 2, bg: '#ffffff' }), `session_${SESSION_ID}_physical.png`);
    });
    document.addEventListener('keydown', event => { if (event.key === 'Escape') closePanel(); });

    watchStatus();
})();
