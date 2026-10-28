// Baseline comparison page
(() => {
    const { el, fmt, when, getJSON, table } = pyLot;
    const sessionId = Number(document.body.dataset.sessionId);
    const baseline = document.getElementById('baseline').value;

    const hostColumns = [
        { key: 'ip', label: 'IP' }, { key: 'mac', label: 'MAC' }, { key: 'vendor', label: 'Vendor' },
        { key: 'category', label: 'Category' }, { key: 'role', label: 'Role' },
        { key: 'via_mac', label: 'Via router' }, { key: 'first_seen', label: 'First seen', format: when }
    ];
    const conversationColumns = [
        { key: 'client', label: 'Client' }, { key: 'server', label: 'Server' }, { key: 'protocol', label: 'Protocol' },
        { key: 'port', label: 'Port', num: true }, { key: 'packets', label: 'Packets', num: true, format: fmt },
        { key: 'bytes', label: 'Bytes', num: true, format: fmt }, { key: 'first_seen', label: 'First seen', format: when }
    ];
    const macColumns = [
        { key: 'mac', label: 'MAC' }, { key: 'vendor', label: 'Vendor' }, { key: 'packets', label: 'Frames sent', num: true, format: fmt },
        { key: 'first_seen', label: 'First seen', format: when }
    ];
    const changeColumns = [
        { key: 'ip', label: 'IP' },
        { key: 'changes', label: 'Changes', format: changes => el('div', {}, ...changes.map(c => el('div', {},
            `${c.what}: `, el('span', { class: 'change-before', text: c.before || 'none' }), ' → ',
            el('span', { class: 'change-now', text: c.now || 'none' })))) }
    ];

    const KIND_LABELS = { program: 'Program', control: 'Control', write: 'Write', read: 'Read', diagnostic: 'Diagnostic',
                          data: 'Data', session: 'Session', error: 'Error', other: 'Other' };
    const operationColumns = [
        { key: 'src', label: 'Client' }, { key: 'dst', label: 'Server' }, { key: 'protocol', label: 'Protocol' },
        { key: 'operation', label: 'Operation' },
        { key: 'kind', label: 'Kind', format: kind => el('span', { class: `kind kind-${kind}`, text: KIND_LABELS[kind] || kind }) },
        { key: 'count', label: 'Count', num: true, format: fmt }, { key: 'first_seen', label: 'First seen', format: when }
    ];

    const SECTIONS = [
        ['new_hosts', 'New hosts', hostColumns, true],
        ['changed_hosts', 'Hosts that changed', changeColumns, true],
        ['new_operations', 'New industrial operations', operationColumns, true],
        ['new_conversations', 'New conversations', conversationColumns, true],
        ['new_macs', 'New MAC addresses', macColumns, true],
        ['new_layer2', 'New layer-2 protocols', [{ key: 'src_mac', label: 'Sender' }, { key: 'protocol', label: 'Protocol' },
                                                 { key: 'packets', label: 'Frames', num: true, format: fmt }], true],
        ['missing_hosts', 'Hosts no longer seen', hostColumns, false],
        ['missing_conversations', 'Conversations no longer seen', conversationColumns, false],
        ['missing_macs', 'MAC addresses no longer seen', macColumns, false]
    ];

    async function load() {
        if (!baseline) return;
        const sections = document.getElementById('sections');
        sections.replaceChildren(el('div', { class: 'card section', text: 'Comparing…' }));
        let diff;
        try {
            diff = await getJSON(`/api/sessions/${sessionId}/compare?baseline=${encodeURIComponent(baseline)}`);
        } catch (error) {
            sections.replaceChildren(el('div', { class: 'card section error-text', text: error.message }));
            return;
        }
        const summary = document.getElementById('summary');
        summary.replaceChildren(...SECTIONS.map(([key, title, , isNew]) => el('a', {
            class: `stat-box${isNew && diff[key].total ? ' warn' : ''}`, href: `#${key}` },
            el('strong', { text: fmt(diff[key].total) }), ` ${title.replace(/^(\w)/, c => c.toLowerCase())}`)));
        sections.replaceChildren(...SECTIONS.map(([key, title, columns]) => {
            const { items, total } = diff[key];
            return el('div', { class: 'card section', id: key },
                el('h2', { text: `${title} (${fmt(total)})` }),
                items.length ? table(columns, items) : el('p', { class: 'hint', text: 'None.' }),
                items.length < total ? el('p', { class: 'hint', text: `Showing the first ${fmt(items.length)}.` }) : null);
        }));
    }

    load();
})();
