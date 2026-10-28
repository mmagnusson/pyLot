// Named networks page
(() => {
    const { el, getJSON, sendJSON, table } = pyLot;

    async function load() {
        const data = await getJSON('/api/networks');
        render(data.networks);
        for (const [key, limit] of [['auto_prefix_v4', 32], ['auto_prefix_v6', 128]]) {
            const select = document.getElementById(key);
            select.replaceChildren(el('option', { value: '0', text: 'nothing (one "Not in a named network" group)' }));
            for (let prefix = 8; prefix <= limit; prefix += key.endsWith('v4') ? 1 : 4) select.append(new Option(`/${prefix}`, prefix));
            select.value = String(data.settings[key]);
        }
    }

    function render(networks) {
        const container = document.getElementById('networks');
        if (!networks.length) {
            container.replaceChildren(el('div', { class: 'empty', text: 'No named networks yet. You can also add one by clicking a network box in a session graph.' }));
            return;
        }
        container.replaceChildren(table([
            { key: 'name', label: 'Name' }, { key: 'cidr', label: 'Network' },
            { key: 'id', label: '', format: (id, network) => el('span', {},
                el('button', { class: 'link-btn', text: 'Rename', onclick: () => rename(network) }), ' · ',
                el('button', { class: 'link-btn danger', text: 'Delete', onclick: () => remove(network) })) }
        ], networks));
    }

    async function rename(network) {
        const name = prompt(`New name for ${network.cidr}`, network.name);
        if (name == null) return;
        try {
            await sendJSON(`/api/networks/${network.id}`, 'PUT', { name });
        } catch (error) {
            alert(error.message);
        }
        load();
    }

    async function remove(network) {
        if (!confirm(`Delete ${network.name} (${network.cidr})? Its hosts go back to automatic grouping.`)) return;
        await sendJSON(`/api/networks/${network.id}`, 'DELETE');
        load();
    }

    document.getElementById('add-form').addEventListener('submit', async event => {
        event.preventDefault();
        const error = document.getElementById('add-error');
        error.textContent = '';
        try {
            await sendJSON('/api/networks', 'POST', { cidr: document.getElementById('cidr').value, name: document.getElementById('name').value });
            event.target.reset();
            load();
        } catch (e) {
            error.textContent = e.message;
        }
    });

    document.getElementById('settings-form').addEventListener('submit', async event => {
        event.preventDefault();
        const status = document.getElementById('settings-status');
        try {
            await sendJSON('/api/settings', 'PUT', { auto_prefix_v4: Number(document.getElementById('auto_prefix_v4').value),
                                                     auto_prefix_v6: Number(document.getElementById('auto_prefix_v6').value) });
            status.textContent = 'Saved. Session graphs use it the next time they load.';
        } catch (e) {
            status.textContent = e.message;
        }
    });

    load();
})();
