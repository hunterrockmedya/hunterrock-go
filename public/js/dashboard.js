const SITE_DOMAIN = document.body.dataset.domain || '';

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function copyLink(slug) {
    const fullUrl = SITE_DOMAIN + '/' + slug;
    navigator.clipboard.writeText(fullUrl).then(() => {
        alert('Link kopyalandı: ' + fullUrl);
    });
}

let currentLogOffset = 0;
const logLimit = 15;
let currentLinkId = null;

async function openLogModal(linkId, slug) {
    currentLinkId = linkId;
    currentLogOffset = 0;

    document.getElementById('logModalTitle').textContent = '/' + slug + ' Logları';
    document.getElementById('logModal').classList.add('active');
    document.getElementById('logModalBody').innerHTML = '<div class="log-loading"><i class="fas fa-spinner fa-spin"></i> Yükleniyor...</div>';

    loadMoreLogs(false);
}

async function loadMoreLogs(append = false) {
    try {
        const response = await fetch(`/hradmin/api/logs/${currentLinkId}?limit=${logLimit}&offset=${currentLogOffset}`, {
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        });
        const logs = await response.json();

        renderLogsInModal(logs, append);

        if (logs.length === logLimit) {
            addLoadMoreButton();
        }
    } catch (err) {
        console.error('Log fetch error:', err);
    }
}

function renderLogsInModal(logs, append = false) {
    const modalBody = document.getElementById('logModalBody');
    if (!modalBody) return;

    if (!append) {
        modalBody.innerHTML = '';
        if (!logs || logs.length === 0) {
            modalBody.innerHTML = '<div class="log-empty"><i class="fas fa-inbox"></i><br>Henüz tıklama yok</div>';
            return;
        }
    } else {
        document.getElementById('loadMoreBtn')?.parentElement.remove();
    }

    let listContainer = modalBody.querySelector('.log-list-v2');
    if (!listContainer) {
        listContainer = document.createElement('div');
        listContainer.className = 'log-list-v2';
        modalBody.appendChild(listContainer);
    }

    logs.forEach((log) => {
        const item = document.createElement('div');
        item.className = 'log-item-v2';

        const header = document.createElement('div');
        header.className = 'log-header-v2';

        const flagSpan = document.createElement('span');
        flagSpan.className = 'log-flag';
        flagSpan.textContent = getFlagEmoji(log.country_code || log.country);

        const ipSpan = document.createElement('span');
        ipSpan.className = 'log-ip';
        ipSpan.textContent = log.ip;

        const locSpan = document.createElement('span');
        locSpan.className = 'log-location';
        locSpan.textContent = (log.city || log.country || 'Bilinmiyor');

        const chevron = document.createElement('i');
        chevron.className = 'fas fa-chevron-down log-chevron-v2';

        header.append(flagSpan, ipSpan, locSpan, chevron);

        const content = document.createElement('div');
        content.className = 'log-content-v2';

        const grid = document.createElement('div');
        grid.className = 'log-detail-grid';

        const createSection = (title, details) => {
            const sec = document.createElement('div');
            sec.className = 'log-detail-section';
            const h = document.createElement('h4');
            h.textContent = title;
            sec.appendChild(h);
            details.forEach(d => {
                const p = document.createElement('p');
                p.innerHTML = `<strong>${d.label}:</strong> `;
                const s = document.createElement('span');
                s.textContent = d.val;
                p.appendChild(s);
                sec.appendChild(p);
            });
            return sec;
        };

        grid.appendChild(createSection('Konum', [
            { label: 'Bölge', val: log.region || '-' },
            { label: 'Saat Dilimi', val: log.timezone || '-' }
        ]));

        grid.appendChild(createSection('Cihaz', [
            { label: 'Tarayıcı', val: log.browser || '-' },
            { label: 'Sistem', val: log.os || '-' }
        ]));

        const uaDiv = document.createElement('div');
        uaDiv.className = 'log-ua';
        const small = document.createElement('small');
        small.textContent = log.user_agent;
        uaDiv.appendChild(small);

        content.append(grid, uaDiv);

        header.addEventListener('click', (e) => {
            e.stopPropagation();
            item.classList.toggle('active');
        });

        item.append(header, content);
        listContainer.appendChild(item);
    });

    currentLogOffset += logs.length;
}

function closeLogModal() {
    document.getElementById('logModal').classList.remove('active');
}

function getFlagEmoji(countryCode) {
    if (!countryCode || countryCode === 'Unknown') return '🏳️';
    try {
        const codePoints = countryCode
            .toUpperCase()
            .split('')
            .map(char => 127397 + char.charCodeAt());
        return String.fromCodePoint(...codePoints);
    } catch (e) { return '🏳️'; }
}

function addLoadMoreButton() {
    const modalBody = document.getElementById('logModalBody');
    const container = document.createElement('div');
    container.style.textAlign = 'center';
    container.style.padding = '20px';

    const btn = document.createElement('button');
    btn.id = 'loadMoreBtn';
    btn.className = 'btn-primary';
    btn.textContent = 'Daha Fazla Yükle';
    btn.style.width = 'auto';
    btn.style.padding = '10px 30px';

    btn.addEventListener('click', () => {
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Yükleniyor...';
        loadMoreLogs(true);
    });

    container.appendChild(btn);
    modalBody.appendChild(container);
}

document.addEventListener('click', function (e) {
    if (e.target.classList.contains('modal') || e.target.classList.contains('modal-overlay')) {
        const modalId = e.target.id;
        if (modalId === 'logModal') closeLogModal();
        else if (modalId === 'addLinkModal') closeAddModal();
        else if (modalId === 'editLinkModal') closeEditModal();
        else if (modalId === 'passwordModal') closePasswordModal();
        else e.target.classList.remove('active');
    }
});

function closeAddModal() {
    document.getElementById('addLinkModal').classList.remove('active');
}
function openEditModal(id, slug, targetUrl, title) {
    document.getElementById('editLinkId').value = id;
    document.getElementById('editSlug').value = decodeURIComponent(slug);
    document.getElementById('editTargetUrl').value = decodeURIComponent(targetUrl);
    document.getElementById('editTitle').value = decodeURIComponent(title || '');
    document.getElementById('editLinkForm').action = '/hradmin/links/' + id + '/edit';
    document.getElementById('editLinkModal').classList.add('active');
}

function closeEditModal() {
    document.getElementById('editLinkModal').classList.remove('active');
}

document.querySelectorAll('.edit-link-btn').forEach(btn => {
    btn.addEventListener('click', function () {
        openEditModal(
            this.dataset.id,
            this.dataset.slug,
            this.dataset.url,
            this.dataset.title
        );
    });
});

document.getElementById('editLinkModal')?.addEventListener('click', function (e) {
    if (e.target === this) {
        closeEditModal();
    }
});

function openPasswordModal(userId, username) {
    document.getElementById('passwordForm').action = '/hradmin/users/' + userId + '/password';
    document.getElementById('passwordModalUser').innerHTML = '<strong>' + escapeHtml(username) + '</strong> kullanıcısı için yeni şifre:';
    document.getElementById('passwordModal').classList.add('active');
}

function closePasswordModal() {
    document.getElementById('passwordModal').classList.remove('active');
}

document.querySelectorAll('.password-btn').forEach(btn => {
    btn.addEventListener('click', function () {
        openPasswordModal(this.dataset.id, this.dataset.username);
    });
});

document.getElementById('passwordModal')?.addEventListener('click', function (e) {
    if (e.target === this) {
        closePasswordModal();
    }
});

setTimeout(() => {
    document.querySelectorAll('.alert').forEach(el => el.remove());
}, 5000);
