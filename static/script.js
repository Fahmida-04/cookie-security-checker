const scanButton = document.getElementById('scan-button');
const urlInput = document.getElementById('url-input');
const statusMessage = document.getElementById('status-message');
const resultsSection = document.getElementById('results-section');
const scoreValue = document.getElementById('score-value');
const riskCategory = document.getElementById('risk-category');
const cookieCount = document.getElementById('cookie-count');
const issueCount = document.getElementById('issue-count');
const protocolStatus = document.getElementById('protocol-status');
const cookieTableContainer = document.getElementById('cookie-table-container');
const issuesContainer = document.getElementById('issues-container');

const setLoading = (isLoading) => {
    if (isLoading) {
        scanButton.disabled = true;
        scanButton.textContent = 'Scanning...';
        statusMessage.textContent = 'Checking cookies and analyzing configuration...';
    } else {
        scanButton.disabled = false;
        scanButton.textContent = 'Scan Website';
    }
};

const formatRiskLabel = (level) => {
    if (level === 'Low') return `<span class="status-badge green">Low Risk</span>`;
    if (level === 'Medium') return `<span class="status-badge yellow">Medium Risk</span>`;
    return `<span class="status-badge red">High Risk</span>`;
};

const renderCookieTable = (cookies) => {
    if (!cookies.length) {
        cookieTableContainer.innerHTML = '<p>No cookies were found for this site.</p>';
        return;
    }

    const rows = cookies.map(cookie => `
        <tr>
            <td>${cookie.name}</td>
            <td>${cookie.secure === 'Yes' ? '<span class="status-badge green">✅ Secure</span>' : '<span class="status-badge red">❌ Missing</span>'}</td>
            <td>${cookie.httponly === 'Yes' ? '<span class="status-badge green">✅ HttpOnly</span>' : '<span class="status-badge yellow">⚠️ Missing</span>'}</td>
            <td>${cookie.samesite}</td>
            <td>${cookie.domain}</td>
            <td>${cookie.path}</td>
            <td>${cookie.expires}</td>
            <td>${formatRiskLabel(cookie.risk_level)}</td>
        </tr>
    `).join('');

    cookieTableContainer.innerHTML = `
        <div class="table-wrapper">
            <table class="cookie-table">
                <thead>
                    <tr>
                        <th>Cookie</th>
                        <th>Secure</th>
                        <th>HttpOnly</th>
                        <th>SameSite</th>
                        <th>Domain</th>
                        <th>Path</th>
                        <th>Expires</th>
                        <th>Risk</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
};

const renderIssues = (issues) => {
    if (!issues.length) {
        issuesContainer.innerHTML = '<p class="issue-card">No cookie issues were detected. The response appears to use secure cookie settings.</p>';
        return;
    }

    const cards = issues.map(issue => `
        <div class="issue-card">
            <h4>${issue.cookie}: ${issue.issue}</h4>
            <p><strong>Why it matters:</strong> ${issue.explanation}</p>
            <p><strong>How to improve:</strong> ${issue.recommendation}</p>
        </div>
    `).join('');

    issuesContainer.innerHTML = cards;
};

const showResults = (data) => {
    resultsSection.classList.remove('hidden');
    scoreValue.textContent = data.summary.score;
    riskCategory.innerHTML = formatRiskLabel(data.summary.risk_category);
    cookieCount.textContent = data.summary.cookie_count;
    issueCount.textContent = data.summary.issues_found;
    protocolStatus.textContent = data.summary.https ? 'HTTPS' : 'HTTP';
    renderCookieTable(data.cookies);
    renderIssues(data.issues);
    statusMessage.textContent = 'Scan complete. Review the cookie analysis and recommendations below.';
};

const showError = (message) => {
    resultsSection.classList.add('hidden');
    statusMessage.textContent = message;
};

const scanUrl = async () => {
    const url = urlInput.value.trim();
    if (!url) {
        showError('Please enter a website URL to scan.');
        return;
    }

    setLoading(true);
    resultsSection.classList.add('hidden');

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!data.success) {
            showError(data.error || 'Unexpected error during scanning.');
        } else if (data.cookies) {
            showResults(data);
        } else {
            showError(data.message || 'No scan results were available.');
        }
    } catch (error) {
        showError('Could not complete the scan. Please check your internet connection and try again.');
    } finally {
        setLoading(false);
    }
};

scanButton.addEventListener('click', scanUrl);
urlInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
        event.preventDefault();
        scanUrl();
    }
});
