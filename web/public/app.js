/* ==========================================
   ShieldMyRepo — Frontend Application Logic
   ========================================== */

// GitHub API base URL
const GITHUB_API = 'https://api.github.com';

// ==========================================
// Scanner Definitions (client-side)
// ==========================================

const SECRET_PATTERNS = [
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical', recommendation: 'Remove the AWS key and rotate it immediately.' },
    { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g, severity: 'critical', recommendation: 'Revoke this GitHub token and generate a new one.' },
    { name: 'Generic API Key', pattern: /(api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]/gi, severity: 'high', recommendation: 'Move API keys to environment variables.' },
    { name: 'Generic Secret', pattern: /(secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi, severity: 'high', recommendation: 'Never hardcode secrets. Use environment variables.' },
    { name: 'Private Key', pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical', recommendation: 'Remove private keys from the repository.' },
    { name: 'Slack Webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24,}/g, severity: 'high', recommendation: 'Remove and regenerate the Slack webhook.' },
    { name: 'Database URL', pattern: /(mongodb|postgres|mysql|redis):\/\/[^\s'"]+:[^\s'"]+@/gi, severity: 'critical', recommendation: 'Remove database connection strings with credentials.' },
    { name: 'Stripe Key', pattern: /sk_(live|test)_[A-Za-z0-9]{24,}/g, severity: 'critical', recommendation: 'Revoke this Stripe key immediately.' },
    { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g, severity: 'medium', recommendation: 'Remove hardcoded JWT tokens.' },
];

const SKIP_EXTENSIONS = new Set([
    'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2', 'ttf', 'eot',
    'mp3', 'mp4', 'zip', 'tar', 'gz', 'pdf', 'pyc', 'so', 'dll', 'exe', 'bin',
    'whl', 'egg', 'jar', 'class',
]);

const SENSITIVE_GITIGNORE = [
    { file: '.env', description: 'Environment file with secrets', severity: 'high' },
    { file: '.env.local', description: 'Local environment file', severity: 'high' },
    { file: '.env.production', description: 'Production environment file', severity: 'critical' },
    { file: '.pem', description: 'PEM certificate/key file', severity: 'high' },
    { file: '.key', description: 'Private key file', severity: 'high' },
    { file: 'credentials.json', description: 'Credentials file', severity: 'critical' },
    { file: '.htpasswd', description: 'Apache password file', severity: 'high' },
];

// ==========================================
// GitHub API Functions
// ==========================================

function parseRepoUrl(url) {
    url = url.trim().replace(/\/+$/, '');
    // Handle full URLs
    const match = url.match(/github\.com\/([^\/]+)\/([^\/]+)/);
    if (match) return { owner: match[1], repo: match[2].replace('.git', '') };
    // Handle owner/repo format
    const parts = url.split('/');
    if (parts.length === 2) return { owner: parts[0], repo: parts[1] };
    return null;
}

async function fetchRepoTree(owner, repo) {
    const resp = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`, {
        headers: { 'Accept': 'application/vnd.github.v3+json' }
    });
    if (!resp.ok) {
        if (resp.status === 404) throw new Error('Repository not found. Make sure it exists and is public.');
        if (resp.status === 403) throw new Error('API rate limit exceeded. Try again in a few minutes.');
        throw new Error(`GitHub API error: ${resp.status}`);
    }
    return resp.json();
}

async function fetchFileContent(owner, repo, path) {
    const resp = await fetch(`${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, {
        headers: { 'Accept': 'application/vnd.github.v3+json' }
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (data.encoding === 'base64' && data.content) {
        try {
            return atob(data.content.replace(/\n/g, ''));
        } catch {
            return null;
        }
    }
    return null;
}

// ==========================================
// Scanner Implementations
// ==========================================

async function scanSecrets(owner, repo, tree) {
    const findings = [];
    const filesToScan = tree.filter(item => {
        if (item.type !== 'blob') return false;
        const ext = item.path.split('.').pop().toLowerCase();
        if (SKIP_EXTENSIONS.has(ext)) return false;
        if (item.path.includes('node_modules/') || item.path.includes('__pycache__/')) return false;
        if (item.size > 100000) return false; // Skip large files
        return true;
    }).slice(0, 50); // Limit to 50 files for API rate limits

    for (const file of filesToScan) {
        const content = await fetchFileContent(owner, repo, file.path);
        if (!content) continue;

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
            for (const pattern of SECRET_PATTERNS) {
                pattern.pattern.lastIndex = 0;
                if (pattern.pattern.test(lines[i])) {
                    findings.push({
                        severity: pattern.severity,
                        message: `${pattern.name} detected`,
                        file: file.path,
                        line: i + 1,
                        recommendation: pattern.recommendation,
                    });
                }
            }
        }
    }
    return { name: 'Secret Detection', description: 'Scans for leaked API keys and tokens', findings };
}

async function scanDockerfile(owner, repo, tree) {
    const findings = [];
    const dockerfiles = tree.filter(item =>
        item.type === 'blob' && (/^(.*\/)?Dockerfile(\..*)?$/i.test(item.path) || /docker-compose/i.test(item.path))
    );

    for (const file of dockerfiles) {
        const content = await fetchFileContent(owner, repo, file.path);
        if (!content) continue;
        const lines = content.split('\n');
        let hasUser = false;
        const isDockerfile = /dockerfile/i.test(file.path);

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (isDockerfile) {
                if (/^USER\s/i.test(line)) {
                    hasUser = true;
                    if (/^USER\s+(root|0)\s*$/i.test(line)) {
                        findings.push({ severity: 'high', message: 'Container runs as root user', file: file.path, line: i + 1, recommendation: 'Create and use a non-root user.' });
                    }
                }
                if (/^FROM\s/i.test(line)) {
                    const image = line.substring(5).trim().split(' ')[0];
                    if (!image.includes(':') || image.endsWith(':latest')) {
                        findings.push({ severity: 'medium', message: `Unpinned base image: ${image}`, file: file.path, line: i + 1, recommendation: 'Pin to a specific version tag.' });
                    }
                }
                if (/^ARG\s/i.test(line)) {
                    const argName = line.substring(4).trim().split('=')[0];
                    if (/password|secret|key|token|api_key/i.test(argName)) {
                        findings.push({ severity: 'high', message: `Secret in build argument: ${argName}`, file: file.path, line: i + 1, recommendation: 'Use Docker BuildKit secrets instead.' });
                    }
                }
            }
            if (/privileged:\s*true/.test(line)) {
                findings.push({ severity: 'critical', message: 'Container in privileged mode', file: file.path, line: i + 1, recommendation: 'Remove privileged mode. Use specific capabilities.' });
            }
        }
        if (isDockerfile && !hasUser) {
            findings.push({ severity: 'medium', message: 'No USER instruction — runs as root', file: file.path, recommendation: 'Add USER instruction for non-root execution.' });
        }
    }
    return { name: 'Dockerfile Security', description: 'Checks Docker configurations', findings };
}

async function scanGithubActions(owner, repo, tree) {
    const findings = [];
    const workflows = tree.filter(item =>
        item.type === 'blob' && item.path.startsWith('.github/workflows/') && (item.path.endsWith('.yml') || item.path.endsWith('.yaml'))
    );

    for (const file of workflows) {
        const content = await fetchFileContent(owner, repo, file.path);
        if (!content) continue;
        const lines = content.split('\n');

        // Check permissions
        if (!content.includes('permissions:')) {
            findings.push({ severity: 'medium', message: 'No explicit permissions set', file: file.path, recommendation: "Add 'permissions: read-all' and grant write only where needed." });
        }
        if (content.includes('permissions: write-all')) {
            findings.push({ severity: 'high', message: "Workflow has 'write-all' permissions", file: file.path, recommendation: 'Use least-privilege permissions.' });
        }

        // Check unpinned actions
        for (let i = 0; i < lines.length; i++) {
            const match = lines[i].match(/uses:\s*([^@\s]+)@([^\s#]+)/);
            if (match) {
                const [, action, ref] = match;
                if (action.startsWith('./')) continue;
                if (/^[a-f0-9]{40}$/.test(ref)) continue;
                findings.push({ severity: 'medium', message: `Unpinned action: ${action}@${ref}`, file: file.path, line: i + 1, recommendation: `Pin to a full SHA hash instead of '${ref}'.` });
            }
        }

        // Check pull_request_target
        if (content.includes('pull_request_target')) {
            findings.push({ severity: 'high', message: "Uses 'pull_request_target' trigger", file: file.path, recommendation: 'Ensure you are not running untrusted code from PR head.' });
        }
    }
    return { name: 'GitHub Actions', description: 'Audits workflow security', findings };
}

async function scanDependencies(owner, repo, tree) {
    const findings = [];
    const depFiles = {
        'package.json': 'node',
        'requirements.txt': 'python',
    };

    for (const file of tree) {
        if (file.type !== 'blob') continue;
        const basename = file.path.split('/').pop();
        if (!(basename in depFiles)) continue;
        if (file.path.includes('node_modules/')) continue;

        const content = await fetchFileContent(owner, repo, file.path);
        if (!content) continue;

        if (basename === 'requirements.txt') {
            content.split('\n').forEach((line, i) => {
                line = line.trim();
                if (!line || line.startsWith('#') || line.startsWith('-')) return;
                if (!line.includes('==') && !line.includes('>=') && !line.includes('<=')) {
                    findings.push({ severity: 'low', message: `Unpinned dependency: ${line}`, file: file.path, line: i + 1, recommendation: 'Pin version for reproducible builds.' });
                }
            });
        }

        if (basename === 'package.json') {
            try {
                const pkg = JSON.parse(content);
                const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
                for (const [name, version] of Object.entries(allDeps || {})) {
                    if (version === '*' || version === 'latest') {
                        findings.push({ severity: 'medium', message: `Wildcard dependency: ${name}@${version}`, file: file.path, recommendation: `Pin ${name} to a specific version range.` });
                    }
                }
            } catch { /* ignore parse errors */ }
        }
    }

    if (findings.length === 0) {
        const hasDeps = tree.some(f => Object.keys(depFiles).includes(f.path.split('/').pop()));
        if (!hasDeps) {
            findings.push({ severity: 'info', message: 'No dependency files found', recommendation: 'Scanner works best with package.json or requirements.txt.' });
        }
    }
    return { name: 'Dependency Check', description: 'Checks for vulnerable dependencies', findings };
}

async function scanGitignore(owner, repo, tree) {
    const findings = [];
    const gitignoreFile = tree.find(f => f.path === '.gitignore');
    let gitignoreContent = '';

    if (!gitignoreFile) {
        findings.push({ severity: 'medium', message: 'No .gitignore file found', recommendation: 'Create a .gitignore for your project type.' });
    } else {
        gitignoreContent = (await fetchFileContent(owner, repo, '.gitignore')) || '';
    }

    // Check for sensitive files existing in the repo
    for (const sensitive of SENSITIVE_GITIGNORE) {
        const exists = tree.some(f => f.path === sensitive.file || f.path.endsWith('/' + sensitive.file));
        if (exists && !gitignoreContent.includes(sensitive.file)) {
            findings.push({ severity: sensitive.severity, message: `Sensitive file in repo: ${sensitive.file} (${sensitive.description})`, recommendation: `Add '${sensitive.file}' to .gitignore and remove from repo.` });
        }
    }

    return { name: 'Gitignore Check', description: 'Validates gitignore coverage', findings };
}

// ==========================================
// Grade Calculation
// ==========================================

function calculateGrade(results) {
    const severityScores = { critical: 10, high: 8, medium: 5, low: 2, info: 0 };
    let score = 100;

    for (const result of results) {
        for (const finding of result.findings) {
            score -= (severityScores[finding.severity] || 0);
        }
    }
    score = Math.max(0, score);

    if (score >= 90) return { letter: 'A', score, label: 'Excellent Security', color: 'green' };
    if (score >= 80) return { letter: 'B', score, label: 'Good Security', color: 'blue' };
    if (score >= 70) return { letter: 'C', score, label: 'Fair — Needs Attention', color: 'yellow' };
    if (score >= 60) return { letter: 'D', score, label: 'Poor — Significant Gaps', color: 'orange' };
    return { letter: 'F', score, label: 'Critical — Immediate Action Required', color: 'red' };
}

function getStatus(findings) {
    const hasCritHigh = findings.some(f => f.severity === 'critical' || f.severity === 'high');
    const hasMedLow = findings.some(f => f.severity === 'medium' || f.severity === 'low');
    if (hasCritHigh) return 'FAIL';
    if (hasMedLow) return 'WARN';
    return 'PASS';
}

// ==========================================
// UI Logic
// ==========================================

async function startScan() {
    const input = document.getElementById('repo-input').value.trim();
    const errorEl = document.getElementById('error-msg');
    const btnText = document.querySelector('.scan-btn-text');
    const btnLoading = document.querySelector('.scan-btn-loading');
    const scanBtn = document.getElementById('scan-btn');

    errorEl.style.display = 'none';

    if (!input) {
        showError('Please enter a GitHub repository URL.');
        return;
    }

    const parsed = parseRepoUrl(input);
    if (!parsed) {
        showError('Invalid URL. Use format: https://github.com/owner/repo or owner/repo');
        return;
    }

    // Show loading
    btnText.style.display = 'none';
    btnLoading.style.display = 'inline';
    scanBtn.disabled = true;

    try {
        // Fetch repo tree
        const treeData = await fetchRepoTree(parsed.owner, parsed.repo);
        const tree = treeData.tree || [];

        // Run all scanners
        const results = await Promise.all([
            scanSecrets(parsed.owner, parsed.repo, tree),
            scanDockerfile(parsed.owner, parsed.repo, tree),
            scanGithubActions(parsed.owner, parsed.repo, tree),
            scanDependencies(parsed.owner, parsed.repo, tree),
            scanGitignore(parsed.owner, parsed.repo, tree),
        ]);

        // Calculate grade
        const grade = calculateGrade(results);

        // Render results
        renderResults(results, grade, `${parsed.owner}/${parsed.repo}`);

    } catch (err) {
        showError(err.message);
    } finally {
        btnText.style.display = 'inline';
        btnLoading.style.display = 'none';
        scanBtn.disabled = false;
    }
}

function showError(msg) {
    const errorEl = document.getElementById('error-msg');
    errorEl.textContent = msg;
    errorEl.style.display = 'block';
}

function renderResults(results, grade, repoName) {
    // Hide hero features, show results
    document.querySelector('.hero').style.minHeight = 'auto';
    document.querySelector('.hero').style.paddingBottom = '20px';
    document.querySelector('.floating-cards').style.display = 'none';
    document.getElementById('results').style.display = 'block';
    document.getElementById('features').style.display = 'none';

    // Scroll to results
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });

    // Grade display
    const gradeCircle = document.getElementById('grade-circle');
    gradeCircle.className = `grade-circle grade-${grade.letter}`;
    document.getElementById('grade-letter').textContent = grade.letter;
    document.getElementById('grade-score').textContent = `${grade.score}/100`;
    document.getElementById('grade-label').textContent = grade.label;
    document.getElementById('grade-repo').textContent = repoName;

    // Scanner table
    const tbody = document.getElementById('results-body');
    tbody.innerHTML = '';

    const icons = {
        'Secret Detection': '🔑',
        'Dependency Check': '📦',
        'GitHub Actions': '⚙️',
        'Dockerfile Security': '🐳',
        'Gitignore Check': '📄',
    };

    const statusHTML = {
        'PASS': '<span class="status-pass">✅ PASS</span>',
        'WARN': '<span class="status-warn">⚠️ WARN</span>',
        'FAIL': '<span class="status-fail">❌ FAIL</span>',
    };

    for (const result of results) {
        const status = getStatus(result.findings);
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${icons[result.name] || '🔍'} ${result.name}</td>
            <td>${statusHTML[status]}</td>
            <td>${result.findings.length}</td>
        `;
        tbody.appendChild(tr);
    }

    // Detailed findings
    const detailEl = document.getElementById('findings-detail');
    detailEl.innerHTML = '';

    for (const result of results) {
        if (result.findings.length === 0) continue;

        const group = document.createElement('div');
        group.className = 'finding-group';

        let html = `<div class="finding-group-header">${icons[result.name] || '🔍'} ${result.name} — ${result.findings.length} finding(s)</div>`;

        for (const finding of result.findings) {
            html += `
                <div class="finding-item">
                    <div>
                        <span class="finding-severity severity-${finding.severity}">${finding.severity}</span>
                        <span class="finding-message">${escapeHtml(finding.message)}</span>
                    </div>
                    ${finding.file ? `<div class="finding-file">${escapeHtml(finding.file)}${finding.line ? ':' + finding.line : ''}</div>` : ''}
                    ${finding.recommendation ? `<div class="finding-recommendation">💡 ${escapeHtml(finding.recommendation)}</div>` : ''}
                </div>
            `;
        }

        group.innerHTML = html;
        detailEl.appendChild(group);
    }
}

function resetScan() {
    document.getElementById('results').style.display = 'none';
    document.getElementById('features').style.display = 'block';
    document.querySelector('.hero').style.minHeight = '100vh';
    document.querySelector('.hero').style.paddingBottom = '80px';
    document.querySelector('.floating-cards').style.display = 'block';
    document.getElementById('repo-input').value = '';
    document.getElementById('error-msg').style.display = 'none';
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Allow Enter key to trigger scan
document.getElementById('repo-input').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') startScan();
});
