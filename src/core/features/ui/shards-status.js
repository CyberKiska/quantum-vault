import { assessShardSelection } from '../../../app/crypto-service.js';

function applyAssessment(statusDiv, statusText, actionButton, assessment) {
    if (assessment.state === 'sufficient') {
        statusDiv.className = 'shards-status sufficient';
        statusText.textContent = assessment.message;
        statusDiv.setAttribute('aria-label', assessment.message);
        if (actionButton) actionButton.disabled = false;
        return;
    }
    if (assessment.state === 'insufficient') {
        statusDiv.className = 'shards-status insufficient';
        statusText.textContent = assessment.message;
        statusDiv.setAttribute('aria-label', assessment.message);
        if (actionButton) actionButton.disabled = true;
        return;
    }
    if (assessment.state === 'invalid') {
        statusDiv.className = 'shards-status invalid';
        statusText.textContent = assessment.message;
        statusDiv.setAttribute('aria-label', assessment.message);
        if (actionButton) actionButton.disabled = true;
        return;
    }
    statusDiv.className = 'shards-status unknown';
    statusText.textContent = assessment.message || 'Cannot determine restore threshold from selected files.';
    statusDiv.setAttribute('aria-label', statusText.textContent);
    if (actionButton) actionButton.disabled = true;
}

/**
 * Refresh shard readiness indicator.
 * The caller can pass `isCurrent()` to prevent stale async updates.
 */
export async function updateShardSelectionStatus({ files, statusDiv, statusText, actionButton, isCurrent = () => true }) {
    if (!statusDiv || !statusText) return;

    const count = files.length;
    if (count === 0) {
        statusDiv.style.display = 'none';
        if (actionButton) actionButton.disabled = true;
        return { state: 'empty', ready: false };
    }

    statusDiv.style.display = 'block';
    statusDiv.className = 'shards-status unknown';
    statusText.textContent = 'Analyzing shard metadata...';
    statusDiv.setAttribute('aria-label', 'Analyzing shard metadata...');
    if (actionButton) actionButton.disabled = true;

    const assessment = await assessShardSelection(files);
    if (!isCurrent()) return;
    applyAssessment(statusDiv, statusText, actionButton, assessment);
    return assessment;
}
