'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const publish = require('./cryptoscan_pr_comment.cjs');

function fixture(comments = []) {
  const calls = [];
  const pr = { number: 7, head: { sha: 'abc', repo: { full_name: 'owner/repo' } },
    base: { sha: 'def' } };
  const latest = { state: 'open', head: { sha: 'abc' }, base: { sha: 'def' } };
  const github = {
    rest: {
      pulls: { get: async () => ({ data: latest }) },
      issues: { listComments: () => {},
        createComment: async args => calls.push(['create', args]),
        updateComment: async args => calls.push(['update', args]) },
    },
    paginate: async () => comments,
  };
  return { github, context: { repo: { owner: 'owner', repo: 'repo' },
    payload: { pull_request: pr } }, core: { info: () => {} },
    body: '<!-- cryptoscan-pr-summary -->\n## CryptoScan\n', calls, latest };
}

test('creates the first summary and updates the same bot comment on reruns', async () => {
  const first = fixture();
  await publish(first);
  assert.equal(first.calls[0][0], 'create');
  assert.equal(first.calls[0][1].issue_number, 7);
  const rerun = fixture([{ id: 99, user: { login: 'github-actions[bot]', type: 'Bot' },
    body: first.body }]);
  await publish(rerun);
  assert.equal(rerun.calls[0][0], 'update');
  assert.equal(rerun.calls[0][1].comment_id, 99);
});

test('does not overwrite a human comment containing the marker', async () => {
  const f = fixture([{ id: 1, user: { login: 'developer', type: 'User' },
    body: '<!-- cryptoscan-pr-summary -->\nhello' }]);
  await publish(f);
  assert.equal(f.calls[0][0], 'create');
});

test('forks, closed PRs, and stale head or base commits do not publish', async () => {
  for (const kind of ['fork', 'closed', 'head', 'base']) {
    const f = fixture();
    if (kind === 'fork') f.context.payload.pull_request.head.repo.full_name = 'fork/repo';
    if (kind === 'closed') f.latest.state = 'closed';
    if (kind === 'head') f.latest.head.sha = 'new';
    if (kind === 'base') f.latest.base.sha = 'new';
    await publish(f);
    assert.deepEqual(f.calls, []);
  }
});

test('rejects unexpected or oversized report content', async () => {
  for (const body of ['unmarked report', '<!-- cryptoscan-pr-summary -->\n' + 'x'.repeat(60001)]) {
    const f = fixture();
    f.body = body;
    await assert.rejects(publish(f), /Invalid CryptoScan/);
    assert.deepEqual(f.calls, []);
  }
});
