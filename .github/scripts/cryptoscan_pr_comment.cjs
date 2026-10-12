// Publish an idempotent summary using only the workflow's same-repository token.
'use strict';

const MARKER = '<!-- cryptoscan-pr-summary -->';

module.exports = async function publish({ github, context, core, body }) {
  const pr = context.payload.pull_request;
  if (!pr || pr.head.repo?.full_name !== `${context.repo.owner}/${context.repo.repo}`) {
    core.info('PR comments are limited to same-repository pull requests.');
    return;
  }
  if (typeof body !== 'string' || !body.startsWith(`${MARKER}\n`) ||
      Buffer.byteLength(body, 'utf8') > 60000) {
    throw new Error('Invalid CryptoScan PR summary');
  }
  const parameters = { ...context.repo, issue_number: pr.number };
  // A slower older run must not overwrite feedback for a newer PR commit.
  const { data: latest } = await github.rest.pulls.get({
    ...context.repo, pull_number: pr.number,
  });
  if (latest.state !== 'open' || latest.head.sha !== pr.head.sha ||
      latest.base.sha !== pr.base.sha) {
    core.info('PR changed since this scan; leaving its latest summary untouched.');
    return;
  }
  const comments = await github.paginate(github.rest.issues.listComments, {
    ...parameters, per_page: 100,
  });
  const existing = comments.find(comment =>
    comment.user?.login === 'github-actions[bot]' &&
    comment.user?.type === 'Bot' && comment.body?.startsWith(`${MARKER}\n`));
  if (existing) {
    await github.rest.issues.updateComment({
      ...context.repo, comment_id: existing.id, body,
    });
  } else {
    await github.rest.issues.createComment({ ...parameters, body });
  }
  core.info('CryptoScan PR summary updated.');
};
