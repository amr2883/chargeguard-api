'use strict';
// Returns only the path part of a URL (no query string, no fragment).
// No decodeURI on purpose: a malformed URI must never throw inside an error handler.
function safeUrl(url) {
  if (typeof url !== 'string') return '';
  const cut = url.search(/[?#]/);
  return cut === -1 ? url : url.slice(0, cut);
}
module.exports = { safeUrl };
