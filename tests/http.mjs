// Read a response ONCE.
//
// An assertion message is evaluated eagerly, so `assert.equal(res.status, 200, await
// res.text())` consumes the body that the next line wants, and the test then fails with
// "Body is unusable" instead of the thing it was checking. That cost three debugging rounds
// in one session, so the trap is removed rather than avoided by hand each time.
export async function read(res) {
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* not JSON, text is what there is */ }
  return { status: res.status, text, body, headers: res.headers, res };
}

// The common shape: send, read once, and keep the body for the assertions.
export async function get(url, init) { return read(await fetch(url, init)); }
export async function post(url, init = {}) { return read(await fetch(url, { method: "POST", ...init })); }
