// One HTTPS GET, to an address that was checked, with a real timeout and a real size cap.
//
// This file exists because of a measured failure. The resolver used to call global fetch with
// a `connectTo` option, believing that pinned the connection to the address the allowlist had
// just approved. Node's fetch has no such option and ignores it in silence, so the check ran
// and the connection was then made by hostname, which is the TOCTOU hole the pin was supposed
// to close. Worse, the only test of it asserted that a FAKE fetch had recorded the option, so
// the suite stayed green over a defence that did not exist. That is the exact failure the
// header of addresses.mjs warns about, committed in the file that warns about it.
//
// So this uses node:https, where `lookup` is a real option that node:net honours, and hands it
// a function that returns ONLY the checked address. The hostname is still what goes in the Host
// header and in SNI, so the certificate is verified against the name, not the address.
//
// It also streams: the size cap is applied as bytes arrive rather than after the body is
// buffered, and the request is aborted at the cap or at the timeout. The previous version read
// the whole body with res.text() before measuring it, and passed no abort signal at all, so a
// slow or enormous document held a builder's first request for as long as the default allowed.
import { request } from "node:https";

export function pinnedGet(url, { address, timeoutMs = 5000, maxBytes = 100_000,
                                 headers = {}, ca } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(new Error(`not a URL: ${url}`)); }
    if (typeof address !== "string" || !address)
      return reject(new Error("no address to pin the connection to"));

    // One settle path. Three things race here (the body, the cap, the clock) and an earlier
    // version relied on the response's `end` event firing after the request was destroyed,
    // which it does not, so an oversize body was silently accepted.
    let done = false;
    const finish = (fn, value) => { if (done) return; done = true; clearTimeout(timer); fn(value); };

    const timer = setTimeout(() => {
      req.destroy();
      finish(reject, Object.assign(new Error(`no answer within ${timeoutMs}ms`), { timedOut: true }));
    }, timeoutMs);

    const req = request({
      protocol: "https:",
      hostname: u.hostname,
      port: u.port || 443,
      path: u.pathname + u.search,
      method: "GET",
      headers: { accept: "application/json", ...headers },
      // The real pin: node:net calls this instead of resolving the hostname, so the socket
      // goes to the address the allowlist approved and nothing can answer differently.
      lookup: (hostname, options, callback) => {
        const family = address.includes(":") ? 6 : 4;
        if (options?.all) return callback(null, [{ address, family }]);
        return callback(null, address, family);
      },
      // The certificate is still checked against the NAME, which is why the hostname stays in
      // the request and in SNI. `ca` is for a test that generates its own; production passes
      // nothing and gets the system store.
      servername: u.hostname,
      rejectUnauthorized: true,
      ...(ca ? { ca } : {}),
    }, (res) => {
      const status = res.statusCode ?? 0;
      // Read now: the socket is detached by the time `end` fires, so reading it there gives
      // null, and this is the one value that proves which address was actually reached.
      const remoteAddress = res.socket?.remoteAddress ?? null;
      let body = "", bytes = 0;
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        if (done) return;
        bytes += Buffer.byteLength(chunk, "utf8");
        if (bytes > maxBytes) {
          req.destroy();
          finish(reject, Object.assign(new Error(`larger than ${maxBytes} bytes`), { overCap: true, bytes }));
          return;
        }
        body += chunk;
      });
      res.on("end", () => finish(resolve, {
        // A redirect is never followed: 5.3 step 1 fetches the client metadata "without
        // following redirects, as the CIMD draft (§5) requires". The caller reads the status.
        status, redirected: false,
        headers: new Map(Object.entries(res.headers ?? {})),
        text: async () => body,
        json: async () => JSON.parse(body),
        clone() { return this; },
        remoteAddress,
      }));
      res.on("error", (err) => finish(reject, err));
    });

    req.on("error", (err) => finish(reject, err));
    req.end();
  });
}
