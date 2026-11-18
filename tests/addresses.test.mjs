// Which addresses this grader will connect to, and which it refuses.
//
// Section 3: "Personal Agents and Companies MUST NOT connect to a loopback, private, or
// link-local address for a URL the other party gave them, unless they were configured to on
// purpose. Otherwise a Company could aim Personal Agents at another Company's servers or at
// internal ones."
//
// Verifying a delegation means fetching a URL a stranger chose, from inside our network, so
// this is the security boundary of the whole capability. It is a pure function over a string so
// that it can be tested exhaustively, which matters: this project has a recorded case of an
// SSRF pin that never ran because every fixture used an address literal, and the suite was
// green throughout. The classifier is an ALLOWLIST: anything not recognised as a routable
// public address is refused, so a range nobody thought of fails closed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyAddress, checkTargetUrl } from "../addresses.mjs";

test("every address a stranger could aim us at is refused, by name", () => {
  const refused = {
    loopback: ["127.0.0.1", "127.1.2.3", "127.255.255.254", "::1", "[::1]"],
    unspecified: ["0.0.0.0", "::", "[::]"],
    private: ["10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
              "192.168.0.1", "192.168.255.255", "fc00::1", "fd12:3456::1"],
    "link-local": ["169.254.169.254", "169.254.0.1", "fe80::1", "fe80::dead:beef"],
    cgnat: ["100.64.0.1", "100.127.255.255"],
    multicast: ["224.0.0.1", "239.255.255.255", "ff02::1"],
    reserved: ["240.0.0.1", "255.255.255.255", "192.0.0.1"],
    documentation: ["192.0.2.1", "198.51.100.1", "203.0.113.1"],
  };
  for (const [why, list] of Object.entries(refused))
    for (const addr of list) {
      const c = classifyAddress(addr);
      assert.equal(c.allowed, false, `${addr} was allowed`);
      assert.equal(c.kind, why, `${addr} was called ${c.kind} rather than ${why}`);
    }
});

test("the IPv4 forms hidden inside IPv6 are decoded before they are classified", () => {
  // The classic bypass: a classifier that only looks for "127." sees ::ffff:127.0.0.1 as an
  // IPv6 address it does not recognise, and a classifier that then defaults to allow lets it
  // through to the loopback interface.
  for (const addr of ["::ffff:127.0.0.1", "[::ffff:127.0.0.1]", "::ffff:7f00:1",
                      "::127.0.0.1", "0:0:0:0:0:ffff:127.0.0.1"]) {
    const c = classifyAddress(addr);
    assert.equal(c.allowed, false, `${addr} was allowed`);
    assert.equal(c.kind, "loopback", `${addr} was called ${c.kind}`);
  }
  for (const addr of ["::ffff:10.0.0.1", "::ffff:192.168.1.1", "::ffff:169.254.169.254"])
    assert.equal(classifyAddress(addr).allowed, false, `${addr} was allowed`);
});

test("a routable public address is allowed, or the classifier refuses everything", () => {
  // The control. Without it a classifier that returns false for every input passes every
  // assertion above, which is the vacuous check this project exists to catch.
  for (const addr of ["93.184.216.34", "1.1.1.1", "8.8.8.8", "172.32.0.1", "172.15.255.255",
                      "100.63.255.255", "100.128.0.1", "2606:4700::1111", "[2606:4700::1111]"]) {
    const c = classifyAddress(addr);
    assert.equal(c.allowed, true, `${addr} was refused as ${c.kind}`);
    assert.equal(c.kind, "public");
  }
});

test("anything unrecognisable fails closed", () => {
  // "abc" and "dead" matter: they contain only hex characters, so a classifier that validates
  // IPv6 by splitting on colons and checking each group sees ONE group of valid hex and allows
  // them. A mutation that removed the syntax check survived this test until these were added.
  for (const addr of ["", "not-an-address", "999.999.999.999", "127.0.0", "::gg",
                      "abc", "dead", "f", "beef", "localhost", null, undefined, 42])
    assert.equal(classifyAddress(addr).allowed, false, `${addr} was allowed`);
});

test("a target URL is refused for its scheme, its credentials and its port before any lookup", () => {
  // These are decidable without touching the network, so they are decided first. 4.1: a
  // client_id "MUST be an HTTPS URL"; section 3: "Companies MUST reject one from a Personal
  // Agent" for another scheme.
  const ok = checkTargetUrl("https://agent.example/agent.json");
  assert.equal(ok.allowed, true, ok.why);
  assert.equal(ok.host, "agent.example");

  for (const [url, kind] of [
    ["http://agent.example/agent.json", "scheme"],
    ["ftp://agent.example/a", "scheme"],
    ["https://user:pw@agent.example/a", "credentials"],
    ["https://agent.example:8443/a", "port"],
    ["https://127.0.0.1/a", "address"],
    ["https://[::1]/a", "address"],
    ["https://10.0.0.1/a", "address"],
    ["not a url", "url"],
    ["", "url"],
  ]) {
    const r = checkTargetUrl(url);
    assert.equal(r.allowed, false, `${url} was allowed`);
    assert.equal(r.kind, kind, `${url} was refused as ${r.kind} rather than ${kind}`);
    assert.ok(r.why && r.why.length > 10, `${url} was refused without saying why`);
  }
  // an explicit :443 is the default port and is the same URL
  assert.equal(checkTargetUrl("https://agent.example:443/a").allowed, true);
});
