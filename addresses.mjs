// Which addresses this grader will connect to.
//
// Verifying a delegation means fetching a URL a stranger chose, from inside our network, so
// this file is the security boundary of that capability. Section 3: "Personal Agents and
// Companies MUST NOT connect to a loopback, private, or link-local address for a URL the other
// party gave them, unless they were configured to on purpose. Otherwise a Company could aim
// Personal Agents at another Company's servers or at internal ones."
//
// It is an ALLOWLIST, not a denylist. A range nobody thought of must fail closed, because the
// cost of the two directions is not symmetric: refusing a routable address produces an
// abstention a builder can argue with, and allowing an internal one produces a request to
// somebody's metadata service. Everything here is a pure function over a string so it can be
// tested exhaustively, which this project has a recorded reason to insist on: an SSRF pin once
// never ran at all because every fixture used an address literal, and the suite stayed green.

const v4 = (s) => {
  const parts = String(s).split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map(p => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  if (nums.some(n => Number.isNaN(n) || n > 255)) return null;
  return nums;
};

// An IPv4 address written inside an IPv6 one. The classic bypass is `::ffff:127.0.0.1`, which a
// classifier looking for a leading "127." does not see, so the forms are decoded to their IPv4
// value BEFORE anything is classified.
function asV4(raw) {
  const s = String(raw).replace(/^\[|\]$/g, "");
  const direct = v4(s);
  if (direct) return direct;
  if (!s.includes(":")) return null;
  const tail = s.split(":").pop();
  const dotted = v4(tail);
  // ::ffff:a.b.c.d and ::a.b.c.d both carry an IPv4 address.
  if (dotted && /^(0*:)*(0*:)*(ffff:)?/i.test(s)) return dotted;
  // ::ffff:7f00:1, the same address written as two hex groups.
  const m = s.match(/^(?:0{0,4}:)*(?:ffff:)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (m) {
    const hi = parseInt(m[1], 16), lo = parseInt(m[2], 16);
    return [hi >> 8 & 255, hi & 255, lo >> 8 & 255, lo & 255];
  }
  return null;
}

const KINDS = [
  ["unspecified", ([a, b, c, d]) => a === 0 && b === 0 && c === 0 && d === 0],
  ["loopback", ([a]) => a === 127],
  ["private", ([a, b]) => a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)],
  ["link-local", ([a, b]) => a === 169 && b === 254],
  ["cgnat", ([a, b]) => a === 100 && b >= 64 && b <= 127],
  ["multicast", ([a]) => a >= 224 && a <= 239],
  // 192.0.0.0/24 is IETF protocol assignments, 240/4 is reserved, 255.255.255.255 is broadcast.
  ["reserved", ([a, b, c, d]) => (a === 192 && b === 0 && c === 0) || a >= 240],
  // RFC 5737 documentation ranges. Not routable, so a fetch there reaches nothing real, and
  // refusing them keeps our own example addresses out of the network.
  ["documentation", ([a, b, c]) => (a === 192 && b === 0 && c === 2)
    || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)],
];

export function classifyAddress(raw) {
  if (typeof raw !== "string" || !raw) return { allowed: false, kind: "unparseable" };
  const s = raw.replace(/^\[|\]$/g, "");
  const four = asV4(s);
  if (four) {
    for (const [kind, test] of KINDS) if (test(four)) return { allowed: false, kind };
    return { allowed: true, kind: "public" };
  }
  // IPv6, by its own rules. Anything that is not a well-formed address is refused.
  if (!/^[0-9a-f:]+$/i.test(s) || !s.includes(":")) return { allowed: false, kind: "unparseable" };
  if (/^0*:(0*:)*0*$/.test(s)) return { allowed: false, kind: "unspecified" };
  if (/^(0*:)*0*1$/.test(s)) return { allowed: false, kind: "loopback" };
  if (/^f[cd][0-9a-f]{0,2}:/i.test(s)) return { allowed: false, kind: "private" };
  if (/^fe[89ab][0-9a-f]?:/i.test(s)) return { allowed: false, kind: "link-local" };
  if (/^ff[0-9a-f]{2}:/i.test(s)) return { allowed: false, kind: "multicast" };
  const groups = s.split(":");
  if (groups.some(g => g !== "" && !/^[0-9a-f]{1,4}$/i.test(g))) return { allowed: false, kind: "unparseable" };
  return { allowed: true, kind: "public" };
}

// Everything about a target URL that is decidable without the network, decided first.
//
// The port restriction is OURS and not the specification's: 4.1 permits any https URL, so a
// URL on another port is never a FAIL against the agent, only something this grader declines to
// connect to. A grader that connects to arbitrary ports is a port scanner for whoever holds
// the lease.
export function checkTargetUrl(raw) {
  let u;
  try { u = new URL(String(raw)); } catch { return { allowed: false, kind: "url", why: `not a URL: ${String(raw).slice(0, 80)}` }; }
  if (u.protocol !== "https:")
    return { allowed: false, kind: "scheme", why: `${u.protocol}//, and section 3 requires every URL this protocol exchanges to be HTTPS` };
  if (u.username || u.password)
    return { allowed: false, kind: "credentials", why: "a URL carrying credentials, which this grader will not send" };
  if (u.port && u.port !== "443")
    return { allowed: false, kind: "port", why: `port ${u.port}, and this grader connects only to 443` };
  // A host written as an address literal is classified here; a hostname is classified after
  // resolution, against every address it resolves to.
  const literal = classifyAddress(u.hostname);
  if (/^[\d.]+$/.test(u.hostname) || u.hostname.includes(":") || u.hostname.startsWith("[")) {
    if (!literal.allowed)
      return { allowed: false, kind: "address", why: `a ${literal.kind} address, which section 3 forbids connecting to for a URL the other party gave us` };
  }
  return { allowed: true, url: u.toString(), host: u.hostname, origin: u.origin };
}
