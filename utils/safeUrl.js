// Guards the "test connection" button, which makes the server fetch a URL a
// tenant admin typed in. Private networks stay allowed — an on-premise SAP
// endpoint is a real use — but the server's own loopback and link-local
// addresses (where cloud metadata services live) are refused.

const dns = require("dns").promises;
const net = require("net");

function isRefusedAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 127 || a === 0 || (a === 169 && b === 254);
  }
  const v6 = ip.toLowerCase();
  if (v6 === "::1" || v6 === "::") return true;
  if (/^fe[89ab]/.test(v6)) return true; // fe80::/10 link-local
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(v6);
  return mapped ? isRefusedAddress(mapped[1]) : false;
}

/** null when the URL may be fetched, else a message saying why not. */
async function checkTestTarget(rawUrl) {
  let host;
  try {
    host = new URL(rawUrl).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return "That is not a valid URL.";
  }
  if (host.toLowerCase() === "localhost") return "That address can't be tested from here.";
  let addresses;
  try {
    addresses = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  } catch {
    return `Could not resolve ${host}.`;
  }
  if (addresses.some(({ address }) => isRefusedAddress(address))) {
    return "That address can't be tested from here.";
  }
  return null;
}

module.exports = { checkTestTarget };
