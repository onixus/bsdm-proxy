function FindProxyForURL(url, host) {
  if (host === "localhost" ||
      host === "127.0.0.1" ||
      shExpMatch(host, "*.local") ||
      shExpMatch(host, "*.localhost")) {
    return "DIRECT";
  }
  if (isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0") ||
      isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
      isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
      isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")) {
    return "DIRECT";
  }
  return "PROXY 127.0.0.1:8080";
}
