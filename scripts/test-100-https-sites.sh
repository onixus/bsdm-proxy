#!/usr/bin/env bash
# Test 100 HTTPS sites through BSDM proxy (single pass / MISS).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA="${CA:-$ROOT/certs/ca.crt}"
PROXY="${PROXY:-http://127.0.0.1:1488}"
CONCURRENCY="${CONCURRENCY:-10}"
MAX_TIME="${MAX_TIME:-25}"

if [[ ! -f "$CA" ]]; then
  echo "CA not found: $CA (run ./scripts/generate-mitm-ca.sh)" >&2
  exit 1
fi

SITES=(
  https://httpbin.org/get
  https://example.com/
  https://www.iana.org/
  https://www.wikipedia.org/
  https://en.wikipedia.org/wiki/Main_Page
  https://www.rust-lang.org/
  https://doc.rust-lang.org/
  https://crates.io/
  https://docs.rs/
  https://github.com/
  https://gitlab.com/
  https://stackoverflow.com/
  https://serverfault.com/
  https://superuser.com/
  https://news.ycombinator.com/
  https://www.mozilla.org/
  https://www.cloudflare.com/
  https://www.nginx.com/
  https://www.apache.org/
  https://www.gnu.org/
  https://www.kernel.org/
  https://www.python.org/
  https://docs.python.org/3/
  https://nodejs.org/
  https://www.php.net/
  https://go.dev/
  https://www.ruby-lang.org/
  https://www.perl.org/
  https://www.postgresql.org/
  https://redis.io/
  https://www.mongodb.com/
  https://www.elastic.co/
  https://kafka.apache.org/
  https://prometheus.io/
  https://grafana.com/
  https://www.docker.com/
  https://kubernetes.io/
  https://www.digitalocean.com/
  https://aws.amazon.com/
  https://azure.microsoft.com/
  https://cloud.google.com/
  https://www.apple.com/
  https://www.microsoft.com/
  https://www.ibm.com/
  https://www.intel.com/
  https://www.amd.com/
  https://www.debian.org/
  https://ubuntu.com/
  https://archlinux.org/
  https://www.freebsd.org/
  https://www.openbsd.org/
  https://www.eff.org/
  https://www.w3.org/
  https://www.ietf.org/
  https://letsencrypt.org/
  https://www.openssl.org/
  https://www.bbc.com/
  https://apnews.com/
  https://www.npr.org/
  https://arxiv.org/
  https://www.imdb.com/
  https://www.archive.org/
  https://www.khanacademy.org/
  https://www.coursera.org/
  https://www.edx.org/
  https://www.mit.edu/
  https://www.stanford.edu/
  https://www.harvard.edu/
  https://www.berkeley.edu/
  https://www.nasa.gov/
  https://www.noaa.gov/
  https://www.usgs.gov/
  https://www.cdc.gov/
  https://www.nih.gov/
  https://www.who.int/
  https://www.un.org/
  https://european-union.europa.eu/
  https://www.gov.uk/
  https://www.canada.ca/
  https://www.data.gov/
  https://jsonplaceholder.typicode.com/todos/1
  https://api.github.com/zen
  https://httpbingo.org/get
  https://1.1.1.1/cdn-cgi/trace
  https://ifconfig.me/
  https://ipinfo.io/json
  https://duckduckgo.com/
  https://www.bing.com/
  https://www.yahoo.com/
  https://www.ebay.com/
  https://www.etsy.com/
  https://www.spotify.com/
  https://vimeo.com/
  https://www.flickr.com/
  https://medium.com/
  https://dev.to/
  https://bitbucket.org/
  https://sourceforge.net/
  https://www.npmjs.com/
  https://pypi.org/
  https://packagist.org/
  https://hub.docker.com/
  https://lobste.rs/
  https://status.github.com/
  https://www.atlassian.com/
  https://slack.com/
  https://zoom.us/
  https://www.dropbox.com/
  https://www.wikimedia.org/
  https://commons.wikimedia.org/
  https://www.openstreetmap.org/
  https://react.dev/
  https://vuejs.org/
  https://angular.io/
  https://svelte.dev/
  https://tailwindcss.com/
  https://getbootstrap.com/
  https://www.typescriptlang.org/
  https://graphql.org/
  https://grpc.io/
  https://www.rabbitmq.com/
  https://nats.io/
  https://opensearch.org/
  https://www.sqlite.org/
  https://www.mariadb.org/
  https://www.djangoproject.com/
  https://fastapi.tiangolo.com/
  https://spring.io/
  https://laravel.com/
  https://wordpress.org/
  https://www.drupal.org/
  https://caddyserver.com/
  https://traefik.io/
  https://www.torproject.org/
  https://opensource.org/
  https://semver.org/
  https://12factor.net/
  https://martinfowler.com/
  https://arstechnica.com/
  https://www.wired.com/
  https://techcrunch.com/
  https://www.theverge.com/
  https://lwn.net/
  https://www.openweathermap.org/
  https://www.weather.gov/
  https://www.timeanddate.com/
  https://ourworldindata.org/
  https://www.kaggle.com/
  https://pytorch.org/
  https://huggingface.co/
  https://openai.com/
  https://www.meta.com/
  https://paperswithcode.com/
  https://blog.cloudflare.com/
  https://github.blog/
  https://stackoverflow.blog/
  https://www.cisa.gov/
  https://www.ncsc.gov.uk/
)

SITES=("${SITES[@]:0:100}")

if ((${#SITES[@]} != 100)); then
  echo "Expected 100 sites, got ${#SITES[@]}" >&2
  exit 1
fi

RESULTS="$(mktemp)"
trap 'rm -f "$RESULTS"' EXIT

test_one() {
  local url="$1"
  local out code time err
  if out=$(curl -sS -o /dev/null -w '%{http_code} %{time_total}' \
    --cacert "$CA" -x "$PROXY" --max-time "$MAX_TIME" --connect-timeout 10 \
    -A 'BSDM-Proxy-HTTPS-Test/1.0' "$url" 2>&1); then
    code=$(echo "$out" | awk '{print $1}')
    time=$(echo "$out" | awk '{print $2}')
    printf 'OK\t%s\t%s\t%s\n' "$code" "$time" "$url"
  else
    err=$(echo "$out" | tr '\n' ' ' | cut -c1-120)
    printf 'FAIL\t000\t0\t%s\t%s\n' "$url" "$err"
  fi
}

export -f test_one
export CA PROXY MAX_TIME

printf 'Testing %s HTTPS sites via %s (concurrency=%s)...\n' "${#SITES[@]}" "$PROXY" "$CONCURRENCY"

printf '%s\n' "${SITES[@]}" | xargs -P "$CONCURRENCY" -I {} bash -c 'test_one "$@"' _ {} >"$RESULTS"

total=$(wc -l <"$RESULTS" | tr -d ' ')
ok=$(grep -c '^OK' "$RESULTS" || true)
fail=$(grep -c '^FAIL' "$RESULTS" || true)

echo
echo "=== Summary ==="
echo "Total:   $total"
echo "OK:      $ok"
echo "FAIL:    $fail"

echo
echo "=== HTTP status distribution ==="
awk -F'\t' '$1=="OK"{print $2}' "$RESULTS" | sort | uniq -c | sort -rn

echo
echo "=== Timing (OK, seconds) ==="
awk -F'\t' '$1=="OK"{sum+=$3; if(!n||$3<min)min=$3; if($3>max)max=$3; n++} END{
  if(n>0) printf "count=%d avg=%.3f min=%.3f max=%.3f\n", n, sum/n, min, max
}' "$RESULTS"

echo
echo "=== Failed sites ($fail) ==="
grep '^FAIL' "$RESULTS" | awk -F'\t' '{printf "  %s\n    %s\n", $4, $5}'

echo
echo "=== Slowest 10 ==="
awk -F'\t' '$1=="OK"{print $3"\t"$4}' "$RESULTS" | sort -rn | head -10 | awk -F'\t' '{printf "  %.3fs  %s\n", $1, $2}'

echo
echo "=== Fastest 10 ==="
awk -F'\t' '$1=="OK"{print $3"\t"$4}' "$RESULTS" | sort -n | head -10 | awk -F'\t' '{printf "  %.3fs  %s\n", $1, $2}'

echo
echo "=== Proxy metrics ==="
curl -fsS "${METRICS_URL:-http://127.0.0.1:9090/metrics}" | grep -E '^bsdm_proxy_(cache_hits|cache_misses|requests_total)' | grep -v '#'
