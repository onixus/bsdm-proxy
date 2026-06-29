-- wrk: HTTP forward proxy with absolute request URI.
-- Usage: WRK_TARGET_URL=http://127.0.0.1:18080/path wrk -s scripts/wrk-proxy.lua http://PROXY:PORT

local default_target = "http://127.0.0.1:18080/loadtest-static"
local target_url = os.getenv("WRK_TARGET_URL") or default_target
local miss_mode = os.getenv("WRK_MISS_MODE") == "1"
local counter = 0

local hostport = target_url:match("^https?://([^/]+)")
if hostport then
  wrk.headers["Host"] = hostport
end

request = function()
  counter = counter + 1
  local url = target_url
  if miss_mode then
    url = string.format("http://127.0.0.1:18080/miss/%d-%d", counter, math.random(1000000000))
  end
  return wrk.format("GET", url)
end

responses = {}
response = function(status, _headers, _body)
  responses[status] = (responses[status] or 0) + 1
end

done = function(_summary, _latency, _requests)
  io.write("  wrk status codes:")
  for code, count in pairs(responses) do
    io.write(string.format(" [%s]=%d", code, count))
  end
  io.write("\n")
end
