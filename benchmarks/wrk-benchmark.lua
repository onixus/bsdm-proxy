-- wrk benchmark script for BSDM-Proxy

math.randomseed(os.time())

local urls = {
    "https://httpbin.org/get",
    "https://api.github.com/users/octocat",
    "https://jsonplaceholder.typicode.com/posts/1",
    "https://example.com",
}

request = function()
    local url = urls[math.random(#urls)]
    local headers = {}
    headers["Host"] = "httpbin.org"
    headers["User-Agent"] = "BSDM-Proxy-Benchmark/1.0"
    
    return wrk.format("GET", url, headers)
end

response = function(status, headers, body)
    if status ~= 200 then
        print("Error: " .. status)
    end
end

done = function(summary, latency, requests)
    io.write("------------------------------------\n")
    io.write("Total Requests: " .. summary.requests .. "\n")
    io.write("Requests/sec: " .. string.format("%.2f", summary.requests / summary.duration * 1e6) .. "\n")
    io.write("Latency (avg): " .. string.format("%.2f", latency.mean / 1000) .. "ms\n")
    io.write("Latency (p50): " .. string.format("%.2f", latency:percentile(50) / 1000) .. "ms\n")
    io.write("Latency (p99): " .. string.format("%.2f", latency:percentile(99) / 1000) .. "ms\n")
    io.write("------------------------------------\n")
end
