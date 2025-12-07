# BSDM-Proxy Web Configurator

🌐 **Visual configuration tool for BSDM-Proxy**

## 🚀 Quick Start

### Option 1: Using Python HTTP Server (Recommended)

```bash
cd web-config
python3 serve.py
```

Then open: http://localhost:8000

### Option 2: Using Python Built-in Server

```bash
cd web-config
python3 -m http.server 8000
```

Then open: http://localhost:8000

### Option 3: Direct File Opening

Simply open `index.html` in your browser:
```bash
open index.html  # macOS
xdg-open index.html  # Linux
start index.html  # Windows
```

**Note:** Some browsers may restrict certain features when opening files directly.

## ⚙️ Features

### 7 Configuration Sections:

1. **General** - Basic proxy settings (ports, logging)
2. **Cache** - L1/L2 cache configuration
3. **Kafka** - Event streaming setup
4. **Auth** - Authentication (Basic, LDAP, NTLM)
5. **ACL** - Access control rules
6. **Categories** - URL categorization (Shallalist, URLhaus, PhishTank)
7. **Monitoring** - Prometheus, Grafana, OpenSearch

### Export Options:

- ✅ **Generate Configuration** - View all settings
- ✅ **Export .env** - Download environment variables file
- ✅ **Export docker-compose.yml** - Generate complete deployment
- ✅ **Copy to Clipboard** - Quick copy functionality

## 📝 Usage

1. **Navigate tabs** to configure each section
2. **Fill in values** or use defaults
3. **Enable features** with checkboxes
4. **Generate** configuration when ready
5. **Export** files for deployment

### Example Workflow:

```bash
# 1. Configure via web UI
cd web-config && python3 serve.py
# Open http://localhost:8000 and configure

# 2. Export files
# Click "Export .env" and "Export docker-compose.yml"

# 3. Deploy
mv ~/Downloads/.env ../
mv ~/Downloads/docker-compose.yml ../
cd .. && docker-compose up -d
```

## 🔧 Configuration Details

### Authentication

**Basic Auth:**
- No external dependencies
- Username/password only
- Fast and simple

**LDAP/Active Directory:**
- Enterprise authentication
- Group membership support
- Requires LDAP server

**NTLM:**
- Windows Integrated Auth
- Domain authentication
- TODO: Implementation pending

### ACL Rules

Quick presets available:
- ❌ Block Adult Content
- ❌ Block Gambling
- ✅ Block Malware (enabled by default)
- ✅ Block Phishing (enabled by default)

Custom rules via JSON file:
```json
{
  "default_action": "deny",
  "rules": [
    {
      "id": "allow-work",
      "action": "allow",
      "rule_type": {
        "Domain": "*.company.com"
      }
    }
  ]
}
```

### URL Categorization

**Shallalist** (Open-Source):
```bash
wget http://www.shallalist.de/Downloads/shallalist.tar.gz
tar -xzf shallalist.tar.gz -C /var/lib/
```

**URLhaus** (Malware):
- Real-time API
- No setup required
- Rate limited

**PhishTank** (Phishing):
- Community database
- API key recommended
- Free tier available

**Custom Database:**
JSON format:
```json
{
  "example.com": ["adult", "gambling"],
  "malicious-site.net": ["malware", "phishing"]
}
```

## 🐛 Troubleshooting

### UI Not Loading?

1. **Check browser console** (F12)
2. **Use HTTP server** instead of file://
3. **Clear browser cache** (Ctrl+Shift+R)
4. **Check file permissions**

### Configuration Not Generating?

1. **Fill required fields** (highlighted in red)
2. **Check browser console** for errors
3. **Try exporting .env** first (simpler output)

### Files Not Downloading?

1. **Check download folder** permissions
2. **Allow popup/downloads** in browser settings
3. **Use "Copy to Clipboard"** as alternative

### Styling Issues?

1. Ensure `styles.css` is in same directory
2. Check browser DevTools Network tab
3. Hard refresh (Ctrl+Shift+R)

## 📚 Resources

- [BSDM-Proxy Documentation](../README.md)
- [Shallalist Database](http://www.shallalist.de/)
- [URLhaus API](https://urlhaus.abuse.ch/)
- [PhishTank API](https://www.phishtank.com/)
- [OpenSearch Docs](https://opensearch.org/docs/)

## 🤝 Contributing

Contributions welcome!

- Add new configuration options
- Improve validation
- Add export formats
- Enhance UI/UX

## 📝 License

MIT License - See [LICENSE](../LICENSE)
