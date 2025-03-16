# Python HTTP/HTTPS Proxy (pyja3proxy)
Python proxy for TLS Fingerprinting with JA3

This is a **fully functional HTTP/HTTPS proxy** written in Python. It supports:
- **HTTP and HTTPS traffic forwarding**
- **HTTP/2 support with Chrome 131 impersonation** (via `curl_cffi`)
- **Custom listening interface & port**
- **Logging support**
- **Command-line arguments for configuration**

## 📦 Requirements
Install the necessary dependencies before running the proxy:
```sh
pip install requests curl_cffi argparse
```

## 🚀 Running the Proxy
To start the proxy server, use the following command:
```sh
python proxy.py --interface 0.0.0.0 --port 8080 --impersonate chrome131 --debug
```

### 🔹 Available Command-Line Arguments
| Argument | Description | Default Value |
|----------|-------------|---------------|
| `--interface` | IP address to bind (e.g., `127.0.0.1`, `0.0.0.0`) | `0.0.0.0` |
| `--port` | Port number to listen on | `8080` |
| `--impersonate` | Chrome version for impersonation (`chrome131`) | `chrome131` |
| `--debug` | Enable debug mode for verbose logging | Disabled |

## 🌍 Configuring Your System/Browser to Use the Proxy
To use the proxy, configure your browser or system proxy settings:
- **HTTP Proxy:** `127.0.0.1:8080`
- **HTTPS Proxy:** `127.0.0.1:8080`

For remote use, replace `127.0.0.1` with the **server's IP**.

## 🔍 Testing the Proxy
### **1️⃣ Test HTTP Requests**
```sh
curl -x http://127.0.0.1:8080 http://example.com
```
### **2️⃣ Test HTTPS Requests**
```sh
curl -x http://127.0.0.1:8080 https://example.com -k
```
### **3️⃣ Test HTTP/2 with Chrome 131 Impersonation**
```sh
curl --http2 -x http://127.0.0.1:8080 https://www.google.com -k
```

## 📜 Features
✅ **Supports HTTP & HTTPS requests**  
✅ **Handles HTTPS CONNECT method**  
✅ **Impersonates Chrome 131 using `curl_cffi`**  
✅ **Multi-threaded for handling multiple clients**  
✅ **Customizable via command-line arguments**  
✅ **Logging support (`proxy.log`)**

## 📌 Next Steps
- 🔒 Add authentication support
- 🚀 Implement caching
- 🔍 Enable TLS inspection (Man-in-the-Middle Proxy)

---
### 🛠️ Need Help?
If you have any issues or feature requests, feel free to submit an issue or a pull request! 🚀
