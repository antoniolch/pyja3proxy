import socket
import threading
import select
import requests
import logging
import argparse
from curl_cffi import requests as curl_requests

BUFFER_SIZE = 4096

def setup_logging(debug_mode):
    """Sets up logging configuration."""
    log_level = logging.DEBUG if debug_mode else logging.INFO
    logging.basicConfig(
        filename="proxy.log",
        filemode="a",
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=log_level
    )
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    logging.getLogger().addHandler(console_handler)

def handle_client(client_socket, impersonate, debug_mode):
    """Handles an incoming client connection."""
    try:
        request = client_socket.recv(BUFFER_SIZE)
        if not request:
            client_socket.close()
            return

        first_line = request.decode().split("\n")[0]
        method, url, *_ = first_line.split()

        logging.info(f"Received request: {first_line.strip()}")

        if method == "CONNECT":
            handle_https(client_socket, url, impersonate)
        else:
            handle_http(client_socket, request, url, impersonate)

    except Exception as e:
        logging.error(f"Error handling client: {e}")
        client_socket.close()

def handle_http(client_socket, request, url, impersonate):
    """Handles both HTTP/1.1 and HTTP/2 requests."""
    try:
        http_pos = url.find("://")
        if http_pos != -1:
            url = url[(http_pos + 3):]
        port_pos = url.find(":")
        if port_pos == -1:
            host = url.split("/")[0]
            port = 80
        else:
            host = url[:port_pos]
            port = int(url[(port_pos + 1):].split("/")[0])

        logging.info(f"Forwarding HTTP request to {host}:{port}")

        if b"HTTP/2" in request:
            response = curl_requests.get(f"http://{host}:{port}", impersonate=impersonate)
        else:
            response = requests.get(f"http://{host}:{port}")

        client_socket.sendall(
            f"HTTP/1.1 {response.status_code} OK\r\n".encode() +
            b"\r\n".join([f"{k}: {v}".encode() for k, v in response.headers.items()]) +
            b"\r\n\r\n" + response.content
        )
        logging.info(f"Response: {response.status_code} - {len(response.content)} bytes")

    except Exception as e:
        logging.error(f"HTTP Proxy Error: {e}")
    finally:
        client_socket.close()

def handle_https(client_socket, url, impersonate):
    """Handles HTTPS CONNECT requests and supports HTTP/1.1 & HTTP/2."""
    try:
        host, port = url.split(":")
        port = int(port)

        logging.info(f"Establishing HTTPS tunnel to {host}:{port}")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))

        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Determine if the request is HTTP/2
        try:
            response = curl_requests.get(f"https://{host}:{port}", impersonate=impersonate)
            is_http2 = response.http_version == "HTTP/2"
        except Exception:
            is_http2 = False

        if is_http2:
            logging.info(f"Handling HTTPS as HTTP/2 for {host}:{port}")
            response = curl_requests.get(f"https://{host}:{port}", impersonate=impersonate)
        else:
            logging.info(f"Handling HTTPS as HTTP/1.1 for {host}:{port}")
            response = requests.get(f"https://{host}:{port}")

        client_socket.sendall(
            f"HTTP/1.1 {response.status_code} OK\r\n".encode() +
            b"\r\n".join([f"{k}: {v}".encode() for k, v in response.headers.items()]) +
            b"\r\n\r\n" + response.content
        )

        logging.info(f"HTTPS Response: {response.status_code} - {len(response.content)} bytes")

    except Exception as e:
        logging.error(f"HTTPS Proxy Error: {e}")
    finally:
        client_socket.close()

def start_proxy(interface, port, impersonate, debug_mode):
    """Starts the proxy server."""
    setup_logging(debug_mode)

    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind((interface, port))
    proxy_socket.listen(100)

    logging.info(f"Proxy Server Listening on {interface}:{port} (Impersonating {impersonate})")

    while True:
        client_sock, _ = proxy_socket.accept()
        threading.Thread(target=handle_client, args=(client_sock, impersonate, debug_mode)).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python HTTP/HTTPS Proxy")
    parser.add_argument("--interface", type=str, default="0.0.0.0", help="IP address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port number to listen on (default: 8080)")
    parser.add_argument("--impersonate", type=str, default="chrome131", help="Chrome version to impersonate (default: chrome131)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    start_proxy(args.interface, args.port, args.impersonate, args.debug)
