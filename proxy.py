#!/usr/bin/env python3
import argparse
import socket
import socketserver
import threading
import ssl
import logging

# Import the requests module from curl_cffi.
from curl_cffi import requests

logger = logging.getLogger("proxy")

# Define a dynamic impersonation function.
def impersonate(browser):
    """
    Patch curl_cffi.requests.request to add a default User-Agent header.
    Currently supports impersonation for "chrome131". Extend as needed.
    """
    if browser.lower() == "chrome131":
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    else:
        logger.warning("Impersonation for browser '%s' is not implemented. No changes made.", browser)
        return

    original_request = requests.request

    def new_request(method, url, **kwargs):
        headers = kwargs.get("headers", {})
        if "User-Agent" not in headers:
            headers["User-Agent"] = user_agent
        kwargs["headers"] = headers
        return original_request(method, url, **kwargs)

    requests.request = new_request
    logger.debug("Impersonation enabled: using %s User-Agent", browser)

class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            data = self.connection.recv(8192)
            if not data:
                return

            # Check for HTTP/2 client connection preface.
            if data.startswith(b"PRI * HTTP/2.0"):
                logger.debug("Handling HTTP/2 connection")
                self.handle_http2(data)
            else:
                # For HTTP/1.x: check if it's a CONNECT method (for HTTPS) or a standard HTTP request.
                first_line = data.splitlines()[0].decode('utf-8', errors='replace')
                parts = first_line.split()
                if len(parts) < 3:
                    return
                method = parts[0].upper()
                if method == "CONNECT":
                    logger.debug("Handling CONNECT request for %s", parts[1])
                    self.handle_connect(parts[1])
                else:
                    logger.debug("Handling HTTP/1.x request: %s", first_line)
                    self.handle_http(data)
        except Exception as e:
            logger.exception("Error handling request: %s", e)

    def handle_connect(self, target):
        """
        Handle HTTPS tunneling via the CONNECT method.
        """
        try:
            host, port = target.split(":")
            port = int(port)
        except Exception as e:
            logger.error("Invalid CONNECT target: %s", target)
            self.connection.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        try:
            remote = socket.create_connection((host, port))
            self.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except Exception as e:
            logger.error("Error connecting to remote %s:%s - %s", host, port, e)
            self.connection.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        self.tunnel(self.connection, remote)

    def tunnel(self, client, remote):
        """
        Bidirectionally forward data between client and remote.
        """
        def forward(source, destination):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    destination.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=forward, args=(client, remote))
        t2 = threading.Thread(target=forward, args=(remote, client))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def handle_http(self, initial_data):
        """
        Handle an HTTP/1.x request: parse the request, forward it via curl_cffi.requests,
        and return the response back to the client. All HTTP verbs are forwarded.
        For HEAD requests, no response body is returned.
        """
        try:
            lines = initial_data.split(b'\r\n')
            request_line = lines[0].decode('utf-8', errors='replace')
            method, url, protocol = request_line.split()
            headers = {}
            i = 1
            while i < len(lines):
                line = lines[i].decode('utf-8', errors='replace')
                i += 1
                if line == "":
                    break
                if ':' in line:
                    key, value = line.split(":", 1)
                    headers[key.strip()] = value.strip()
            body = b'\r\n'.join(lines[i:]) if i < len(lines) else None

            logger.debug("Forwarding HTTP/1.x request to %s with verb %s", url, method)
            resp = requests.request(method, url, headers=headers, data=body, verify=True)

            # Build the response headers.
            response_data = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
            for key, value in resp.headers.items():
                response_data += f"{key}: {value}\r\n"
            response_data += "\r\n"
            self.connection.sendall(response_data.encode('utf-8'))
            # For HEAD requests, do not send the body.
            if method.upper() != "HEAD":
                self.connection.sendall(resp.content)
        except Exception as e:
            logger.exception("Error handling HTTP/1.x request: %s", e)
            error_response = "HTTP/1.1 500 Internal Server Error\r\n\r\n"
            self.connection.sendall(error_response.encode('utf-8'))

    def handle_http2(self, initial_data):
        """
        Handle a basic HTTP/2 (h2c) connection. This simplified implementation uses
        hyper-h2 to process HTTP/2 frames, extract the request, forward it via curl_cffi.requests,
        and then send back an HTTP/2 response. All HTTP verbs are supported.
        For HEAD requests, no response body is returned.
        """
        from h2.connection import H2Connection
        from h2.events import RequestReceived, DataReceived, StreamEnded

        conn = H2Connection(client_side=False)
        conn.initiate_connection()
        self.connection.sendall(conn.data_to_send())

        # Feed the initial data (including the preface) into the H2 connection.
        events = conn.receive_data(initial_data)
        stream_data = {}      # Maps stream_id to accumulated body bytes.
        request_headers = {}  # Maps stream_id to received headers.
        ended_streams = set()

        # Process any events already received.
        for event in events:
            if isinstance(event, RequestReceived):
                stream_id = event.stream_id
                request_headers[stream_id] = event.headers
                stream_data[stream_id] = b""
            elif isinstance(event, DataReceived):
                stream_id = event.stream_id
                stream_data.setdefault(stream_id, b"")
                stream_data[stream_id] += event.data
                conn.acknowledge_received_data(event.flow_controlled_length, stream_id)
            elif isinstance(event, StreamEnded):
                ended_streams.add(event.stream_id)
        self.connection.sendall(conn.data_to_send())

        # Read further data until at least one stream ends.
        while not ended_streams:
            data = self.connection.recv(8192)
            if not data:
                break
            events = conn.receive_data(data)
            for event in events:
                if isinstance(event, RequestReceived):
                    stream_id = event.stream_id
                    request_headers[stream_id] = event.headers
                    stream_data[stream_id] = b""
                elif isinstance(event, DataReceived):
                    stream_id = event.stream_id
                    stream_data.setdefault(stream_id, b"")
                    stream_data[stream_id] += event.data
                    conn.acknowledge_received_data(event.flow_controlled_length, stream_id)
                elif isinstance(event, StreamEnded):
                    ended_streams.add(event.stream_id)
            self.connection.sendall(conn.data_to_send())

        # Process the first completed stream.
        for stream_id, headers in request_headers.items():
            if stream_id in ended_streams:
                # Separate pseudo-headers from standard headers.
                headers_dict = {}
                pseudo_headers = {}
                for name, value in headers:
                    if name.startswith(":"):
                        pseudo_headers[name] = value
                    else:
                        headers_dict[name] = value

                method = pseudo_headers.get(":method", "GET")
                scheme = pseudo_headers.get(":scheme", "http")
                authority = pseudo_headers.get(":authority", "")
                path = pseudo_headers.get(":path", "/")
                url = f"{scheme}://{authority}{path}"
                body = stream_data.get(stream_id, None)

                logger.debug("Forwarding HTTP/2 request to %s with verb %s", url, method)
                try:
                    resp = requests.request(method, url, headers=headers_dict, data=body, verify=True)
                except Exception as e:
                    logger.exception("Error in HTTP/2 request: %s", e)
                    error_headers = [(':status', '500')]
                    conn.send_headers(stream_id, error_headers, end_stream=True)
                    self.connection.sendall(conn.data_to_send())
                    continue

                # Build response headers. The pseudo-header :status is required.
                response_headers = [(':status', str(resp.status_code))]
                for key, value in resp.headers.items():
                    response_headers.append((key.lower(), value))
                if method.upper() == "HEAD":
                    conn.send_headers(stream_id, response_headers, end_stream=True)
                else:
                    conn.send_headers(stream_id, response_headers)
                    conn.send_data(stream_id, resp.content, end_stream=True)
                self.connection.sendall(conn.data_to_send())
                # Process only one stream for simplicity.
                break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Transparent HTTP/HTTPS proxy with HTTP/2 support handling all HTTP verbs using curl_cffi, hyper-h2, and argparse"
    )
    parser.add_argument("--interface", default="0.0.0.0", help="Interface to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--impersonate", type=str, default="", help="Use impersonation for outbound requests (e.g. chrome131)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Apply impersonation if requested.
    if args.impersonate:
        impersonate(args.impersonate)

    class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True

    server_address = (args.interface, args.port)
    with ThreadedTCPServer(server_address, ProxyHandler) as server:
        logger.info("Proxy server running on %s:%s", args.interface, args.port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Proxy server shutting down.")
            server.shutdown()
