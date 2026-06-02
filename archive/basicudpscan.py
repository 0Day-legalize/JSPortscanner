import socket
import sys

TIMEOUT = 2.0


def scan_udp(host: str, port: int) -> str | None:
    """
    Sends an empty UDP packet to host:port and waits for a response.

    Returns:
        - Response string if the service replied
        - "OPEN|FILTERED" if no reply within the timeout
        - None if the port is definitely closed (ICMP port unreachable)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    try:
        sock.sendto(b"", (host, port))

        try:
            data, _ = sock.recvfrom(1024)
            return data.decode("utf-8", errors="replace")

        except socket.timeout:
            # no reply within timeout — port is open or filtered, can't tell which
            return "OPEN|FILTERED"

    except ConnectionRefusedError:
        # OS received ICMP port-unreachable — port is definitely closed
        return None

    except OSError as e:
        return f"ERROR: {e}"

    finally:
        sock.close()


def scan(host: str, start: int, end: int) -> None:
    for port in range(start, end + 1):
        print(f"\rscanning UDP {port}...", end="", flush=True)

        result = scan_udp(host, port)

        if result is None:
            continue  # closed

        print(f"\r\033[K", end="")
        status = "OPEN|FILTERED" if result == "OPEN|FILTERED" else "OPEN"
        print(f"UDP {host}:{port} {status}")

        if isinstance(result, str) and result.strip() and result != "OPEN|FILTERED":
            print(f"  {result.strip()}")

    print("\r\033[Kdone.")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: python basicudpscan.py <host> <start-port> <end-port>")
        sys.exit(1)

    host  = sys.argv[1]
    start = int(sys.argv[2])
    end   = int(sys.argv[3])

    scan(host, start, end)
