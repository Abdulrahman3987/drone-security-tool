import socket
import threading
import time


FAKE_UDP_PORTS = [8889, 8890, 8891, 11111, 14550]

def open_udp_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[Fake Drone] UDP port {port} is OPEN (simulated)")
    while True:
        data, addr = sock.recvfrom(1024)
        print(f"[Fake Drone] Received on {port}: {data} from {addr}")
        # Send a simple response so your tool sees an active service
        sock.sendto(b"OK", addr)

def start_fake_drone():
    for port in FAKE_UDP_PORTS:
        threading.Thread(target=open_udp_port, args=(port,), daemon=True).start()

    print("\nFake drone ONLINE at IP: 127.0.0.1")
    print("Open UDP ports: 8889, 8890, 8891, 11111, 14550\n")

if __name__ == "__main__":
    start_fake_drone()
    # Keep the main thread alive
    while True:
        time.sleep(1)
