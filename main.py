from flask import Flask, request, jsonify, Response, send_file
from scapy.all import sniff, wrpcap, rdpcap
import threading
import time

app = Flask(__name__)

packets_buffer = []
capturing = False
capture_thread = None
pcap_file = "captured_packets.pcap"


def capture_packets():
    """Background packet capture thread"""
    global packets_buffer, capturing
    packets_buffer = []
    sniff(prn=lambda x: packets_buffer.append(x), store=True, stop_filter=lambda x: not capturing)


@app.post("/capture/start")
def start_capture():
    global capturing, capture_thread
    if capturing:
        return {"status": "already capturing"}
    capturing = True
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    return {"status": "capture started"}


@app.post("/capture/stop")
def stop_capture():
    global capturing
    capturing = False
    if packets_buffer:
        wrpcap(pcap_file, packets_buffer)
    return {"status": "capture stopped", "saved_file": pcap_file}


@app.get("/packets")
def get_packets():
    proto = request.args.get("protocol")
    data = []
    for pkt in packets_buffer:
        summary = pkt.summary()
        if not proto or proto.lower() in summary.lower():
            data.append(summary)
    return jsonify(data)


@app.post("/upload/pcap")
def upload_pcap():
    file = request.files["file"]
    packets = rdpcap(file)
    global packets_buffer
    packets_buffer = packets
    return {"status": "pcap uploaded", "packet_count": len(packets_buffer)}


@app.get("/download/pcap")
def download_pcap():
    if not packets_buffer:
        return {"error": "No packets available"}, 400
    wrpcap(pcap_file, packets_buffer)
    return send_file(pcap_file, as_attachment=True)


@app.get("/stream/packets")
def stream_packets():
    def generate():
        last_len = 0
        while capturing:
            if len(packets_buffer) > last_len:
                for pkt in packets_buffer[last_len:]:
                    yield f"data: {pkt.summary()}\n\n"
                last_len = len(packets_buffer)
            time.sleep(1)

    return Response(generate(), mimetype="text/event-stream")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
