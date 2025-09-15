from flask import Flask, request, jsonify
from services.capture import PacketCapture
from services.analyzer import PacketAnalyzer

app = Flask(__name__)

# Initialize services
capture_service = PacketCapture()
analyzer_service = PacketAnalyzer()


@app.route("/")
def home():
    return jsonify({"status": "Packet Analyzer running on EC2"})


@app.route("/capture/start", methods=["POST"])
def start_capture():
    capture_service.start()
    return jsonify({"message": "Packet capture started!"})


@app.route("/capture/stop", methods=["POST"])
def stop_capture():
    capture_service.stop()
    return jsonify({"message": "Packet capture stopped!"})


@app.route("/packets", methods=["GET"])
def get_packets():
    protocol = request.args.get("protocol")
    src_ip = request.args.get("src_ip")
    dst_ip = request.args.get("dst_ip")

    packets = capture_service.get_packets()
    analyzed = analyzer_service.analyze(packets)

    # Apply filters
    if protocol:
        analyzed = [pkt for pkt in analyzed if pkt.get("protocol") == protocol]
    if src_ip:
        analyzed = [pkt for pkt in analyzed if pkt.get("src_ip") == src_ip]
    if dst_ip:
        analyzed = [pkt for pkt in analyzed if pkt.get("dst_ip") == dst_ip]

    return jsonify(analyzed)


if __name__ == "__main__":
    # Important: bind to 0.0.0.0 and use port 8000 for EC2 access
    app.run(host="0.0.0.0", port=8000, debug=True)
