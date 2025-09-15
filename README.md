Here’s a step-by-step guide to run your packet capture microservice from the zip:

1. Unzip the file

If you haven’t already, unzip the downloaded packet_microservice.zip:

unzip packet_microservice.zip
cd packet_microservice


You should see the files:

main.py
packet_capture.py
packet_analyzer.py
classifier.py
requirements.txt
database.db (created automatically)

2. Create a Python environment (recommended)

Use a virtual environment to avoid dependency conflicts:

python -m venv venv


Activate it:

Linux/macOS:

source venv/bin/activate


Windows:

venv\Scripts\activate

3. Install dependencies

Install all required Python packages:

pip install -r requirements.txt


This will install:

fastAPI (for the API)

uvicorn (ASGI server)

scapy (packet capture)

scikit-learn (ML classifier)

pandas (data handling)

SQLAlchemy (database)

4. Run the microservice

Start the FastAPI service using uvicorn:

uvicorn main:app --reload


--reload makes it automatically reload on code changes.

By default, the service runs on http://127.0.0.1:8000.

5. Access API endpoints

Capture packets (e.g., 5 packets):

POST http://127.0.0.1:8000/capture?count=5


Get captured packets:

GET http://127.0.0.1:8000/packets


Supports filtering, e.g.:

GET http://127.0.0.1:8000/packets?protocol=TCP&src_ip=192.168.1.10


Detect anomalies:

GET http://127.0.0.1:8000/anomalies

6. Optional: Explore interactive docs

FastAPI automatically provides Swagger UI:

Go to: http://127.0.0.1:8000/docs

You can test all endpoints interactively here.

⚠️ Notes

Capturing live packets may require root/admin privileges depending on your OS:

Linux/macOS: sudo uvicorn main:app --reload

Windows: Run the terminal as Administrator.

You can also filter packets using BPF filters in the /capture endpoint:

POST /capture?count=10&filter=tcp port 80
