from fastapi import FastAPI, Query
from typing import Optional
from packet_capture import capture_packets
from classifier import train_anomaly_detector
from sqlalchemy import create_engine, Table, MetaData, select

app = FastAPI(title="Packet Capture Microservice")

engine = create_engine("sqlite:///database.db")
metadata = MetaData()
packets_table = Table('packets', metadata, autoload_with=engine)


@app.get("/")
def home():
    return {"status": "Packet Analyzer running on EC2"}


@app.get("/packets")
def get_packets(protocol: Optional[str] = None, src_ip: Optional[str] = None, dst_ip: Optional[str] = None):
    query = select(packets_table)
    
    if protocol:
        query = query.where(packets_table.c.protocol == protocol)
    if src_ip:
        query = query.where(packets_table.c.src_ip == src_ip)
    if dst_ip:
        query = query.where(packets_table.c.dst_ip == dst_ip)
    
    with engine.connect() as conn:
        result = conn.execute(query).fetchall()
    
    return [dict(r) for r in result]


@app.get("/anomalies")
def get_anomalies():
    df = train_anomaly_detector()
    if df is None:
        return {"message": "No packets captured yet."}
    anomalies = df[df['anomaly'] == -1]
    return anomalies.to_dict(orient='records')


@app.post("/capture")
def start_capture(count: int = 10, filter: Optional[str] = None):
    capture_packets(count=count, filter=filter)
    return {"message": f"Captured {count} packets"}
