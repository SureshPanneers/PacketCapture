from scapy.all import sniff
from packet_analyzer import parse_packet
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData

engine = create_engine("sqlite:///database.db")
metadata = MetaData()

packets_table = Table(
    'packets', metadata,
    Column('id', Integer, primary_key=True),
    Column('protocol', String),
    Column('src_ip', String),
    Column('dst_ip', String),
    Column('src_port', String),
    Column('dst_port', String),
    Column('payload', String)
)

metadata.create_all(engine)

def store_packet(packet_info):
    with engine.connect() as conn:
        conn.execute(packets_table.insert().values(**packet_info))

def capture_packets(filter=None, count=0):
    def process_packet(pkt):
        info = parse_packet(pkt)
        if info:
            store_packet(info)
    
    sniff(prn=process_packet, filter=filter, count=count)
