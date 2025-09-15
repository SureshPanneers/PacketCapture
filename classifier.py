import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy import create_engine, Table, MetaData, select

engine = create_engine("sqlite:///database.db")
metadata = MetaData()
packets_table = Table('packets', metadata, autoload_with=engine)

def train_anomaly_detector():
    with engine.connect() as conn:
        result = conn.execute(select(packets_table))
        df = pd.DataFrame(result.fetchall(), columns=result.keys())
    
    if df.empty:
        return None
    
    df['payload_len'] = df['payload'].apply(lambda x: len(x))
    df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0)
    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0)
    
    X = df[['src_port','dst_port','payload_len']]
    
    clf = IsolationForest(contamination=0.1)
    clf.fit(X)
    df['anomaly'] = clf.predict(X)
    
    return df
