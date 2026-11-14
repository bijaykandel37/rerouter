import sqlite3

from rerouter.db import Database


def test_migration_adds_new_flow_columns(tmp_path):
    path = tmp_path / "old.db"
    # simulate a pre-upgrade database: flows table without the L7 columns
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE flows (id INTEGER PRIMARY KEY, ts_start REAL, ts_end REAL, src_ip TEXT, "
        "dst_ip TEXT, src_port INTEGER, dst_port INTEGER, proto INTEGER, bytes INTEGER, "
        "packets INTEGER, tcp_flags INTEGER, direction TEXT, local_ip TEXT, remote_ip TEXT, "
        "local_port INTEGER, remote_port INTEGER, app TEXT NOT NULL, source TEXT NOT NULL, "
        "exporter TEXT)")
    conn.execute("INSERT INTO flows(ts_end, app, source, local_ip) VALUES (1, 'https', "
                 "'netflow', '192.168.1.5')")
    conn.commit()
    conn.close()

    db = Database(path)
    cols = {r["name"] for r in db._wconn.execute("PRAGMA table_info(flows)")}
    assert {"host", "fingerprint", "tls_version"} <= cols
    # existing row still readable, new columns NULL
    row = db.query_one("SELECT host, fingerprint FROM flows")
    assert row["host"] is None and row["fingerprint"] is None
    # http_transactions table created on open
    assert db.query("SELECT * FROM http_transactions") == []
    db.close()
