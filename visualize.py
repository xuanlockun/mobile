import sqlite3
from graphviz import Digraph

conn = sqlite3.connect('restaurant.db')
cursor = conn.cursor()
# code minh họa diagram
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
tables = cursor.fetchall()

dot = Digraph(comment='Database Schema')

for table_name, in tables:
    cursor.execute(f"PRAGMA table_info({table_name});")
    columns = cursor.fetchall()
    column_lines = " | ".join([
        f"<{col[1]}> {col[1]} : {col[2]}{' (PK)' if col[5] == 1 else ''}"
        for col in columns
    ])
    label = f"{{{table_name} | {column_lines}}}"
    dot.node(table_name, label=label, shape="record")

relations = [
    ("kho", "cong_thuc", "1:1"),
    ("cong_thuc", "mon_an", "N:1"),
    ("chi_tiet_hoa_don", "hoa_don", "N:1"),
    ("hang_doi", "mon_an", "1:1"),
    ("hang_doi", "ban", "N:1"),
    ("hoa_don", "ban", "N:1"),
    ("thong_ke_mon_an", "mon_an", "N:1"),
    ("thong_ke_ngay", "hoa_don", "N:1")
]


for src, dst, relation in relations:
    dot.edge(src, dst, label=relation, dir="none")

conn.close()

dot.render('schema_diagram', format='png', cleanup=True)
