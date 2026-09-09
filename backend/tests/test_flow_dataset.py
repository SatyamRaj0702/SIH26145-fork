import csv

from sih_detector.flow_dataset import import_labeled_flow_csv


def test_import_cic_flow_csv_into_labeled_windows(tmp_path) -> None:
    source = tmp_path / "flows.csv"
    output = tmp_path / "windows.jsonl"
    fields = [
        "Timestamp", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
        "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Label",
    ]
    with source.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index in range(4):
            writer.writerow({
                "Timestamp": f"2026-09-09T10:00:0{index}Z",
                "Src IP": "10.0.0.5", "Src Port": "42000", "Dst IP": "10.0.0.10",
                "Dst Port": "80", "Protocol": "6", "Tot Fwd Pkts": "5", "Tot Bwd Pkts": "1",
                "TotLen Fwd Pkts": "400", "TotLen Bwd Pkts": "80", "Label": "DoS Hulk",
            })
        writer.writerow({**{field: "" for field in fields}, "Label": "Unknown Attack"})

    result = import_labeled_flow_csv(source, output, window_size=4)
    assert result["rows_by_label"] == {"ddos": 4}
    assert result["windows"] == 1
    assert result["skipped_unknown_labels"] == 1
    assert '"label": "ddos"' in output.read_text()
