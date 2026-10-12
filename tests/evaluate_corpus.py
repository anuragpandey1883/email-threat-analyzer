"""Evaluate saved analyzer JSON reports against a simple labeled CSV.

CSV columns: file, label where label is malicious or benign.
Run against your own reviewed corpus; this script does not download samples.
Each file should be a JSON report produced by the analyzer, named as in the CSV.
"""
import csv, json, sys
from pathlib import Path

def main(csv_path, report_dir):
    rows=[]
    with open(csv_path, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            label=row['label'].strip().lower()
            if label not in {'malicious','benign'}: raise ValueError('label must be malicious or benign')
            report=json.loads((Path(report_dir)/row['file']).read_text(encoding='utf-8'))
            predicted=str(report.get('risk_level','LOW')).upper() in {'HIGH','CRITICAL'}
            actual=label == 'malicious'
            rows.append((actual,predicted))
    tp=sum(a and p for a,p in rows); tn=sum((not a) and (not p) for a,p in rows)
    fp=sum((not a) and p for a,p in rows); fn=sum(a and (not p) for a,p in rows)
    precision=tp/(tp+fp) if tp+fp else 0.0
    recall=tp/(tp+fn) if tp+fn else 0.0
    fpr=fp/(fp+tn) if fp+tn else 0.0
    print(f'n={len(rows)} TP={tp} TN={tn} FP={fp} FN={fn}')
    print(f'precision={precision:.3f} recall={recall:.3f} false_positive_rate={fpr:.3f}')
    print('Metrics are meaningful only when labels are reviewed and the test set was not used to tune thresholds.')

if __name__ == '__main__':
    if len(sys.argv)!=3: raise SystemExit('Usage: python tests/evaluate_corpus.py labels.csv report_directory')
    main(sys.argv[1],sys.argv[2])
