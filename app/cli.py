import argparse,json
from pathlib import Path
from .analyzer import analyze

def main():
    p=argparse.ArgumentParser(description="Analyze an .eml file locally.")
    p.add_argument("file")
    args=p.parse_args()
    print(json.dumps(analyze(Path(args.file).read_bytes()),indent=2,default=str))
if __name__=="__main__": main()
