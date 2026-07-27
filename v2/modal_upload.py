"""Upload dataset to Modal Volume — no GPU needed, no payment required."""
from pathlib import Path
import modal
import shutil

app = modal.App("rakshakai-upload")
volume = modal.Volume.from_name("rakshakai-data", create_if_missing=True)


@app.function(volumes={"/data": volume}, timeout=600)
def upload():
    src = Path("v2/inputs/datasets/axolotl")
    dst = Path("/data/axolotl")
    dst.mkdir(parents=True, exist_ok=True)
    for f in ["train.jsonl", "val.jsonl", "test.jsonl"]:
        sp = src / f
        if sp.exists():
            shutil.copy2(str(sp), str(dst / f))
            print(f"  Uploaded {f} ({sp.stat().st_size / 1e6:.1f} MB)")
    volume.commit()
    print("Done.")


@app.local_entrypoint()
def main():
    upload.remote()
