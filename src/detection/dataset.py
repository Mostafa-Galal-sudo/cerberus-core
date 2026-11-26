from pathlib import Path

import pandas as pd

WEB_FOLDERS = {
    "Backdoor_Malware",
    "BrowserHijacking",
    "CommandInjection",
    "SqlInjection",
    "Uploading_Attack",
    "XSS",
}


def category_of(folder):
    if folder == "Benign_Final":
        return "Benign"
    if folder.startswith("DDoS-"):
        return "DDoS"
    if folder.startswith("DoS-"):
        return "DoS"
    if folder.startswith("Mirai-"):
        return "Mirai"
    if folder.startswith("Recon-") or folder == "VulnerabilityScan":
        return "Recon"
    if folder in ("DNS_Spoofing", "MITM-ArpSpoofing"):
        return "Spoofing"
    if folder in WEB_FOLDERS:
        return "Web"
    if folder == "DictionaryBruteForce":
        return "BruteForce"
    raise ValueError(f"unmapped dataset folder: {folder}")


def class_files(root):
    root = Path(root)
    out = []
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        category = category_of(folder.name)
        for f in sorted(folder.glob("*.csv")):
            out.append({
                "path": f,
                "folder": folder.name,
                "category": category,
                "is_attack": category != "Benign",
            })
    return out


def load_sample(root, rows_per_file=2000, categories=None):
    parts = []
    for entry in class_files(root):
        if categories and entry["category"] not in categories:
            continue
        df = pd.read_csv(entry["path"], nrows=rows_per_file)
        df = df.drop(columns=[c for c in df.columns if c.lower() == "label"], errors="ignore")
        df["category"] = entry["category"]
        df["is_attack"] = int(entry["is_attack"])
        df["source_file"] = entry["path"].name
        df["source_folder"] = entry["folder"]
        parts.append(df)
    data = pd.concat(parts, ignore_index=True)
    return drop_constant_features(data)


def drop_constant_features(df, protected=("category", "is_attack", "source_file", "source_folder")):
    numeric = [c for c in df.columns if c not in protected and pd.api.types.is_numeric_dtype(df[c])]
    constant = [c for c in numeric if df[c].nunique(dropna=False) <= 1]
    return df.drop(columns=constant)


def split_by_file(df, test_fraction=0.3, seed=0, stratify_on="source_folder"):
    test_files = set()
    for _, group in df.groupby(stratify_on):
        files = sorted(group["source_file"].unique())
        shuffled = pd.Series(files).sample(frac=1.0, random_state=seed).tolist()
        n_test = max(1, int(round(len(shuffled) * test_fraction)))
        if n_test >= len(shuffled) and len(shuffled) > 1:
            n_test = len(shuffled) - 1
        test_files.update(shuffled[:n_test])
    mask = df["source_file"].isin(test_files)
    return df.loc[~mask].reset_index(drop=True), df.loc[mask].reset_index(drop=True)
