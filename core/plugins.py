import importlib.util, pathlib


def load_plugins(folder="plugins"):
    p = pathlib.Path(folder)
    if not p.exists():
        return []
    mods = []
    for f in p.glob("*.py"):
        if f.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(f.stem, f)
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            if hasattr(mod, "scan"):
                mods.append(mod)
        except Exception as e:
            print(f"[!] Plugin {f.name}: {e}")
    return mods
