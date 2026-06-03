import json


def exportar_jsonl(resultados, path):
    with open(path, "w", encoding="utf-8") as f:
        for evento in resultados:
            f.write(json.dumps(evento, ensure_ascii=False) + "\n")
