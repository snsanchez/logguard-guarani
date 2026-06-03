#!/usr/bin/env python3

import argparse
import csv
import json
from pathlib import Path

from features import FEATURE_NAMES, extraer_features


def main():
    parser = argparse.ArgumentParser(
        description="Genera dataset CSV desde eventos JSONL exportados por LogGuard"
    )

    parser.add_argument("jsonl", help="Archivo JSONL exportado por LogGuard")

    parser.add_argument(
        "-o",
        "--output",
        default="datasets/dataset.csv",
        help="Archivo CSV de salida",
    )

    args = parser.parse_args()

    Path("datasets").mkdir(exist_ok=True)

    filas = []

    with open(args.jsonl, encoding="utf-8") as f:
        for linea in f:
            evento = json.loads(linea)

            feats = extraer_features(evento)

            row = {name: float(value) for name, value in zip(FEATURE_NAMES, feats)}
            row["label"] = evento["etiqueta"]

            filas.append(row)

    if not filas:
        print("No se encontraron eventos")
        return

    columnas = filas[0].keys()

    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columnas)

        writer.writeheader()
        writer.writerows(filas)

    print(f"Dataset generado: {args.output}")
    print(f"Registros: {len(filas)}")


if __name__ == "__main__":
    main()
