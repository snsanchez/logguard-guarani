# Architecture

Current architecture:
src/
├── logguard_guarani.py
├── core/
└── ml/

core:
- parsing
- heuristics
- scoring
- exporting
- attack classification

ml:
- feature extraction
- dataset generation
- model training
- inference

Outputs:

logs
  -> parser
  -> heuristics
  -> score
  -> attack type
  -> JSONL
  -> ML classification

Future:

logs
  -> parser
  -> heuristics
  -> ML
  -> AI agent
  -> analyst report
