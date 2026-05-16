# Algorithms

## Full deobfuscation pipeline

```mermaid
flowchart TD
    A[Protected PE] --> B[INT3 VEH Resolution]
    B --> C[Per-function Deobfuscation]
    C --> D[Indirect JMP Resolution]
    D --> E[Inline INT3 NOP]
    E --> F[Deobfuscated PE]

    subgraph B[INT3 VEH Resolution]
        B1[Scan: CC 90 CC...48 B8 pattern] --> B2[Follow call -> INT3 -> NOP -> JMP]
        B2 --> B3[Patch: replace block with JMP to real target]
    end

    subgraph C[Per-function Deobfuscation]
        C1[Build CFG] --> C2[Constant propagation]
        C2 --> C3[MBA pattern simplification]
        C3 --> C4[Opaque predicate resolution]
        C4 --> C5[Patch simplified instructions]
    end
```

## Indirect JMP resolution levels

```mermaid
flowchart LR
    A[Unresolved JMP] --> L1
    L1[L1: Pattern match] -->|fail| L3
    L3[L3: Static dispatch parse] -->|fail| L3b
    L3b[L3b: LEA+LEA+JMP] -->|fail| L5
    L5[L5: Symbolic modular inverse] -->|fail| L4
    L4[L4: Unicorn emulation]

    L1 -->|resolved| P[Patch]
    L3 -->|resolved| P
    L3b -->|resolved| P
    L5 -->|resolved| P
    L4 -->|resolved| P
```

## MBA constant propagation

```mermaid
flowchart TD
    A[Function entry with dispatch key] --> B[Initialize register state]
    B --> C[Walk instructions in CFG order]
    C --> D{Operands constant?}
    D -->|Yes| E[Compute result]
    D -->|No| F[Mark as TOP]
    E --> G{Is branch condition?}
    G -->|Yes, always true| H[Eliminate false path]
    G -->|Yes, always false| I[Eliminate true path]
    G -->|No| J[Store result, continue]
    H --> C
    I --> C
    J --> C
    F --> C
```

## Inline INT3 NOP detection

```mermaid
flowchart TD
    A[Scan executable section] --> B{Byte == 0xCC?}
    B -->|No| A
    B -->|Yes| C{Previous byte is boundary?}
    C -->|Yes: C3/00/90| A
    C -->|No| D[Count CC run length]
    D --> E{3-15 bytes?}
    E -->|No| A
    E -->|Yes| F{Valid instruction byte after?}
    F -->|No| A
    F -->|Yes| G[Start chain detection]
    G --> H{Another CC run after short code gap?}
    H -->|Yes| I[Extend chain]
    I --> H
    H -->|No, 2+ runs found| J[NOP all CC runs in chain]
    H -->|No, only 1 run| K[Single-run validation]
    K --> L{Both sides valid code?}
    L -->|Yes| J
    L -->|No| A
```
