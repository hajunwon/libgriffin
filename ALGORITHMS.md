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

## Layered xref reachability

```mermaid
flowchart TD
    A[Build XrefGraphCtx] --> B[funcRdata: text fn -> .rdata refs]
    B --> C[callGraph: text -> text via E8/E9]
    C --> D[Vtable expansion:<br/>add slot fns as callees of any fn<br/>that LEAs the vtable]
    D --> E[Transitive propagation<br/>up to maxDepth]
    E --> F[Layer 1: .grfn1 root]
    E --> G[Layer 2: PE export root]
    E --> H[Layer 3: function pointer root]

    F --> J[.grfn1 caller -> .text target -> reachable rdata]
    G --> K[export entry as root -> reachable rdata]
    H --> L[.data/.rdata fn ptr -> reachable rdata]

    J --> M[XrefResult.xrefs with layer tag]
    K --> M
    L --> M

    M --> L4Block

    subgraph L4Block[Layer 4: FBR roots, append-only]
        L4A[pefix::discoverFunctionBoundaries] --> L4B[Drop FBR funcs whose start RVA<br/>maps to a function already used as<br/>an L1/L2/L3 root via ctx.findFunc]
        L4B --> L4C{Section?}
        L4C -->|.text| L4D[Use ctx.reachable for the FBR start RVA;<br/>register .rdata targets not in knownTargets]
        L4C -->|.grfn1| L4E[No ctx.reachable entry: scan ctx.allRefs<br/>directly inside FBR func range,<br/>register new .rdata targets]
        L4D --> L4F[Append as XrefLayerFbr;<br/>existing entries untouched]
        L4E --> L4F
    end

    L4Block --> N[expandSubstringTargets:<br/>'pkg.Msg.field' container reachable<br/>=> every '.'-delimited suffix reachable]
    N --> O[Final XrefResult]
```

L4 contributes *net-new* targets that the L1/L2/L3 propagation misses — typically
small `.text` functions reached only via FBR-discovered roots that none of pdata,
exports, fnptr tables, or `.grfn1` callers point at. The `.grfn1` branch exists
for completeness: when an FBR boundary lands inside `.grfn1`, the regular
`ctx.reachable` map (built from `.text`-only func starts) has no entry for it,
so its inner LEAs are picked up directly. In practice L1 already covers the
entire `.grfn1` LEA surface via its own BFS, so this branch usually adds 0
unique targets but is kept so the L4 set is symmetric across sections.

`strictOnly=true` restricts L4 roots to FBR boundaries backed by strong sources
(pdata / export / RTTI / EH) or multi-source agreement. In current builds this
produces an identical target count to the default — every weak FBR root's
reach is already covered by a strong-rooted FBR sibling — so the flag exists
mainly as a precision lever for future experiments.

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
