# testbench_crypto_bits.py
# -*- coding: utf-8 -*-
"""
Testbench de qualidade para GEN/ENC/DEC quando GEN espera seed como lista de bits (0/1).

Uso rÃ¡pido:
  python testbench_crypto_bits.py --impl ./minha_impl.py --seed-bits 0101
  python testbench_crypto_bits.py --impl pacote.alg --seed-len 8 --runs 6000
"""

from __future__ import annotations
import argparse
import importlib
import importlib.util
import os
import random
import time
from collections import Counter
from dataclasses import dataclass
from typing import Callable, List


# ---------------------------------------------------------------------
# Carregamento dinÃ¢mico de GEN, ENC, DEC
# ---------------------------------------------------------------------

def load_module(path_or_modname: str):
    if os.path.exists(path_or_modname) or path_or_modname.endswith(".py"):
        path = path_or_modname
        mod_name = os.path.splitext(os.path.basename(path))[0]
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"NÃ£o foi possÃ­vel carregar mÃ³dulo de {path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        return mod
    return importlib.import_module(path_or_modname)


def get_funcs(mod):
    try:
        return mod.GEN, mod.ENC, mod.DEC
    except AttributeError:
        raise AttributeError("O mÃ³dulo deve exportar GEN, ENC e DEC.")


# ---------------------------------------------------------------------
# Utilidades de bits
# ---------------------------------------------------------------------

Bits = List[int]  # lista de 0/1


def rand_bits(n: int, rng: random.Random) -> Bits:
    return [rng.getrandbits(1) for _ in range(n)]


def flip_bit(bits: Bits, idx: int) -> Bits:
    out = bits.copy()
    out[idx] ^= 1
    return out


def hamming(a: Bits, b: Bits) -> int:
    return sum(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------
# Resultados
# ---------------------------------------------------------------------

@dataclass
class TimeRes:
    enc_us: float
    dec_us: float
    runs: int


@dataclass
class StatRes:
    mean: float
    min_: int
    max_: int
    trials: int


@dataclass
class EquivRes:
    keys: int
    collisions: int
    unique_ciphertexts: int


# ---------------------------------------------------------------------
# Testes
# ---------------------------------------------------------------------

def time_test(GEN, ENC, DEC, seed: Bits, runs=4000) -> TimeRes:
    K = GEN(seed)
    n = len(K)
    rng = random.Random(123)
    Ms = [rand_bits(n, rng) for _ in range(runs)]
    Cs = []

    t0 = time.perf_counter()
    for M in Ms:
        Cs.append(ENC(K, M))
    t1 = time.perf_counter()

    t2 = time.perf_counter()
    for C in Cs:
        DEC(K, C)
    t3 = time.perf_counter()

    return TimeRes(
        enc_us=(t1 - t0) * 1e6 / runs,
        dec_us=(t3 - t2) * 1e6 / runs,
        runs=runs,
    )


def equiv_keys_test(GEN, ENC, template_seed: Bits, n_keys=300) -> EquivRes:
    n = len(GEN(template_seed))               # tamanho de K â‡’ tamanho de M
    rng = random.Random(999)
    M = rand_bits(n, rng)

    ciphertexts = []
    for _ in range(n_keys):
        seed_i = rand_bits(len(template_seed), rng)
        K_i = GEN(seed_i)
        ciphertexts.append(tuple(ENC(K_i, M)))

    counts = Counter(ciphertexts)
    collisions = sum(c - 1 for c in counts.values() if c > 1)
    return EquivRes(
        keys=n_keys,
        collisions=collisions,
        unique_ciphertexts=len(counts),
    )


def diffusion_test(GEN, ENC, seed: Bits, trials=300) -> StatRes:
    K = GEN(seed)
    n = len(K)
    rng = random.Random(321)
    changes = []

    for _ in range(trials):
        M0 = rand_bits(n, rng)
        C0 = ENC(K, M0)
        idx = rng.randrange(n)
        C1 = ENC(K, flip_bit(M0, idx))
        changes.append(hamming(C0, C1))

    return StatRes(sum(changes)/trials, min(changes), max(changes), trials)


def confusion_test(GEN, ENC, seed: Bits, trials=300) -> StatRes:
    K0 = GEN(seed)
    n = len(K0)
    rng = random.Random(777)
    M = rand_bits(n, rng)
    C0 = ENC(K0, M)

    changes = []
    for _ in range(trials):
        idx = rng.randrange(len(seed))
        seed2 = flip_bit(seed, idx)
        C1 = ENC(GEN(seed2), M)
        changes.append(hamming(C0, C1))

    return StatRes(sum(changes)/trials, min(changes), max(changes), trials)


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Testbench para GEN/ENC/DEC com seed = lista de bits")
    ap.add_argument("--impl", required=True,
                    help="Arquivo .py ou nome de mÃ³dulo contendo GEN, ENC, DEC")
    seed_grp = ap.add_mutually_exclusive_group()
    seed_grp.add_argument("--seed-bits",
                          help="Seed como string de 0/1, ex.: 010011")
    seed_grp.add_argument("--seed-len", type=int, default=10,
                          help="Gera seed aleatÃ³ria de comprimento N bits")
    ap.add_argument("--runs", type=int, default=4000, help="Runs para tempo (default 4000)")
    ap.add_argument("--trials", type=int, default=3000, help="Trials difusÃ£o/confusÃ£o (default 300)")
    ap.add_argument("--equiv-keys", type=int, default=3000, help="Seeds para teste de chaves equivalentes")
    return ap.parse_args()


def main():
    args = parse_args()
    # carrega implementaÃ§Ã£o
    mod = load_module(args.impl)
    GEN, ENC, DEC = get_funcs(mod)

    # prepara seed
    if args.seed_bits:
        if set(args.seed_bits) - {"0", "1"}:
            raise SystemExit("Erro: --seed-bits deve conter apenas 0/1")
        seed: Bits = [int(b) for b in args.seed_bits]
    else:  # --seed-len
        rng = random.Random(42)
        seed = rand_bits(args.seed_len, rng)

    # relatÃ³rio
    k_len = len(GEN(seed))
    print("=== ParÃ¢metros ===")
    print(f"Seed..............: {seed}")
    print(f"|K| (bits)........: {k_len} (esperado 4Ã—len(seed)?)\n")

    t = time_test(GEN, ENC, DEC, seed, runs=args.runs)
    print("1) Tempo (Âµs por chamada)  runs=", t.runs)
    print(f"   ENC: {t.enc_us:.3f}   DEC: {t.dec_us:.3f}\n")

    eq = equiv_keys_test(GEN, ENC, seed, n_keys=args.equiv_keys)
    print("2) Chaves equivalentes (M fixa)")
    print(f"   Keys testadas.........: {eq.keys}")
    print(f"   Ciphertexts Ãºnicos....: {eq.unique_ciphertexts}")
    print(f"   ColisÃµes observadas...: {eq.collisions}\n")

    d = diffusion_test(GEN, ENC, seed, trials=args.trials)
    print("3) DifusÃ£o (flip 1 bit em M)")
    print(f"   MÃ©dia/min/mÃ¡x bits em C: {d.mean:.2f}/{d.min_}/{d.max_}  trials={d.trials}\n")

    c = confusion_test(GEN, ENC, seed, trials=args.trials)
    print("4) ConfusÃ£o (flip 1 bit na seed)")
    print(f"   MÃ©dia/min/mÃ¡x bits em C: {c.mean:.2f}/{c.min_}/{c.max_}  trials={c.trials}\n")

    print(f"{t.enc_us+t.dec_us:.3f}\t{eq.collisions}\t{d.mean:.2f}\t{c.mean:.2f}")


if __name__ == "__main__":
    main()
