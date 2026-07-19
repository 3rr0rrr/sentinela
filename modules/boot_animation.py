#!/usr/bin/env python3
"""Animação de abertura: caveira com falha de sinal intermitente antes do banner estático."""

import sys
import time
import random

from modules.utils import Colors

HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"
CLEAR       = "\033[2J\033[H"

SKULL = r"""
                  uuuuuuu
              uu$$$$$$$$$$$uu
           uu$$$$$$$$$$$$$$$$$uu
          u$$$$$$$$$$$$$$$$$$$$$u
          u$$$$$$$$$$$$$$$$$$$$$u
          u$$$$$$"   "$$$"   "$$$$$$u
          "$$$$"      u$u       $$$$"
           $$$u       u$u       u$$$
           $$$u      u$$$u      u$$$
            "$$$$uu$$$   $$$uu$$$$"
             "$$$$$$$"   "$$$$$$$"
               u$$$$$$$u$$$$$$$u
                 u$$$$$$$$$u
                   "$$$$$"
"""

CLEAN_LINES  = SKULL.strip("\n").split("\n")
GLITCH_CHARS = "#%@&$?!*"


def _render(lines, color):
    sys.stdout.write(CLEAR + color + "\n".join(lines) + Colors.RESET + "\n")
    sys.stdout.flush()


def _glitched(intensity):
    out = []
    for line in CLEAN_LINES:
        new_line = list(line)
        for i, ch in enumerate(new_line):
            if ch != " " and random.random() < intensity:
                new_line[i] = random.choice(GLITCH_CHARS)
        out.append("".join(new_line))
    return out


def _flicker():
    for _ in range(random.randint(2, 4)):
        color = Colors.BOLD_RED if random.random() < 0.7 else Colors.BOLD_GREEN
        _render(_glitched(random.uniform(0.15, 0.4)), color)
        time.sleep(random.uniform(0.03, 0.08))
    _render(CLEAN_LINES, Colors.BOLD_RED)


def play_intro(duration=4.0):
    """Mostra a caveira parada com falhas de sinal aleatórias por `duration` segundos."""
    if not sys.stdout.isatty():
        return

    sys.stdout.write(HIDE_CURSOR)
    try:
        _render(CLEAN_LINES, Colors.BOLD_RED)
        end = time.time() + duration
        while time.time() < end:
            wait = min(random.uniform(1.5, 4.0), max(0.0, end - time.time()))
            time.sleep(wait)
            if time.time() < end:
                _flicker()
    finally:
        sys.stdout.write(SHOW_CURSOR)
        sys.stdout.write(CLEAR)
        sys.stdout.flush()
