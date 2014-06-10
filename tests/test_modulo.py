#!/usr/bin/env python3

import unittest

import sys
import os

sys.path.append (os.path.join (os.path.dirname (__file__), ".."))

from decnet import modulo

class mod15 (modulo.Mod, mod = 15): pass
class mod16 (modulo.Mod, mod = 16): pass

class TestModulo (unittest.TestCase):
    def test_abc (self):
        with self.assertRaises (TypeError):
            b = modulo.Mod (1)

    def test_init (self):
        # Test various init cases
        a = mod16 (1)
        b = mod16 (15)
        with self.assertRaises (OverflowError):
            b = mod16 (-1)
        with self.assertRaises (OverflowError):
            b = mod16 (16)

    def test_eq (self):
        a = mod16 (1)
        self.assertTrue (a == a)
        self.assertTrue (a <= a)
        self.assertTrue (a >= a)
        self.assertFalse (a != a)
        self.assertFalse (a < a)
        self.assertFalse (a > a)

    def test_ne (self):
        a = mod16 (1)
        b = mod16 (8)
        self.assertTrue (a < b)
        self.assertTrue (a <= b)
        self.assertTrue (a != b)
        self.assertFalse (a > b)
        self.assertFalse (a >= b)
        self.assertFalse (a == b)
        c = mod16 (10)
        self.assertFalse (a < c)
        self.assertFalse (a <= c)
        self.assertTrue (a != c)
        self.assertTrue (a > c)
        self.assertTrue (a >= c)
        self.assertFalse (a == c)

    def test_undef (self):
        a = mod16 (1)
        b = mod16 (9)
        with self.assertRaises (TypeError):
            a < b
        with self.assertRaises (TypeError):
            a <= b
        with self.assertRaises (TypeError):
            a > b
        with self.assertRaises (TypeError):
            a >= b
        self.assertTrue (a != b)
        self.assertFalse (a == b)

    def test_unordered (self):
        a = mod16 (1)
        c = mod15 (2)
        with self.assertRaises (TypeError):
            a < c
        with self.assertRaises (TypeError):
            a <= c
        with self.assertRaises (TypeError):
            a > c
        with self.assertRaises (TypeError):
            a >= c
        self.assertTrue (a != c)
        self.assertFalse (a == c)

    def test_largeint (self):
        a = mod16 (1)
        d = 50000
        self.assertTrue (a < d)
        self.assertTrue (a <= d)
        self.assertTrue (a != d)
        self.assertFalse (a > d)
        self.assertFalse (a >= d)
        self.assertFalse (a == d)

    def test_negint (self):
        a = mod16 (1)
        d = -5
        self.assertFalse (a < d)
        self.assertFalse (a <= d)
        self.assertTrue (a != d)
        self.assertTrue (a > d)
        self.assertTrue (a >= d)
        self.assertFalse (a == d)

if __name__ == "__main__":
    unittest.main ()
    
