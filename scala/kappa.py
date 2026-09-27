"""Cohen's kappa between two labellings of the same reference-set decisions.

Purpose: measure how consistently the same expert labels the same decisions on
two occasions, or how far a second expert agrees with the first. A sample of
decisions is labelled a second time, without sight of the first label, in a
spreadsheet; this script compares the second labels with the first and prints
Cohen's kappa, which corrects raw agreement for the agreement that would happen
by chance. This is the instrument for the expert-rating check described as
future work.

Usage: python kappa.py <workbook.xlsx> <first_labels.json>

Inputs:
  workbook.xlsx      sheet "Second labelling": one decision per row from row 2 to
                     row 25; the decision number is in column A and the fresh
                     verdict ("violated" / "not violated") in column F
  first_labels.json  a list of {"n": <decision number>, "original_status": ...}
                     giving the original label for each decision

Output: N, observed agreement, expected (chance) agreement, kappa, and the list
of decisions where the two labels differ.
"""
import json, sys                  # json reads the key file; sys gives the command-line arguments and exit
import openpyxl                   # reads .xlsx workbooks

# Open the workbook and the sheet that holds the second labelling.
wb = openpyxl.load_workbook(sys.argv[1]); ws = wb["Second labelling"]
# Original labels keyed by decision number.
key = {k["n"]: k["original_status"] for k in json.load(open(sys.argv[2]))}
pairs = []                        # (original label, new label, decision number)
for row in ws.iter_rows(min_row=2, max_row=25, values_only=True):
    # Column A = decision number; column F = the fresh verdict, normalised to "violated" / "not_violated".
    n, verdict = row[0], (row[5] or "").strip().lower().replace(" ", "_")
    if n in key and verdict in ("violated", "not_violated"):
        pairs.append((key[n], verdict, n))
if not pairs:
    sys.exit("no verdicts found in column F")
a = [p[0] for p in pairs]; b = [p[1] for p in pairs]; N = len(pairs)
# Observed agreement: share of decisions where the two labels match.
po = sum(1 for x, y in zip(a, b) if x == y) / N
cats = ("violated", "not_violated")
# Expected agreement by chance: for each category, the product of how often each
# labelling used it, summed over categories.
pe = sum((a.count(c) / N) * (b.count(c) / N) for c in cats)
# Kappa = (observed - expected) / (1 - expected); 1.0 is perfect, 0 is chance level.
if pe >= 1:
    sys.exit(f"N={N}: both labellings use a single category, so kappa is undefined (observed agreement={po:.3f})")
kappa = (po - pe) / (1 - pe)
print(f"N={N}  observed agreement={po:.3f}  expected={pe:.3f}  Cohen's kappa={kappa:.3f}")
for orig, new, n in pairs:
    if orig != new:
        print(f"  disagreement #{n}: first={orig} second={new}")
