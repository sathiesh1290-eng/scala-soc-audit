"""SCALA constraint knowledge base (the retrieval half of the pipeline).

What this module does, in plain terms:

  1. Reads the twelve constraints from standards/constraints.json and checks
     each record against the Constraint form defined in models.py.
  2. Turns the text of each constraint into a vector (an "embedding": a list of
     numbers that places similar sentences close together) and stores those
     vectors in a small local vector database (ChromaDB).
  3. When given a playbook's structural summary, embeds that summary the same
     way and returns the constraints whose vectors are closest to it, i.e. the
     rules most likely to be relevant.

With only twelve constraints the retrieval step ranks rather than filters
(the auditor asks for all twelve). It is kept because the same mechanism
scales to a much larger rule base, for example an organisation's own policies.

Fallback: if ChromaDB or the sentence-embedding library is not installed, or
the embedding model cannot be downloaded, the class falls back to a simple
word-overlap ranking so the rest of the pipeline still runs end to end. The
`backend` attribute records which mode is active so every result file can say
how retrieval was done.

The constraints themselves are data written by hand; nothing in this file
creates or edits a rule.
"""
from __future__ import annotations

import json                    # constraints.json is plain JSON; json.loads turns it into Python dicts
import re                      # regular expressions, used by the fallback ranker to split text into words
from pathlib import Path       # Path objects make file handling explicit and cross-platform

from .models import Constraint   # the validated record type for one rule

# Name of the ChromaDB collection (a "table" of vectors). Fixed so a persisted
# database can be re-opened on the next run instead of being rebuilt.
_COLLECTION = "scala_policy_kb"


def load_constraints(path: Path) -> list[Constraint]:
    """Read constraints.json and return one validated Constraint per record.

    The file has the shape {"_note": "...", "constraints": [ {...}, {...} ]}.
    Constructing Constraint(**c) validates every field, so a typo in the file
    (for example a severity of "hgih") stops the program here with a clear
    message rather than reaching the model.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Constraint(**c) for c in data["constraints"]]


class PolicyKB:
    """Holds the constraints and answers "which rules are relevant to this playbook?"."""

    def __init__(self, constraints_path: Path, persist_dir: Path | None = None):
        """Load and validate the constraint records, then build (or reopen) the embedding index."""
        # Load and validate the rules once.
        self.constraints = load_constraints(constraints_path)
        # A dictionary from id to rule, so retrieval results (which come back as
        # ids) can be turned back into full records quickly.
        self.by_id = {c.constraint_id: c for c in self.constraints}
        # Stays None if the vector database cannot be initialised (lexical fallback).
        self._chroma = None
        # Where ChromaDB should store its files between runs (None = in memory only).
        self._persist_dir = persist_dir
        # Assume the fallback until the vector database is confirmed working.
        self.backend = "lexical-fallback"
        self._try_init_chroma()

    # ------------------------------------------------------------ chroma --
    def _try_init_chroma(self) -> None:
        """Set up the vector database if the optional libraries are available.

        Imports are done inside the function on purpose: chromadb and
        sentence-transformers are heavy optional dependencies, and a machine
        without them should still be able to parse playbooks and run the
        pipeline in fallback mode.
        """
        try:
            import chromadb                                   # the local vector database
            from chromadb.utils import embedding_functions    # ready-made adapters for embedding models
        except ImportError:
            return                                            # libraries absent: keep the lexical fallback
        try:
            # all-MiniLM-L6-v2 is a small, widely used sentence-embedding model
            # (about 80 MB, downloaded automatically on first use).
            ef = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2"
            )
            # Persistent client writes to disk (re-usable across runs);
            # plain client keeps everything in memory for this process only.
            client = (
                chromadb.PersistentClient(path=str(self._persist_dir))
                if self._persist_dir
                else chromadb.Client()
            )
            col = client.get_or_create_collection(_COLLECTION, embedding_function=ef)
            # Only add rules that are not already stored, so re-opening a
            # persisted database does not duplicate entries.
            existing = set(col.get()["ids"]) if col.count() else set()
            new = [c for c in self.constraints if c.constraint_id not in existing]
            if new:
                col.add(
                    ids=[c.constraint_id for c in new],
                    # The text that gets embedded: rule plus audit question,
                    # because together they describe what the rule is about.
                    documents=[f"{c.constraint_text} {c.audit_question}" for c in new],
                    metadatas=[{"source": c.source, "control_ref": c.control_ref} for c in new],
                )
            self._chroma = col
            self.backend = "chromadb+all-MiniLM-L6-v2"
        except Exception as exc:  # e.g. first run without network access for the model download
            print(f"[kb] ChromaDB unavailable ({exc}); using lexical fallback.")

    # ----------------------------------------------------------- retrieve --
    def retrieve(self, query_text: str, k: int = 8) -> list[Constraint]:
        """Return the k constraints most relevant to query_text (a playbook summary)."""
        k = min(k, len(self.constraints))             # cannot return more rules than exist
        if self._chroma is not None:
            # Vector search: the database embeds the query with the same model
            # and returns the ids of the nearest stored vectors, best first.
            res = self._chroma.query(query_texts=[query_text], n_results=k)
            ids = res["ids"][0]
            return [self.by_id[i] for i in ids if i in self.by_id]
        return self._lexical_retrieve(query_text, k)

    def _lexical_retrieve(self, query_text: str, k: int) -> list[Constraint]:
        """Fallback ranking by shared words.

        Splits the query and each rule into lower-case words of three or more
        letters, counts how many words they have in common, and returns the
        rules with the largest overlap. Crude, but it needs no external library.
        """
        qtokens = set(re.findall(r"[a-z]{3,}", query_text.lower()))
        scored = []
        for c in self.constraints:
            ctokens = set(re.findall(r"[a-z]{3,}", (c.constraint_text + " " + c.audit_question).lower()))
            scored.append((len(qtokens & ctokens), c))     # (overlap count, rule)
        scored.sort(key=lambda x: -x[0])                   # highest overlap first
        return [c for _, c in scored[:k]]
