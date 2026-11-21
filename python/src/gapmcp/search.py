"""Natural-language action search for progressive disclosure."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from .action import Action
from .registry import ActionRegistry

__all__ = ["SearchResult", "search_actions"]

_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _tokenize(value: str) -> list[str]:
    return [token for token in _TOKEN_SPLIT.split(value.lower()) if len(token) > 1]


@dataclass(kw_only=True, slots=True)
class SearchResult:
    """One ranked action search hit."""

    action: Action
    score: int
    matched: list[str]

    def to_dict(self) -> dict[str, object]:
        """Compact result shape suitable for a tool response."""
        return {
            "name": self.action.name,
            "description": self.action.description,
            "risk": self.action.risk,
            "scopes": list(self.action.scopes),
            "tags": list(self.action.tags),
            "score": self.score,
            "matched": list(self.matched),
        }


def search_actions(
    registry: ActionRegistry,
    query: str,
    *,
    limit: int = 10,
    scopes: Sequence[str] | None = None,
) -> list[SearchResult]:
    """Rank actions for a natural-language query.

    Name matches score 6, tags 4, descriptions 2, and prefix matches add 1.
    Results are sorted by score then name and truncated to ``limit``. When
    ``scopes`` is supplied, only actions visible to that principal are
    searched.
    """
    terms = _tokenize(query)
    if not terms:
        return []
    actions = registry.visible_to(scopes) if scopes is not None else registry.list()

    results: list[SearchResult] = []
    for action in actions:
        name_tokens = set(_tokenize(action.name))
        description_tokens = set(_tokenize(action.description))
        tag_tokens = {token for tag in action.tags for token in _tokenize(tag)}
        score = 0
        matched: list[str] = []
        matched_set: set[str] = set()

        for term in terms:
            if term in name_tokens:
                score += 6
                matched_set.add(term)
            if term in tag_tokens:
                score += 4
                matched_set.add(term)
            if term in description_tokens:
                score += 2
                matched_set.add(term)
            for token in [*name_tokens, *description_tokens]:
                if token != term and (token.startswith(term) or term.startswith(token)):
                    score += 1
                    matched_set.add(term)

        if score > 0:
            matched = [term for term in terms if term in matched_set]
            results.append(SearchResult(action=action, score=score, matched=matched))

    results.sort(key=lambda result: (-result.score, result.action.name))
    return results[: max(0, limit)]
