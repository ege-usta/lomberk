"""Property-based fuzzing of the AST hard gate (sentinel._ast_firewall).

The hand-written catalogue in test_firewall_attacks.py pins specific strings.
This generalises it: thousands of semantics-preserving mutations of each known
attack must STILL be blocked, each known-safe query must STAY allowed, and no
input — however malformed — may crash the gate. Together they hunt the class of
bug the catalogue can't: a normalisation gap (case, whitespace, comments) or a
parser crash that lets a dangerous statement through.
"""
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from test_firewall_attacks import MUST_ALLOW, MUST_BLOCK

from lomberk.sentinel import AISentinel

fw = AISentinel()._ast_firewall

# Whitespace fillers that cannot hide a token: real spacing variants plus an
# EMPTY block comment (/**/ can't comment anything out) and a trailing newline.
WS = st.sampled_from([" ", "  ", "\t", "\n", "\r\n", " /**/ ", "\t/**/\t", "\n  "])


def _fold_case(s: str, upper: bool) -> str:
    """Change case OUTSIDE single-quoted literals only. SQL keywords and unquoted
    identifiers are case-insensitive, so this preserves meaning and danger; string
    literal contents are data and are left byte-for-byte intact."""
    out, in_str = [], False
    for ch in s:
        if ch == "'":
            in_str = not in_str
            out.append(ch)
        else:
            out.append(ch if in_str else (ch.upper() if upper else ch.lower()))
    return "".join(out)


@st.composite
def mutated(draw, pool, allow_stacking):
    sql = draw(st.sampled_from(pool))
    # Expand every existing run of whitespace into a (possibly fatter) filler.
    buf, out = "", []
    for ch in sql:
        if ch.isspace():
            buf += ch
        else:
            if buf:
                out.append(draw(WS))
                buf = ""
            out.append(ch)
    if buf:
        out.append(draw(WS))
    s = "".join(out)
    mode = draw(st.sampled_from(["asis", "upper", "lower"]))
    if mode != "asis":
        s = _fold_case(s, mode == "upper")
    # Stacking a second banned statement must never relax the verdict.
    if allow_stacking and draw(st.booleans()):
        s = s + draw(st.sampled_from(["; ", ";", ";\n", " ;\t"])) + draw(st.sampled_from(MUST_BLOCK))
    return s


@settings(max_examples=1500, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(mutated(MUST_BLOCK, allow_stacking=True))
def test_mutated_attacks_stay_blocked(sql):
    safe, _ = fw(sql)
    assert not safe, f"BYPASS via mutation: {sql!r}"


@settings(max_examples=800, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(mutated(MUST_ALLOW, allow_stacking=False))
def test_mutated_safe_sql_stays_allowed(sql):
    # Normalisation must not make a legitimate query un-runnable for the agent.
    safe, reason = fw(sql)
    assert safe, f"false block of safe SQL: {sql!r} ({reason})"


@settings(max_examples=2000, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(st.text())
def test_firewall_never_crashes_and_fails_closed(sql):
    # Arbitrary text — including control chars and garbage — returns a verdict,
    # never raises, and anything it rejects carries a reason.
    safe, reason = fw(sql)
    assert isinstance(safe, bool)
    if not safe:
        assert reason
