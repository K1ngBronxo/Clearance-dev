# Not legal advice

Clearance reports what licence texts say and applies stated, published rules to a
declared intent. It is an informational tool. It is not a lawyer, and it does not
give legal advice.

This page is the full statement of what a verdict claims, and why that claim is
defensible.

---

## The disclaimer

> **Not legal advice.**
>
> Clearance reports what licence texts say and applies stated, published rules to
> a declared intent. It is an informational tool. It is not a lawyer, and it does
> not give legal advice.
>
> Every finding quotes the licence clause it relies on and links to the source.
> Where a clause is ambiguous, Clearance says so and shows you the text rather
> than guessing.
>
> Licence interpretation depends on facts Clearance cannot see: your specific use,
> your jurisdiction, your contracts, and how a court would read a clause. For any
> decision with material consequences, consult a qualified professional.
>
> Clearance's corpus is versioned and public. Every correction is published. If you
> believe a verdict is wrong, report it — and it will be investigated, corrected,
> and recorded.

Every human-readable and Markdown verdict ends with the short form of this
statement, and a test asserts the string is present.

---

## What a verdict is a statement about

A verdict is a statement about **a corpus, an intent, and a corpus version** — not
a legal opinion. It says: *given this declared intent, and these published rules
about these licence texts, here is what follows.*

That precision is what makes the tool defensible. Clearance is not asserting what
the law says. It is quoting a licence and applying a rule that a reader can check.

---

## The five structural mitigations

**1. It is not legal advice, and it says so everywhere.** In every verdict, in
this page, in the CLI help footer, and in the MCP tool descriptions.

**2. Every finding cites a primary source.** A finding quotes the clause and links
to the publisher's own document. Clearance applies a stated rule to a quoted text;
it does not pronounce on the law.

**3. Confidence levels make the limits visible.** A `LOW`-confidence finding
cannot block. A `MEDIUM` finding shows "the clause text is ambiguous". The tool
never presents an interpretation as certain when it is not (INV-2). This is the
most important mitigation, because it means the tool does not overclaim: a tool
that says "this is ambiguous, here is the text, you decide" is surfacing a
document, not giving advice.

**4. The corpus is a published, versioned, correctable record.** Every entry has a
citation and a `last_verified` date, and every correction is published. The record
of corrections is the evidence of good faith.

**5. `UNDETERMINED` is never rounded to `SHIP`.** The tool refuses a permissive
answer when it is unsure. This removes the most dangerous failure mode: a
confident green light on an unlicensed weight file.

---

## What the tool does not do

- It does not tell you whether your specific use is lawful. That depends on facts
  it cannot see.
- It does not read your contracts, your jurisdiction's case law, or your
  agreements with your own users.
- It does not replace a lawyer for any decision with material consequences.
- It does not reproduce full licence texts. It quotes excerpts for citation and
  links to the source.

---

## If a verdict is wrong

A wrong or debatable reading of a licence is an **accuracy** issue, not a security
issue, and it has its own process: re-read the clause, add a fixture that
reproduces the exact case, correct the corpus with a correction record, and
publish the change. The fixture is permanent, so the same mistake cannot recur
silently.

See `PLAN/07-OPERATIONS/02-wrong-verdict-process.md`.

---

## What needs a professional before launch

Clearance's own legal posture identifies five items that genuinely need a lawyer's
read, not an engineering fix:

1. whether the disclaimer is sufficient to limit liability for a wrong verdict;
2. the terms of service for the hosted tier;
3. the corpus's publishing posture (excerpt reproduction and interpretation);
4. whether errors-and-omissions insurance is warranted, and at what cost;
5. the EU AI Act overlay, if regulatory obligations are ever mapped to
   dependencies as advice.

The full analysis is in `PLAN/08-BUSINESS/03-legal-posture.md`. It is worth
reading in full before relying on any verdict for a consequential decision.
