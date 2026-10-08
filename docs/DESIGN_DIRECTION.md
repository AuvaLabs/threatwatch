# ThreatWatch design direction

## Intent

ThreatWatch should feel like a working intelligence desk, not a generic software dashboard. The interface is designed around reading, evidence review, and decisions. Decoration is secondary.

## Reference study

[Rösti](https://rosti.dev/) demonstrates useful restraint: a clear typographic hierarchy, broad calm fields, direct product language, sparse borders, and structured threat data shown without excessive containers.

The [Nielsen Norman Group visual design principles](https://media.nngroup.com/media/articles/attachments/Principles_Visual_Design-Letter.pdf) emphasize hierarchy, contrast, scale, and grouping as the means for guiding attention. The redesign uses those fundamentals instead of shadows and decorative components.

Common generated-interface patterns include uniform rounded cards, repeated pills, soft shadows, equal feature grids, centered hero layouts, and default serif or geometric type pairings. These patterns were removed from the core workspace.

## Visual language

- Warm paper canvas and near-black ink establish a desk and report character.
- Hazard yellow is reserved for selection and attention, not general decoration.
- Blue is reserved for navigation and links.
- Helvetica-style sans serif carries both headings and body copy. Monospace is limited to scores, dates, methods, and operational labels.
- Geometry is square. Rules and alignment create grouping.
- Lists and registers replace repeated card stacks.
- Status colors retain their semantic meaning and are never the sole carrier of state.
- Large headings appear once per workspace. Supporting copy stays narrow and direct.

## Interaction model

- The masthead establishes identity, search, health, theme, and the numbered desk index.
- Mobile uses a deliberate index drawer instead of persistent bottom tabs.
- Decision priorities read as a ruled register with score, evidence, action, and controls on one line.
- Articles remain source evidence and use a dense editorial list.
- Empty, loading, stale, and degraded states remain explicit.

## Release harness

Every design release must pass:

1. TypeScript production build and frontend unit coverage above 80 percent.
2. The complete Python regression suite.
3. Desktop and 390 pixel browser checks for every workspace.
4. No horizontal page overflow.
5. No browser console or page errors.
6. WCAG A and AA automated checks in light and dark modes.
7. Investigation creation and save flow.
8. Container build, API smoke test, and public production verification.
