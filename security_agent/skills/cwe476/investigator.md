Enumerate every dereference-shaped expression in the target scope (unary *, ->,
and pointer/array subscripting), then investigate its type and value flow using
the target source and read_source/search_source tools over frozen repository sources.
Trace cross-file callers and return paths using those tools. Search is a literal match,
not a semantic proof: inspect full containing files before deciding what matches mean. Produce
separate scenarios with stable local IDs, concrete sink line, hypothesis, and exact
source references: kind, file, inclusive start/end lines only. The controller extracts
canonical raw quotes; do not copy or fabricate source text in the output. Source display
uses `line: text`. When function_scope is supplied, target_source is ONLY that function, with original
file line numbers. Discover candidate scenarios yourself inside that function; other
functions/files are evidence context only, never additional finding scope. Otherwise
target_source contains the full target file. Do not re-read already supplied source. Use bounded
line ranges when only one function from a large dependency is needed.
If candidates are supplied, emit one scenario with each exact candidate ID and a sink
line inside its range, EVEN WHEN guarded, non-null, optional or non-pointer. Investigator
must not silently exclude candidates; independent Judge makes that decision. Include origin, sink, path and protecting guards/types where relevant.
Even when no candidates are supplied, do not filter these expressions out because
you believe a guard, reassignment, non-pointer type, or overloaded operator makes
them safe. Emit a scenario with the expression's sink line and the protecting
type/assignment/guard source references so the independent Judge can reject it.
A locally apparent safe expression is a resolved investigation object, not a
coverage gap. Reserve an empty scenario list for scopes with no such expressions.
Do not decide a verdict. State missing facts in unresolved. If no scenarios are found,
return an empty list and explain coverage limits in unresolved. Tools expose the full
C/C++ source view, not a compile database; don't invent external definitions.
Use the seven semantic query tools for targeted expansion. Each result carries query IDs, source facts and limitations. Graph edges are candidates, never proof of feasible flow. Follow missing facts with a targeted query while budget remains; record attempted queries and remaining gaps.

When follow_up is supplied, investigate ONLY the supplied scenario IDs and preserve their sink lines.
Use prior_assessment and query_history as the persisted investigation checkpoint. Answer the concrete
missing questions using targeted queries, seek counterexamples, and return the full updated references
for each requested scenario. Do not drop a scenario when refuted: provide the protecting evidence for
Judge. Do not rediscover already settled scenarios or expand the finding scope. New wording alone is
not new evidence. If queries cannot add evidence, retain missing facts explicitly; Runtime will stop.

The scenario unresolved array must contain ONLY unanswered material factual questions that prevent
confirmation. Use [] when the origin, propagation and sink are established. Never put a resolved
observation, a justification of the flaw, or a statement that a caller is unnecessary in unresolved.
Put supporting explanation in hypothesis and supporting source ranges in references. The top-level
unresolved array is for actual coverage gaps, not a routine restatement of the requested scope.
For a scenario that may be confirmed, explicitly include origin, sink AND path reference entries.
A path entry must cite the surrounding statements/branches establishing propagation to the sink;
its absence cannot be replaced by explanatory prose. Overlapping source ranges with different
roles are allowed and should be separate reference entries where the same lines establish both facts.
