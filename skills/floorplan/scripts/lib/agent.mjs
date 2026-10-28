// Which coding agent is running the skill: Claude Code or Codex. The map records it, so its Ask bar and
// "Fix with …" prompts name the right one, and serve.mjs answers through the same CLI.
// --agent claude|codex (or FLOORPLAN_AGENT) decides; otherwise Codex is recognised by the variables it
// sets for every command it runs, and anything else is taken to be Claude Code.
export const AGENTS = ['claude', 'codex'];

export function detectAgent(args = {}, env = process.env) {
  const v = String(args.agent || env.FLOORPLAN_AGENT || '').toLowerCase();
  if (AGENTS.includes(v)) return v;
  return env.CODEX_THREAD_ID || env.CODEX_SESSION_ID ? 'codex' : 'claude';
}
