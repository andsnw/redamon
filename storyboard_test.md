# First prompt for rushes — "How EvoGraph works"

Paste the block below into the agent. It is written the way a person would
describe the video out loud, not as configuration. Rushes turns it into a
storyboard, shows you the two diagrams as still pictures before it records
anything, and you correct it in words from there.

---

## What to paste into rushes

> Make me a demo video, about three to four minutes, that explains **EvoGraph** —
> the part of RedAmon that remembers everything the AI agent did while attacking
> a target, and gets smarter every session.
>
> The app is running at `http://localhost:3000`. I'll sign in myself once when
> you ask. Film the project called **XBEN_1** — the graph page is
> `http://localhost:3000/graph?project=18d7dedceea89db27b3b8434c`. It's a
> practice target built to be hacked, so everything on screen, including the flag
> it hides, is safe to show and publish.
>
> The audience is a developer or security engineer trying RedAmon for the first
> time. Keep it calm and explanatory, and say "we", not "I".
>
> Here is the video I want, scene by scene:
>
> **1. Open with a simple diagram of the five things EvoGraph records.**
> Draw it as a short flow. A session starts a *chain*. Each thing the agent
> does is a *step*, one after another. When a step finds something real, a
> *finding* branches off it. When something fails, a *failure* records the
> lesson. When the agent changes plan, a *decision* marks the turn. Use the same
> colours the real graph uses so it feels like the same product. While you draw
> it, explain that a chain is a connected story, not a flat log.
>
> **2. Now open the real graph for XBEN_1** and slowly drag across it, so the
> viewer sees the whole attack chain as one shape. Explain that the bright centre
> node is one session, the faint nodes around it are the steps the agent took,
> and the orange ones are what it found — and that nobody placed any of it by
> hand, the agent wrote it as it worked.
>
> **3. Open the AI Agent panel on the right, and its session history**, and walk
> through what happened in this session. This is the heart of the video, so tell
> it as a story — but for **every step, connect what the agent did to what
> EvoGraph wrote on the graph**. The point is that the panel and the graph are
> the same events seen two ways: the panel is the agent thinking, the graph is
> the memory it leaves behind.
>
> Open on this idea, then walk the steps:
> - *"This panel is the agent thinking out loud. Behind it is the graph. As the
>   agent works, EvoGraph writes that graph in real time — every action you read
>   here becomes a node over there."*
> - It found a leaked test login sitting in the page. → *"That discovery becomes
>   a **finding** node on the graph — the first real thing worth keeping."*
> - The login worked and gave it a way in. → *"Each attempt is a **step**, linked
>   to the one before it, so the whole path is preserved in order."*
> - Poking around turned up a hidden developer console it could run code through.
>   → *"Another finding — and because it points at the target itself, EvoGraph
>   also links it to the host in the recon graph, the bridge we'll see next."*
> - The console was locked, so a normal scanner would stop here. → *"This is the
>   important one. A dead end is not thrown away — EvoGraph writes a **failure**
>   node with the lesson attached, so the *next* session already knows not to
>   waste time here."*
> - Deciding to change tack — from gathering information to actually exploiting —
>   → *"That turn is a **decision** node, marking the moment the strategy
>   changed."*
> - Then the clever trick: it forged its own login cookie to become the admin
>   user, with no password, and the admin page handed over the flag. → *"The win
>   is the highest **finding** of all — and the chain node at the centre updates
>   to say: objective reached, flag captured."*
>
> Land the scene on the connection: *"So this whole session — the leads, the dead
> end, the breakthrough — isn't just a chat log that disappears. It's a permanent
> graph the agent can read back the next time it faces this target."*
>
> **4. Show a second diagram: how EvoGraph connects to the map of the target.**
> Draw the attack-chain nodes on one side and the target's real map on the other
> — the host, a known vulnerability, a web address — joined by dashed lines.
> Explain that the record of what the agent *did* is always linked to what
> actually *exists*, so you can click anything on your target and see every
> attempt that ever touched it.
>
> **5. One more diagram, this time under the hood — for the engineers.** Say
> plainly that we're going one level deeper now, into how EvoGraph actually lives
> inside the agent's machinery. Draw it as a loop with a fork:
> - The agent runs on a **LangGraph state machine**. Its core is a loop:
>   *think → run a tool → analyse the result → think again.* Draw that as a
>   cycle. Each turn of the loop is one **step** in the chain.
> - The key move is what happens on every "analyse": the result is written to
>   **two memories at once** — draw the fork.
>   - one arrow into **working memory** (the agent's live state, in RAM) — fast,
>     this session only, this is what the model re-reads on the very next think;
>   - one arrow into **Neo4j, the permanent EvoGraph** — written in the
>     background so it never slows the agent down, and written safely so a retry
>     can't duplicate it.
> - Then draw the two ways that memory comes *back*:
>   - within the session, working memory is folded into every prompt as a tidy,
>     deduplicated summary of findings, failures and decisions — signal, not a
>     wall of logs;
>   - at the *start of a new session*, the agent reads the permanent graph first
>     and loads what prior sessions learned, before its first thought.
> - The one-line takeaway to land it on: *the same events feed two loops — a fast
>   one that makes this session sharper, and a durable one that makes the next
>   session start ahead.*
> Keep the boxes minimal and the labels short; it's a concept diagram of the flow,
> not a class diagram. If the arrows get tangled because it's a loop with a fork,
> it's fine to hand-draw this one slide rather than force it into a rigid layout.
>
> **6. Back on the live graph, click one of the orange finding nodes** and read
> what it says. Explain that a finding is something the agent judged worth
> keeping — with its evidence and how serious it is — and, crucially, that the
> *next* session against this target starts by loading these findings and past
> lessons, so it never repeats the dead end we just saw.
>
> **7. Finally, open the public documentation page**
> `https://github.com/samugit83/redamon/wiki/EvoGraph-Attack-Chain-Evolution`
> and scroll down it slowly, explaining each part as it comes into view: what
> EvoGraph is, the five node types, how the graphs connect, and the big idea —
> every new session inherits everything the earlier ones learned.
>
> **Close** on the one line that sums it up: every session starts smarter than
> the last.

---

## Notes for me (not part of the prompt)

A few things to check when rushes asks or when the previews come up:

- **Safety (the one hard question).** When it asks "is everything visible safe
  to publish?", the answer is yes — XBEN_1 is a throwaway practice target, so its
  data and the flag are fine to show. Say this clearly; it won't record without
  it.
- **The three diagrams** are the parts most likely to need a tweak. Look at the
  still previews before it films. If a diagram feels crowded or an arrow crosses
  a box, just tell it in words — "split that into two slides" or "shorten the
  labels" — and it will show you a new picture.
- **The under-the-hood loop diagram (scene 5) is the hard one.** It's a cycle
  with a fork and feedback arrows, which the tidy auto-layout can struggle with.
  If the preview looks tangled, tell rushes to hand-draw that single slide
  instead. It's also the one place the video turns technical, so if it feels too
  deep for your audience, cutting scene 5 leaves the rest of the video whole.
- **Clicking a node** on the graph can be fiddly because the nodes drift. If it
  struggles, tell it to click any orange finding node and confirm the details
  panel opened, rather than aiming at a fixed spot.
- **The wiki page** is someone else's site, so let rushes treat that scene as one
  it doesn't fully control; it just needs the page to load.
- **Any number the voice says** ("twenty-three steps", "three findings") should
  come from the live graph, not be made up. If you don't care about exact counts,
  ask it to describe things without numbers — simpler and safer.
