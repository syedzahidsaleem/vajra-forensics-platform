# Vajra — Team Repository Setup Guide

## Decision: every branch gets the full code, not just the two MD files

Everyone needs the actual working codebase to build on top of — Nitya can't build the UI without the real crates to bind against, Akanksha can't benchmark without the real binaries and test scripts, Vaibhavi can't add a carving validator without the real `vajra-carve` source. Branching from `main` gives everyone the full code and full history automatically, at zero extra cost — there's no advantage to a code-less branch here.

All five role documents are added to `main` itself (not selectively per-branch), so everyone can see the whole team's plan for coordination — this matters more for a 5-person hackathon team than keeping branches minimal.

## Step-by-step process

### 1. Place the six new documents into your local Vajra folder

Put all six files (the five `ROLE_*.md` files plus this guide) into a new folder:
```
Vajra/
└── docs/
    └── team-roles/
        ├── ROLE_Syed_Zahid.md
        ├── ROLE_Nitya.md
        ├── ROLE_Hari_Priya.md
        ├── ROLE_Akanksha.md
        ├── ROLE_Vaibhavi.md
        └── TEAM_SETUP_GUIDE.md
```

### 2. Create the GitHub repository

On github.com, create a new **empty** repository (no README/license/gitignore — you already have a real project) — e.g. `vajra-forensics-platform`. Keep it private if this is meant to stay internal to your team before submission; you can make it public later.

### 3. Push your existing work as `main`

From inside your local `Vajra/` folder:
```bash
git init                     # only if not already a git repo
git add .
git commit -m "Vajra backend: 8-conversation build complete (foundation through reporting/verifier)"
git branch -M main
git remote add origin https://github.com/<your-username>/vajra-forensics-platform.git
git push -u origin main
```

### 4. Create the five branches

```bash
git checkout -b syed-zahid && git push -u origin syed-zahid
git checkout main
git checkout -b nitya && git push -u origin nitya
git checkout main
git checkout -b hari-priya && git push -u origin hari-priya
git checkout main
git checkout -b akanksha && git push -u origin akanksha
git checkout main
git checkout -b vaibhavi && git push -u origin vaibhavi
git checkout main
```

Each branch now has the identical full codebase, full history, the master blueprint, and all five role documents.

### 5. Add each teammate as a collaborator

GitHub repo → Settings → Collaborators → add each person's GitHub username. Ask each person to clone the repo and check out their own branch:
```bash
git clone https://github.com/<your-username>/vajra-forensics-platform.git
cd vajra-forensics-platform
git checkout <their-branch-name>
```

### 6. Working conventions going forward

- Each person works on their own branch, opening Antigravity in that branch's checkout.
- Each person's Antigravity conversations should follow the same discipline the original 8 backend conversations used: read the relevant blueprint sections and agent-logs first, work in defined steps, write a new numbered `docs/agent-log/` entry when done (continue the existing numbering — 09, 10, 11... — don't restart at 01 per person, since the agent-log is a single shared project history, not five separate ones).
- When a person's work is ready to merge: open a Pull Request from their branch into `main`, tag Syed as reviewer (he owns integration per his role doc).
- Periodically (e.g. daily), everyone should `git pull origin main` into their own branch and merge, so branches don't drift too far apart before the final integration.

## A note on scope discipline

Every role document above inherits this project's established pattern: read the exact blueprint section before building, don't guess at existing APIs when you can read the agent-log that documents them exactly, and report real results (real command output, real measured numbers) rather than asserted ones. This discipline is what got the backend through 8 conversations without silent bugs accumulating — worth keeping for the rest of the project too.
