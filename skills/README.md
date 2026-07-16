# depsound skills

Self-contained skills that teach an agent to use `depsound` for a task. Each is a single Markdown file with YAML frontmatter (`name`, `description`): load it into a skill-aware agent, or just curl and read it.

```
curl -s https://raw.githubusercontent.com/rvagg/depsound/master/skills/review-dependency-change/SKILL.md
```

## Available

- **[review-dependency-change](review-dependency-change/SKILL.md)**: review a proposed dependency change (a name + versions, a changed manifest/lockfile, or a GitHub PR; one or many) and report a proceed/hold recommendation with specific reasons. Review only, not merging.
- **[adopt-a-new-dependency](adopt-a-new-dependency/SKILL.md)**: decide whether to add a new dependency, or which of several candidates, using census mode; weigh footprint, need, compatibility, and supply-chain risk. Not an installer.
